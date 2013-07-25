// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// DNS server implementation.

package dns

import (
	"net"
	"sync"
	"time"
)

type Handler interface {
	ServeDNS(w ResponseWriter, r *Msg)
}

// A ResponseWriter interface is used by an DNS handler to
// construct an DNS response.
type ResponseWriter interface {
	// RemoteAddr returns the net.Addr of the client that sent the current request.
	RemoteAddr() net.Addr
	// WriteMsg writes a reply back to the client.
	WriteMsg(*Msg) error
	// Write writes a raw buffer back to the client.
	Write([]byte) (int, error)
	// Close closes the connection.
	Close() error
	// TsigStatus returns the status of the Tsig.
	TsigStatus() error
	// TsigTimersOnly sets the tsig timers only boolean.
	TsigTimersOnly(bool)
	// Hijack lets the caller take over the connection.
	// After a call to Hijack(), the DNS package will not do anything with the connection
	Hijack()
}

type response struct {
	hijacked       bool // connection has been hijacked by handler
	tsigStatus     error
	tsigTimersOnly bool
	tsigRequestMAC string
	tsigSecret     map[string]string // the tsig secrets
	udp            *net.UDPConn      // i/o connection if UDP was used
	tcp            *net.TCPConn      // i/o connection if TCP was used
	remoteAddr     net.Addr          // address of the client
}

// ServeMux is an DNS request multiplexer. It matches the
// zone name of each incoming request against a list of
// registered patterns add calls the handler for the pattern
// that most closely matches the zone name. ServeMux is DNSSEC aware, meaning
// that queries for the DS record are redirected to the parent zone (if that
// is also registered), otherwise the child gets the query.
// ServeMux is also safe for concurrent access from multiple goroutines.
type ServeMux struct {
	z map[string]Handler
	m *sync.RWMutex
}

// NewServeMux allocates and returns a new ServeMux.
func NewServeMux() *ServeMux { return &ServeMux{z: make(map[string]Handler), m: new(sync.RWMutex)} }

// DefaultServeMux is the default ServeMux used by Serve.
var DefaultServeMux = NewServeMux()

// Authors is a list of authors that helped create or make Go DNS better.
var Authors = []string{"Miek Gieben", "Ask Bjørn Hansen", "Dave Cheney", "Dusty Wilson", "Peter van Dijk"}

// Version holds the current version.
var Version = "v1.2"

// The HandlerFunc type is an adapter to allow the use of
// ordinary functions as DNS handlers.  If f is a function
// with the appropriate signature, HandlerFunc(f) is a
// Handler object that calls f.
type HandlerFunc func(ResponseWriter, *Msg)

// ServerDNS calls f(w, r)
func (f HandlerFunc) ServeDNS(w ResponseWriter, r *Msg) {
	f(w, r)
}

// FailedHandler returns a HandlerFunc
// returns SERVFAIL for every request it gets.
func HandleFailed(w ResponseWriter, r *Msg) {
	m := new(Msg)
	m.SetRcode(r, RcodeServerFailure)
	// does not matter if this write fails
	w.WriteMsg(m)
}

// AuthorHandler returns a HandlerFunc that returns the authors
// of Go DNS for 'authors.bind' or 'authors.server' queries in the
// CHAOS Class. Note with:
//
//	dns.HandleFunc("authors.bind.", dns.HandleAuthors)
//
// the handler is registered for all DNS classes, thereby potentially
// hijacking the authors.bind. zone in the IN class. If you need the
// authors.bind zone to exist in the IN class, you need to register
// some other handler, check the class in there and then call HandleAuthors.
func HandleAuthors(w ResponseWriter, r *Msg) {
	if len(r.Question) != 1 {
		HandleFailed(w, r)
		return
	}
	if r.Question[0].Qtype != ClassCHAOS && r.Question[0].Qtype != TypeTXT {
		HandleFailed(w, r)
		return
	}
	if r.Question[0].Name != "authors.server." && r.Question[0].Name != "authors.bind." {
		HandleFailed(w, r)
		return
	}
	m := new(Msg)
	m.SetReply(r)
	for _, author := range Authors {
		h := RR_Header{r.Question[0].Name, TypeTXT, ClassCHAOS, 0, 0}
		m.Answer = append(m.Answer, &TXT{h, []string{author}})
	}
	w.WriteMsg(m)
}

// VersionHandler returns a HandlerFunc that returns the version
// of Go DNS for 'version.bind' or 'version.server' queries in the
// CHAOS Class. Note with:
//
//	dns.HandleFunc("version.bind.", dns.HandleVersion)
//
// the handler is registered for all DNS classes, thereby potentially
// hijacking the version.bind. zone in the IN class. If you need the
// version.bind zone to exist in the IN class, you need to register
// some other handler, check the class in there and then call HandleVersion.
func HandleVersion(w ResponseWriter, r *Msg) {
	if len(r.Question) != 1 {
		HandleFailed(w, r)
		return
	}
	if r.Question[0].Qtype != ClassCHAOS && r.Question[0].Qtype != TypeTXT {
		HandleFailed(w, r)
		return
	}
	if r.Question[0].Name != "version.server." && r.Question[0].Name != "version.bind." {
		HandleFailed(w, r)
		return
	}
	m := new(Msg)
	m.SetReply(r)
	h := RR_Header{r.Question[0].Name, TypeTXT, ClassCHAOS, 0, 0}
	m.Answer = append(m.Answer, &TXT{h, []string{Version}})
	w.WriteMsg(m)
}

func authorHandler() Handler  { return HandlerFunc(HandleAuthors) }
func failedHandler() Handler  { return HandlerFunc(HandleFailed) }
func versionHandler() Handler { return HandlerFunc(HandleVersion) }

// Start a server on addresss and network speficied. Invoke handler
// for incoming queries.
func ListenAndServe(addr string, network string, handler Handler) error {
	server := &Server{Addr: addr, Net: network, Handler: handler}
	return server.ListenAndServe()
}

func (mux *ServeMux) match(q string, t uint16) Handler {
	mux.m.RLock()
	defer mux.m.RUnlock()
	var handler Handler
	b := make([]byte, len(q)) // worst case, one label of length q
	off := 0
	end := false
	for {
		l := len(q[off:])
		for i := 0; i < l; i++ {
			b[i] = q[off+i] | ( 'a' - 'A')
		}
		if h, ok := mux.z[string(b[:l])]; ok { // 'causes garbage, might want to change the map key
			if t != TypeDS {
				return h
			} else {
				// Continue for DS to see if we have a parent too, if so delegeate to the parent
				handler = h
			}
		}
		off, end = NextLabel(q, off)
		if end {
			break
		}
	}
	// Wildcard match, if we have found nothing try the root zone as a last resort.
	if h, ok := mux.z["."]; ok {
		return h
	}
	return handler
}

// Handle adds a handler to the ServeMux for pattern.
func (mux *ServeMux) Handle(pattern string, handler Handler) {
	if pattern == "" {
		panic("dns: invalid pattern " + pattern)
	}
	mux.m.Lock()
	mux.z[Fqdn(pattern)] = handler
	mux.m.Unlock()
}

// Handle adds a handler to the ServeMux for pattern.
func (mux *ServeMux) HandleFunc(pattern string, handler func(ResponseWriter, *Msg)) {
	mux.Handle(pattern, HandlerFunc(handler))
}

// HandleRemove deregistrars the handler specific for pattern from the ServeMux.
func (mux *ServeMux) HandleRemove(pattern string) {
	if pattern == "" {
		panic("dns: invalid pattern " + pattern)
	}
	mux.m.Lock()
	delete(mux.z, Fqdn(pattern))
	mux.m.Unlock()
}

// ServeDNS dispatches the request to the handler whose
// pattern most closely matches the request message. If DefaultServeMux
// is used the correct thing for DS queries is done: a possible parent
// is sought.
// If no handler is found a standard SERVFAIL message is returned
// If the request message does not have a single question in the
// question section a SERVFAIL is returned.
func (mux *ServeMux) ServeDNS(w ResponseWriter, request *Msg) {
	var h Handler
	if len(request.Question) != 1 {
		h = failedHandler()
	} else {
		if h = mux.match(request.Question[0].Name, request.Question[0].Qtype); h == nil {
			h = failedHandler()
		}
	}
	h.ServeDNS(w, request)
}

// Handle registers the handler with the given pattern
// in the DefaultServeMux. The documentation for
// ServeMux explains how patterns are matched.
func Handle(pattern string, handler Handler) { DefaultServeMux.Handle(pattern, handler) }

// HandleRemove deregisters the handle with the given pattern
// in the DefaultServeMux.
func HandleRemove(pattern string) { DefaultServeMux.HandleRemove(pattern) }

// HandleFunc registers the handler function with the given pattern
// in the DefaultServeMux.
func HandleFunc(pattern string, handler func(ResponseWriter, *Msg)) {
	DefaultServeMux.HandleFunc(pattern, handler)
}

// A Server defines parameters for running an DNS server.
type Server struct {
	Addr         string            // address to listen on, ":dns" if empty
	Net          string            // if "tcp" it will invoke a TCP listener, otherwise an UDP one
	Handler      Handler           // handler to invoke, dns.DefaultServeMux if nil
	UDPSize      int               // default buffer size to use to read incoming UDP messages
	ReadTimeout  time.Duration     // the net.Conn.SetReadTimeout value for new connections
	WriteTimeout time.Duration     // the net.Conn.SetWriteTimeout value for new connections
	TsigSecret   map[string]string // secret(s) for Tsig map[<zonename>]<base64 secret>
}

// ListenAndServe starts a nameserver on the configured address in *Server.
func (srv *Server) ListenAndServe() error {
	addr := srv.Addr
	if addr == "" {
		addr = ":domain"
	}
	switch srv.Net {
	case "tcp", "tcp4", "tcp6":
		a, e := net.ResolveTCPAddr(srv.Net, addr)
		if e != nil {
			return e
		}
		l, e := net.ListenTCP(srv.Net, a)
		if e != nil {
			return e
		}
		return srv.serveTCP(l)
	case "udp", "udp4", "udp6":
		a, e := net.ResolveUDPAddr(srv.Net, addr)
		if e != nil {
			return e
		}
		l, e := net.ListenUDP(srv.Net, a)
		if e != nil {
			return e
		}
		return srv.serveUDP(l)
	}
	return &Error{err: "bad network"}
}

// serveTCP starts a TCP listener for the server.
// Each request is handled in a seperate goroutine.
func (srv *Server) serveTCP(l *net.TCPListener) error {
	defer l.Close()
	handler := srv.Handler
	if handler == nil {
		handler = DefaultServeMux
	}
forever:
	for {
		rw, e := l.AcceptTCP()
		if e != nil {
			// don't bail out, but wait for a new request
			continue
		}
		if srv.ReadTimeout != 0 {
			rw.SetReadDeadline(time.Now().Add(srv.ReadTimeout))
		}
		if srv.WriteTimeout != 0 {
			rw.SetWriteDeadline(time.Now().Add(srv.WriteTimeout))
		}
		l := make([]byte, 2)
		n, err := rw.Read(l)
		if err != nil || n != 2 {
			continue
		}
		length, _ := unpackUint16(l, 0)
		if length == 0 {
			continue
		}
		m := make([]byte, int(length))
		n, err = rw.Read(m[:int(length)])
		if err != nil || n == 0 {
			continue
		}
		i := n
		for i < int(length) {
			j, err := rw.Read(m[i:int(length)])
			if err != nil {
				continue forever
			}
			i += j
		}
		n = i
		go serve(rw.RemoteAddr(), handler, m, nil, rw, srv.TsigSecret)
	}
	panic("dns: not reached")
}

// serveUDP starts a UDP listener for the server.
// Each request is handled in a seperate goroutine.
func (srv *Server) serveUDP(l *net.UDPConn) error {
	defer l.Close()
	handler := srv.Handler
	if handler == nil {
		handler = DefaultServeMux
	}
	if srv.UDPSize == 0 {
		srv.UDPSize = udpMsgSize
	}
	for {
		if srv.ReadTimeout != 0 {
			l.SetReadDeadline(time.Now().Add(srv.ReadTimeout))
		}
		if srv.WriteTimeout != 0 {
			l.SetWriteDeadline(time.Now().Add(srv.WriteTimeout))
		}
		m := make([]byte, srv.UDPSize)
		n, a, e := l.ReadFromUDP(m)
		if e != nil || n == 0 {
			// don't bail out, but wait for a new request
			continue
		}
		m = m[:n]
		go serve(a, handler, m, l, nil, srv.TsigSecret)
	}
	panic("dns: not reached")
}

// Serve a new connection.
func serve(a net.Addr, h Handler, m []byte, u *net.UDPConn, t *net.TCPConn, tsigSecret map[string]string) {
	// for block to make it easy to break out to close the tcp connection
	for {
		// Request has been read in serveUDP or serveTCP
		w := new(response)
		w.tsigSecret = tsigSecret
		w.udp = u
		w.tcp = t
		w.remoteAddr = a
		req := new(Msg)
		if req.Unpack(m) != nil {
			// Send a format error back
			x := new(Msg)
			x.SetRcodeFormatError(req)
			w.WriteMsg(x)
			break
		}

		w.tsigStatus = nil
		if w.tsigSecret != nil {
			if t := req.IsTsig(); t != nil {
				secret := t.Hdr.Name
				if _, ok := tsigSecret[secret]; !ok {
					w.tsigStatus = ErrKeyAlg
				}
				w.tsigStatus = TsigVerify(m, tsigSecret[secret], "", false)
				w.tsigTimersOnly = false
				w.tsigRequestMAC = req.Extra[len(req.Extra)-1].(*TSIG).MAC
			}
		}
		h.ServeDNS(w, req) // this does the writing back to the client
		if w.hijacked {
			// client takes care of the connection, i.e. calls Close()
			break
		}
		if t != nil {
			w.Close()
		}
		break
	}
	return
}

// WriteMsg implements the ResponseWriter.WriteMsg method.
func (w *response) WriteMsg(m *Msg) (err error) {
	var data []byte
	if w.tsigSecret != nil { // if no secrets, dont check for the tsig (which is a longer check)
		if t := m.IsTsig(); t != nil {
			data, w.tsigRequestMAC, err = TsigGenerate(m, w.tsigSecret[t.Hdr.Name], w.tsigRequestMAC, w.tsigTimersOnly)
			if err != nil {
				return err
			}
			_, err = w.Write(data)
			return err
		}
	}
	data, err = m.Pack()
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// Write implements the ResponseWriter.Write method.
func (w *response) Write(m []byte) (int, error) {
	switch {
	case w.udp != nil:
		n, err := w.udp.WriteTo(m, w.remoteAddr)
		return n, err
	case w.tcp != nil:
		lm := len(m)
		if len(m) > MaxMsgSize {
			return 0, &Error{err: "message too large"}
		}
		l := make([]byte, 2)
		l[0], l[1] = packUint16(uint16(lm))
		m = append(l, m...)
		n, err := w.tcp.Write(m)
		if err != nil {
			return n, err
		}
		i := n
		if i < lm {
			j, err := w.tcp.Write(m[i:lm])
			if err != nil {
				return i, err
			}
			i += j
		}
		n = i
		return i, nil
	}
	panic("not reached")
}

// RemoteAddr implements the ResponseWriter.RemoteAddr method.
func (w *response) RemoteAddr() net.Addr { return w.remoteAddr }

// TsigStatus implements the ResponseWriter.TsigStatus method.
func (w *response) TsigStatus() error { return w.tsigStatus }

// TsigTimersOnly implements the ResponseWriter.TsigTimersOnly method.
func (w *response) TsigTimersOnly(b bool) { w.tsigTimersOnly = b }

// Hijack implements the ResponseWriter.Hijack method.
func (w *response) Hijack() { w.hijacked = true }

// Close implements the ResponseWriter.Close method
func (w *response) Close() error {
	if w.udp != nil {
		e := w.udp.Close()
		w.udp = nil
		return e
	}
	if w.tcp != nil {
		e := w.tcp.Close()
		w.tcp = nil
		return e
	}
	// no-op
	return nil
}
