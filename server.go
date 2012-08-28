// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// DNS server implementation.

package dns

import (
	"github.com/miekg/radix"
	"io"
	"net"
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
	// Write writes a reply back to the client.
	Write(*Msg) error
	// WriteBuf writes a raw buffer back to the client.
	WriteBuf([]byte) error
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

type conn struct {
	remoteAddr net.Addr          // address of the client
	handler    Handler           // request handler
	request    []byte            // bytes read
	_UDP       *net.UDPConn      // i/o connection if UDP was used
	_TCP       *net.TCPConn      // i/o connection if TCP was used
	hijacked   bool              // connection has been hijacked by hander TODO(mg)
	tsigSecret map[string]string // the tsig secrets
}

type response struct {
	conn           *conn
	req            *Msg
	tsigStatus     error
	tsigTimersOnly bool
	tsigRequestMAC string
}

// ServeMux is an DNS request multiplexer. It matches the
// zone name of each incoming request against a list of 
// registered patterns add calls the handler for the pattern
// that most closely matches the zone name. ServeMux is DNSSEC aware, meaning
// that queries for the DS record are redirected to the parent zone (if that
// is also registered), otherwise the child gets the query.
type ServeMux struct {
	m *radix.Radix
}

// NewServeMux allocates and returns a new ServeMux.
func NewServeMux() *ServeMux { return &ServeMux{m: radix.New()} }

// DefaultServeMux is the default ServeMux used by Serve.
var DefaultServeMux = NewServeMux()

// The HandlerFunc type is an adapter to allow the use of
// ordinary functions as DNS handlers.  If f is a function
// with the appropriate signature, HandlerFunc(f) is a
// Handler object that calls f.
type HandlerFunc func(ResponseWriter, *Msg)

// ServerDNS calls f(w, r)
func (f HandlerFunc) ServeDNS(w ResponseWriter, r *Msg) {
	f(w, r)
}

// Failed is a helper handler that returns an answer with
// RCODE = servfail for every request.
func Failed(w ResponseWriter, r *Msg) {
	m := new(Msg)
	m.SetRcode(r, RcodeServerFailure)
	w.Write(m)
}

// FailedHandler returns HandlerFunc with Failed.
func FailedHandler() Handler { return HandlerFunc(Failed) }

// Start a server on addresss and network speficied. Invoke handler
// for any incoming queries.
func ListenAndServe(addr string, network string, handler Handler) error {
	server := &Server{Addr: addr, Net: network, Handler: handler}
	return server.ListenAndServe()
}

func (mux *ServeMux) match(zone string, t uint16) Handler {
	// Exact match
	zone = toRadixName(zone)
	if h := mux.m.Find(zone); h != nil && h.Value != nil {
		// If we got queried for a DS record, we must see if we
		// if we also serve the parent. We then redirect it.
		if t == TypeDS {
			if d := h.Up(); d != nil {
				return d.Value.(Handler)
			}
		}
		return h.Value.(Handler)
	}
	// Best matching one.
	if h := mux.m.Predecessor(zone); h != nil && h.Value != nil {
		return h.Value.(Handler)
	}
	return nil
}

// Handle adds a handler to the ServeMux for pattern.
func (mux *ServeMux) Handle(pattern string, handler Handler) {
	if pattern == "" {
		panic("dns: invalid pattern " + pattern)
	}
	mux.m.Insert(toRadixName(Fqdn(pattern)), handler)
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
	// if its there, its gone
	mux.m.Remove(toRadixName(Fqdn(pattern)))
}

// ServeDNS dispatches the request to the handler whose
// pattern most closely matches the request message. For DS queries
// a parent zone is sought.
// If no handler is found a standard SERVFAIL message is returned
func (mux *ServeMux) ServeDNS(w ResponseWriter, request *Msg) {
	h := mux.match(request.Question[0].Name, request.Question[0].Qtype)
	if h == nil {
		h = FailedHandler()
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
		return srv.ServeTCP(l)
	case "udp", "udp4", "udp6":
		a, e := net.ResolveUDPAddr(srv.Net, addr)
		if e != nil {
			return e
		}
		l, e := net.ListenUDP(srv.Net, a)
		if e != nil {
			return e
		}
		return srv.ServeUDP(l)
	}
	return &Error{Err: "bad network"}
}

// ServeTCP starts a TCP listener for the server.
// Each request is handled in a seperate goroutine.
func (srv *Server) ServeTCP(l *net.TCPListener) error {
	defer l.Close()
	handler := srv.Handler
	if handler == nil {
		handler = DefaultServeMux
	}
forever:
	for {
		rw, e := l.AcceptTCP()
		if e != nil {
			return e
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
		d, err := newConn(rw, nil, rw.RemoteAddr(), m, handler, srv.TsigSecret)
		if err != nil {
			continue
		}
		go d.serve()
	}
	panic("not reached")
}

// ServeUDP starts a UDP listener for the server.
// Each request is handled in a seperate goroutine.
func (srv *Server) ServeUDP(l *net.UDPConn) error {
	defer l.Close()
	handler := srv.Handler
	if handler == nil {
		handler = DefaultServeMux
	}
	if srv.UDPSize == 0 {
		srv.UDPSize = udpMsgSize
	}
	for {
		m := make([]byte, srv.UDPSize)
		n, a, e := l.ReadFromUDP(m)
		if e != nil || n == 0 {
			return e
		}
		m = m[:n]

		if srv.ReadTimeout != 0 {
			l.SetReadDeadline(time.Now().Add(srv.ReadTimeout))
		}
		if srv.WriteTimeout != 0 {
			l.SetWriteDeadline(time.Now().Add(srv.WriteTimeout))
		}
		d, err := newConn(nil, l, a, m, handler, srv.TsigSecret)
		if err != nil {
			continue
		}
		go d.serve()
	}
	panic("not reached")
}

func newConn(t *net.TCPConn, u *net.UDPConn, a net.Addr, buf []byte, handler Handler, tsig map[string]string) (*conn, error) {
	c := new(conn)
	c.handler = handler
	c._TCP = t
	c._UDP = u
	c.remoteAddr = a
	c.request = buf
	c.tsigSecret = tsig
	return c, nil
}

// Serve a new connection.
func (c *conn) serve() {
	// for block to make it easy to break out to close the tcp connection
	for {
		// Request has been read in ServeUDP or ServeTCP
		w := new(response)
		w.conn = c
		req := new(Msg)
		if !req.Unpack(c.request) {
			// Send a format error back
			x := new(Msg)
			x.SetRcodeFormatError(req)
			w.Write(x)
			break
		}

		w.tsigStatus = nil
		if t := req.IsTsig(); t != nil {
			secret := t.Hdr.Name
			if _, ok := w.conn.tsigSecret[secret]; !ok {
				w.tsigStatus = ErrKeyAlg
			}
			w.tsigStatus = TsigVerify(c.request, w.conn.tsigSecret[secret], "", false)
			w.tsigTimersOnly = false
			w.tsigRequestMAC = req.Extra[len(req.Extra)-1].(*RR_TSIG).MAC
		}
		w.req = req
		c.handler.ServeDNS(w, w.req) // this does the writing back to the client
		if c.hijacked {
			return
		}
		break
	}
	if c._TCP != nil {
		c._TCP.Close()
		c._TCP = nil
	}
}

// Write implements the ResponseWriter.Write method.
func (w *response) Write(m *Msg) (err error) {
	var (
		data []byte
		ok   bool
	)
	if m == nil {
		return &Error{Err: "nil message"}
	}
	if t := m.IsTsig(); t != nil {
		data, w.tsigRequestMAC, err = TsigGenerate(m, w.conn.tsigSecret[t.Hdr.Name], w.tsigRequestMAC, w.tsigTimersOnly)
		if err != nil {
			return err
		}
	} else {
		data, ok = m.Pack()
		if !ok {
			return ErrPack
		}
	}
	return w.WriteBuf(data)
}

// WriteBuf implements the ResponseWriter.WriteBuf method.
func (w *response) WriteBuf(m []byte) (err error) {
	if m == nil {
		return &Error{Err: "nil message"}
	}
	switch {
	case w.conn._UDP != nil:
		_, err := w.conn._UDP.WriteTo(m, w.conn.remoteAddr)
		if err != nil {
			return err
		}
	case w.conn._TCP != nil:
		if len(m) > MaxMsgSize {
			return ErrBuf
		}
		l := make([]byte, 2)
		l[0], l[1] = packUint16(uint16(len(m)))
		n, err := w.conn._TCP.Write(l)
		if err != nil {
			return err
		}
		if n != 2 {
			return io.ErrShortWrite
		}
		n, err = w.conn._TCP.Write(m)
		if err != nil {
			return err
		}
		i := n
		if i < len(m) {
			j, err := w.conn._TCP.Write(m[i:len(m)])
			if err != nil {
				return err
			}
			i += j
		}
		n = i
	}
	return nil
}

// RemoteAddr implements the ResponseWriter.RemoteAddr method.
func (w *response) RemoteAddr() net.Addr { return w.conn.remoteAddr }

// TsigStatus implements the ResponseWriter.TsigStatus method.
func (w *response) TsigStatus() error { return w.tsigStatus }

// TsigTimersOnly implements the ResponseWriter.TsigTimersOnly method.
func (w *response) TsigTimersOnly(b bool) { w.tsigTimersOnly = b }

// Hijack implements the ResponseWriter.Hijack method.
func (w *response) Hijack() { w.hijacked = true }

// Close implements the ResponseWriter.Close method
func (w *response) Close() error {
	if w.conn._UDP != nil {
		e := w.conn._UDP.Close()
		w.conn._UDP = nil
		return e
	}
	if w.conn._TCP != nil {
		e := w.conn._TCP.Close()
		w.conn._TCP = nil
		return e
	}
	// no-op
	return nil
}
