// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// DNS server implementation.

package dns

import (
	"io"
	"net"
	"time"
)

// how to do Tsig here?? TODO(mg)

type Handler interface {
	ServeDNS(w ResponseWriter, r *Msg)
	// IP based ACL mapping. The contains the string representation
	// of the IP address and a boolean saying it may connect (true) or not.
}

// A ResponseWriter interface is used by an DNS handler to
// construct an DNS response.
type ResponseWriter interface {
	// RemoteAddr returns the net.Addr of the client that sent the current request.
	RemoteAddr() net.Addr
	// Write a reply back to the client.
	Write([]byte) (int, error)
}

// port?
type conn struct {
	remoteAddr net.Addr     // address of remote side (sans port)
	handler    Handler      // request handler
	request    []byte       // bytes read
	_UDP       *net.UDPConn // i/o connection if UDP was used
	_TCP       *net.TCPConn // i/o connection if TCP was used
	hijacked   bool         // connection has been hijacked by hander TODO(mg)
}

type response struct {
	conn *conn
	req  *Msg
}

// ServeMux is an DNS request multiplexer. It matches the
// zone name of each incoming request against a list of 
// registered patterns add calls the handler for the pattern
// that most closely matches the zone name.
type ServeMux struct {
	m map[string]Handler
}

// NewServeMux allocates and returns a new ServeMux.
func NewServeMux() *ServeMux { return &ServeMux{make(map[string]Handler)} }

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

// Helper handler that returns an answer with
// RCODE = refused for every request.
func Refused(w ResponseWriter, r *Msg) {
	m := new(Msg)
	m.SetRcode(r, RcodeRefused)
	buf, _ := m.Pack()
	w.Write(buf)
}

// RefusedHandler returns HandlerFunc with Refused.
func RefusedHandler() Handler { return HandlerFunc(Refused) }

// ...
func ListenAndServe(addr string, network string, handler Handler) error {
	server := &Server{Addr: addr, Net: network, Handler: handler}
	return server.ListenAndServe()
}

func (mux *ServeMux) match(zone string) Handler {
	var h Handler
	var n = 0
	for k, v := range mux.m {
		if !zoneMatch(k, zone) {
			continue
		}
		if h == nil || len(k) > n {
			n = len(k)
			h = v
		}
	}
	return h
}

func (mux *ServeMux) Handle(pattern string, handler Handler) {
	if pattern == "" {
		panic("dns: invalid pattern " + pattern)
	}
	// Should this go
	//if pattern[len(pattern)-1] != '.' { // no ending .
	//	mux.m[pattern+"."] = handler
	//} else {
	mux.m[pattern] = handler
}

func (mux *ServeMux) HandleFunc(pattern string, handler func(ResponseWriter, *Msg)) {
	mux.Handle(pattern, HandlerFunc(handler))
}

// ServeDNS dispatches the request to the handler whose
// pattern most closely matches the request message.
func (mux *ServeMux) ServeDNS(w ResponseWriter, request *Msg) {
	h := mux.match(request.Question[0].Name)
	if h == nil {
		h = RefusedHandler()
	}
	h.ServeDNS(w, request)
}

// Handle register the handler the given pattern
// in the DefaultServeMux. The documentation for
// ServeMux explains how patters are matched.
func Handle(pattern string, handler Handler) { DefaultServeMux.Handle(pattern, handler) }

func HandleFunc(pattern string, handler func(ResponseWriter, *Msg)) {
	DefaultServeMux.HandleFunc(pattern, handler)
}

// A Server defines parameters for running an DNS server.
// Note how much it starts to look like 'Client struct'
type Server struct {
	Addr         string            // address to listen on, ":dns" if empty
	Net          string            // if "tcp" it will invoke a TCP listener, otherwise an UDP one
	Handler      Handler           // handler to invoke, dns.DefaultServeMux if nil
	UDPSize      int               // default buffer to use to read incoming UDP messages
	ReadTimeout  time.Duration     // the net.Conn.SetReadTimeout value for new connections
	WriteTimeout time.Duration     // the net.Conn.SetWriteTimeout value for new connections
	TsigSecret   map[string]string // secret(s) for Tsig map[<zonename>]<base64 secret>
}

// ListenAndServe starts a nameserver on the configured address.
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
	return nil // os.Error with wrong network
}

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
		if err != nil {
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
		d, err := newConn(rw, nil, rw.RemoteAddr(), m, handler)
		if err != nil {
			continue
		}
		go d.serve()
	}
	panic("not reached")
}

func (srv *Server) ServeUDP(l *net.UDPConn) error {
	defer l.Close()
	handler := srv.Handler
	if handler == nil {
		handler = DefaultServeMux
	}
	if srv.UDPSize == 0 {
		srv.UDPSize = UDPMsgSize
	}
	for {
		m := make([]byte, srv.UDPSize)
		n, a, e := l.ReadFromUDP(m)
		if e != nil {
			return e
		}
		m = m[:n]

		if srv.ReadTimeout != 0 {
			l.SetReadDeadline(time.Now().Add(srv.ReadTimeout))
		}
		if srv.WriteTimeout != 0 {
			l.SetWriteDeadline(time.Now().Add(srv.WriteTimeout))
		}
		d, err := newConn(nil, l, a, m, handler)
		if err != nil {
			continue
		}
		go d.serve()
	}
	panic("not reached")
}

func newConn(t *net.TCPConn, u *net.UDPConn, a net.Addr, buf []byte, handler Handler) (*conn, error) {
	c := new(conn)
	c.handler = handler
	c._TCP = t
	c._UDP = u
	c.remoteAddr = a
	c.request = buf
	return c, nil
}

// Close the connection.
func (c *conn) close() {
	switch {
	case c._UDP != nil:
		c._UDP.Close()
		c._UDP = nil
	case c._TCP != nil:
		c._TCP.Close()
		c._TCP = nil
	}
}

// Serve a new connection.
func (c *conn) serve() {
	for {
		// Request has been read in ServeUDP or ServeTCP
		w := new(response)
		w.conn = c
		req := new(Msg)
		if !req.Unpack(c.request) {
			// Send a format error back
			x := new(Msg)
			x.SetRcodeFormatError(req)
			buf, _ := x.Pack()
			w.Write(buf)
			break
		}
		w.req = req
		c.handler.ServeDNS(w, w.req) // this does the writing back to the client
		if c.hijacked {
			return
		}
		break // TODO(mg) Why is this a loop anyway?
	}
	if c._TCP != nil {
		c.close() // Listen and Serve is closed then
	}
}

func (w *response) Write(data []byte) (n int, err error) {
	switch {
	case w.conn._UDP != nil:
		// I should check the clients, udp message size here TODO(mg)
		n, err = w.conn._UDP.WriteTo(data, w.conn.remoteAddr)
		if err != nil {
			return 0, err
		}
	case w.conn._TCP != nil:
		if len(data) > MaxMsgSize {
			return 0, ErrBuf
		}
		l := make([]byte, 2)
		l[0], l[1] = packUint16(uint16(len(data)))
		n, err = w.conn._TCP.Write(l)
		if err != nil {
			return n, err
		}
		if n != 2 {
			return n, io.ErrShortWrite
		}
		n, err = w.conn._TCP.Write(data)
		if err != nil {
			return n, err
		}
		i := n
		if i < len(data) {
			j, err := w.conn._TCP.Write(data[i:len(data)])
			if err != nil {
				return i, err
			}
			i += j
		}
		n = i
	}
	return n, nil
}

// RemoteAddr implements the ResponseWriter.RemoteAddr method
func (w *response) RemoteAddr() net.Addr { return w.conn.remoteAddr }
