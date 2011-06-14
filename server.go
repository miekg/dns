// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// DNS server implementation.

package dns

import (
	"io"
	"os"
	"net"
)

type Handler interface {
	ServeDNS(w ResponseWriter, r *Msg)
	// IP based ACL mapping. The contains the string representation
	// of the IP address and a boolean saying it may connect (true) or not.
}

// A ResponseWriter interface is used by an DNS handler to
// construct an DNS response.
type ResponseWriter interface {
	// RemoteAddr returns the address of the client that sent the current request
	RemoteAddr() string

	Write([]byte) (int, os.Error)
}

type conn struct {
	remoteAddr net.Addr     // address of remote side (sans port)
	port       int          // port of the remote side, needed TODO(mg)
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

// ServerDNS calls f(w, reg)
func (f HandlerFunc) ServeDNS(w ResponseWriter, r *Msg) {
	f(w, r)
}

// Helper handlers

func Refused(w ResponseWriter, r *Msg) {
	m := new(Msg)
	m.SetReply(r)
	m.MsgHdr.Rcode = RcodeRefused
	m.MsgHdr.Authoritative = false
	buf, _ := m.Pack()
	w.Write(buf)
}

// RefusedHandler return a REFUSED answer
func RefusedHandler() Handler { return HandlerFunc(Refused) }

func ListenAndServe(addr string, network string, handler Handler) os.Error {
	server := &Server{Addr: addr, Net: network, Handler: handler}
	return server.ListenAndServe()
}

func zoneMatch(pattern, zone string) (ok bool) {
	if len(pattern) == 0 {
		return
	}
	i := 0
	for {
		ok = pattern[len(pattern)-1-i] == zone[len(zone)-1-i]
		i++

		if !ok {
			break
		}
		if len(pattern)-1-i < 0 || len(zone)-1-i < 0 {
			break
		}

	}
	return
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
	if pattern[len(pattern)-1] != '.' { // no ending .
		mux.m[pattern+"."] = handler
	} else {
		mux.m[pattern] = handler
	}
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
type Server struct {
	Addr         string  // address to listen on, ":dns" if empty
	Net          string  // if "tcp" it will invoke a TCP listener, otherwise an UDP one
	Handler      Handler // handler to invoke, dns.DefaultServeMux if nil
	ReadTimeout  int64   // the net.Conn.SetReadTimeout value for new connections
	WriteTimeout int64   // the net.Conn.SetWriteTimeout value for new connections
}

// Serve accepts incoming DNS request on the TCP listener l,
// creating a new service thread for each.  The service threads
// read requests and then call handler to reply to them.
// Handler is typically nil, in which case the DefaultServeMux is used.
func ServeTCP(l *net.TCPListener, handler Handler) os.Error {
	srv := &Server{Handler: handler, Net: "tcp"}
	return srv.ServeTCP(l)
}

// Serve accepts incoming DNS request on the UDP Conn l,
// creating a new service thread for each.  The service threads
// read requests and then call handler to reply to them.
// Handler is typically nil, in which case the DefaultServeMux is used.
func ServeUDP(l *net.UDPConn, handler Handler) os.Error {
	srv := &Server{Handler: handler, Net: "udp"}
	return srv.ServeUDP(l)
}

// Fixes for udp/tcp
func (srv *Server) ListenAndServe() os.Error {
	addr := srv.Addr
	if addr == "" {
		addr = ":domain"
	}
	switch srv.Net {
	case "tcp":
		a, e := net.ResolveTCPAddr("tcp",addr)
		if e != nil {
			return e
		}
		l, e := net.ListenTCP("tcp", a)
		if e != nil {
			return e
		}
		return srv.ServeTCP(l)
	case "udp":
		a, e := net.ResolveUDPAddr("udp",addr)
		if e != nil {
			return e
		}
		l, e := net.ListenUDP("udp", a)
		if e != nil {
			return e
		}
		return srv.ServeUDP(l)
	}
	return nil // os.Error with wrong network
}

func (srv *Server) ServeTCP(l *net.TCPListener) os.Error {
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
			rw.SetReadTimeout(srv.ReadTimeout)
		}
		if srv.WriteTimeout != 0 {
			rw.SetWriteTimeout(srv.WriteTimeout)
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

func (srv *Server) ServeUDP(l *net.UDPConn) os.Error {
	defer l.Close()
	handler := srv.Handler
	if handler == nil {
		handler = DefaultServeMux
	}
	for {
		m := make([]byte, DefaultMsgSize)
		n, a, e := l.ReadFromUDP(m)
		if e != nil {
			return e
		}
		m = m[:n]

		if srv.ReadTimeout != 0 {
			l.SetReadTimeout(srv.ReadTimeout)
		}
		if srv.WriteTimeout != 0 {
			l.SetWriteTimeout(srv.WriteTimeout)
		}
		d, err := newConn(nil, l, a, m, handler)
		if err != nil {
			continue
		}
		go d.serve()
	}
	panic("not reached")
}

func newConn(t *net.TCPConn, u *net.UDPConn, a net.Addr, buf []byte, handler Handler) (*conn, os.Error) {
	c := new(conn)
	c.handler = handler
	c._TCP = t
	c._UDP = u
	c.remoteAddr = a
	c.request = buf
	if t != nil {
		c.port = a.(*net.TCPAddr).Port
	}
	if u != nil {
		c.port = a.(*net.UDPAddr).Port
	}
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
			break
		}
		w.req = req
		c.handler.ServeDNS(w, w.req) // this does the writing back to the client
		if c.hijacked {
			return
		}
		break // TODO(mg) Why is this a loop anyway
	}
	if c._TCP != nil {
		c.close() // Listen and Serve is closed then
	}
}


func (w *response) Write(data []byte) (n int, err os.Error) {
	switch {
	case w.conn._UDP != nil:
		n, err = w.conn._UDP.WriteTo(data, w.conn.remoteAddr)
		if err != nil {
			return 0, err
		}
	case w.conn._TCP != nil:
		// TODO(mg) len(data) > 64K
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
func (w *response) RemoteAddr() string { return w.conn.remoteAddr.String() }
