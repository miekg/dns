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
}

// You can ofcourse make YOUR OWN RESPONSE WRITTER that
// uses TSIG an other cool stuff
type ResponseWriter interface {
        // RemoteAddr returns the address of the client that sent the current request
        RemoteAddr() string

        Write([]byte) (int, os.Error)

        // IP based ACL mapping. The contains the string representation
        // of the IP address and a boolean saying it may connect (true) or not.
        Acl() map[string]bool

        // Tsig secrets. Its a mapping of key names to secrets.
        Tsig() map[string]string
}

type conn struct {
        remoteAddr net.Addr             // address of remote side (sans port)
        handler Handler                 // request handler
        request  []byte                 // bytes read
        connUDP *net.UDPConn
        connTCP *net.TCPConn
}

type response struct {
        conn *conn
        req *Msg
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

// Error replies to the request with the specified error msg TODO(mg)
/* 
func Error(w ResponseWriter) {  }

func NotFound(w ResponseWriter, r *Msg) {

func NotFoundHandler() Handler { return HandlerFunc(NotFound) }
*/


// HandleUDP handles one UDP connection. It reads the incoming
// message and then calls the function f.
// The function f is executed in a seperate goroutine at which point 
// HandleUDP returns.
func HandleUDP(l *net.UDPConn, f func(*Conn, *Msg)) os.Error {
	for {
		m := make([]byte, DefaultMsgSize)
		n, addr, e := l.ReadFromUDP(m)
		if e != nil {
			continue
		}
		m = m[:n]

		d := new(Conn)
                // Use the remote addr as we got from ReadFromUDP
                d.SetUDPConn(l, addr)

		msg := new(Msg)
		if !msg.Unpack(m) {
			continue
		}
		go f(d, msg)
	}
	panic("not reached")
}

// HandleTCP handles one TCP connection. It reads the incoming
// message and then calls the function f.
// The function f is executed in a seperate goroutine at which point 
// HandleTCP returns.
func HandleTCP(l *net.TCPListener, f func(*Conn, *Msg)) os.Error {
	for {
		c, e := l.AcceptTCP()
		if e != nil {
			return e
		}
		d := new(Conn)
                d.SetTCPConn(c, nil)

		msg := new(Msg)
		err := d.ReadMsg(msg)

		if err != nil {
			// Logging??
			continue
		}
		go f(d, msg)
	}
	panic("not reached")
}

func ListenAndServe(addr string, network string, handler Handler) os.Error {
        server := &Server{Addr: addr, Network: network, Handler: handler}
        return server.ListenAndServe()

}

// ListenAndServerTCP listens on the TCP network address addr and
// then calls HandleTCP with f to handle requests on incoming
// connections. The function f may not be nil.
func ListenAndServeTCP(addr string, f func(*Conn, *Msg)) os.Error {
	if f == nil {
		return ErrHandle
	}
	a, err := net.ResolveTCPAddr(addr)
	if err != nil {
		return err
	}
	l, err := net.ListenTCP("tcp", a)
	if err != nil {
		return err
	}
	err = HandleTCP(l, f)
	return err
}

// ListenAndServerUDP listens on the UDP network address addr and
// then calls HandleUDP with f to handle requests on incoming
// connections. The function f may not be nil.
func ListenAndServeUDP(addr string, f func(*Conn, *Msg)) os.Error {
	if f == nil {
		return &Error{Error: "The handle function may not be nil"}
	}
	a, err := net.ResolveUDPAddr(addr)
	if err != nil {
		return err
	}
	l, err := net.ListenUDP("udp", a)
	if err != nil {
		return err
	}
	err = HandleUDP(l, f)
	return err
}

func zoneMatch(pattern, zone string) bool {
        if len(pattern) == 0 {
                return false
        }
        n := len(pattern)
        return zone[:n] == pattern
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
//                h = NotFoundHandler()
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

// Serve accepts incoming DNS request on the listener l,
// creating a new service thread for each.  The service threads
// read requests and then call handler to reply to them.
// Handler is typically nil, in which case the DefaultServeMux is used.
func Serve(l net.Listener, handler Handler) os.Error {
        srv := &Server{Handler: handler}
        return srv.Serve(l)
}

// A Server defines parameters for running an HTTP server.
type Server struct {
        Addr         string  // address to listen on, ":dns" if empty
        Network      string  // If "tcp" it will invoke a TCP listener, otherwise an UDP one
        Handler      Handler // handler to invoke, http.DefaultServeMux if nil
        ReadTimeout  int64   // the net.Conn.SetReadTimeout value for new connections
        WriteTimeout int64   // the net.Conn.SetWriteTimeout value for new connections
}

// Fixes for udp/tcp
func (srv *Server) ListenAndServe() os.Error {
        addr := srv.Addr
        if addr == "" {
                addr = ":domain"
        }
        switch srv.Network {
        case "tcp":
                a, e := net.ResolveTCPAddr(addr)
                if e != nil {
                        return e
                }
                l, e := net.ListenTCP("tcp", a)
                if e != nil {
                        return e
                }
                return srv.ServeTCP(l)
        case "udp":
                a, e := net.ResolveUDPAddr(addr)
                if e != nil {
                        return e
                }
                l, e := net.ListenUDP("udp", a)
                if e != nil {
                        return e
                }
                return srv.ServeUDP(l)
        }
        return nil      // os.Error with wrong network
}

func (srv *Server) ServeTCP(l *net.TCPListener) os.Error {
        defer l.Close()
        handler := srv.Handler
        if handler == nil {
                handler = DefaultServeMux
        }
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
                m := read /* read and set the buffer */ 
                d, err := newConn(rw, nil, rw.RemoteAddr(), nil, handler)
                d.ReadReqest()
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
                c, a, e := l.ReadFromUDP()
                if e != nil {
                        return e
                }
                m = m[:n]

                if srv.ReadTimeout != 0 {
                        rw.SetReadTimeout(srv.ReadTimeout)
                }
                if srv.WriteTimeout != 0 {
                        rw.SetWriteTimeout(srv.WriteTimeout)
                }
                d, err := newConn(rw, nil, addr, m, handler)
                if err != nil {
                        continue
                }
                go d.serve()
        }
        panic("not reached")
}

func newConn(t *net.TCPConn, u *net.UDPConn, a net.Addr, buf []byte, handler Handler) (c *conn, err os.Error) {
        c = new(conn)
        c.handler = handler
        c.TCPconn = t
        c.UDPconn = u
        c.RemoteAddr = a
        return c, err
}

func (c *conn) serve() {
        // c.ReadRequest

        // c.Handler.ServeDNS(w, w.req) // this does the writing
}

func (c *conn) ReadRequest() (w *response, err os.Error) {
        w = new(response)
        return w, nil
}
