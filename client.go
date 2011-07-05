package dns

// A concurrent client implementation. 
// Client sends query to a channel which
// will then handle the query. Returned replys
// are return on another channel. Ready for handling --- same
// setup for server - a HANDLER function that gets run
// when the query returns.

import (
	"os"
	"io"
	"net"
)

type QueryHandler interface {
	QueryDNS(w RequestWriter, q *Msg)
}

// A RequestWriter interface is used by an DNS query handler to
// construct an DNS request.
type RequestWriter interface {
	WriteMessages([]*Msg)
	Write(*Msg)
	Send(*Msg) os.Error
	Receive() (*Msg, os.Error)
}

// hijacked connections...?
type reply struct {
	client         *Client
	addr           string
	req            *Msg
	conn           net.Conn
	tsigRequestMAC string
	tsigTimersOnly bool
}

type Request struct {
	Request *Msg
	Addr    string
	Client  *Client
}

// QueryMux is an DNS request multiplexer. It matches the
// zone name of each incoming request against a list of 
// registered patterns add calls the handler for the pattern
// that most closely matches the zone name.
type QueryMux struct {
	m map[string]QueryHandler
}

// NewQueryMux allocates and returns a new QueryMux.
func NewQueryMux() *QueryMux { return &QueryMux{make(map[string]QueryHandler)} }

// DefaultQueryMux is the default QueryMux used by Query.
var DefaultQueryMux = NewQueryMux()

func newQueryChanSlice() chan []*Msg { return make(chan []*Msg) }
func newQueryChan() chan *Request    { return make(chan *Request) }

// Default channel to use for the resolver
var DefaultReplyChan = newQueryChanSlice()
var DefaultQueryChan = newQueryChan()

// The HandlerQueryFunc type is an adapter to allow the use of
// ordinary functions as DNS query handlers.  If f is a function
// with the appropriate signature, HandlerQueryFunc(f) is a
// QueryHandler object that calls f.
type HandlerQueryFunc func(RequestWriter, *Msg)

// QueryDNS calls f(w, reg)
func (f HandlerQueryFunc) QueryDNS(w RequestWriter, r *Msg) {
	go f(w, r)
}

func HandleQueryFunc(pattern string, handler func(RequestWriter, *Msg)) {
	DefaultQueryMux.HandleQueryFunc(pattern, handler)
}

// reusing zoneMatch from server.go
func (mux *QueryMux) match(zone string) QueryHandler {
	var h QueryHandler
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

func (mux *QueryMux) Handle(pattern string, handler QueryHandler) {
	if pattern == "" {
		panic("dns: invalid pattern " + pattern)
	}
	mux.m[pattern] = handler
}

func (mux *QueryMux) HandleQueryFunc(pattern string, handler func(RequestWriter, *Msg)) {
	mux.Handle(pattern, HandlerQueryFunc(handler))
}

func (mux *QueryMux) QueryDNS(w RequestWriter, r *Msg) {
	h := mux.match(r.Question[0].Name)
	if h == nil {
                panic("dns: no handler found for " + r.Question[0].Name)
	}
	h.QueryDNS(w, r)
}

// TODO add: LocalAddr
type Client struct {
	Net          string            // if "tcp" a TCP query will be initiated, otherwise an UDP one
	Addr         string            // address to call
	Attempts     int               // number of attempts
	Retry        bool              // retry with TCP
	ChannelQuery chan *Request     // read DNS request from this channel
	ChannelReply chan []*Msg       // read DNS request from this channel
	ReadTimeout  int64             // the net.Conn.SetReadTimeout value for new connections
	WriteTimeout int64             // the net.Conn.SetWriteTimeout value for new connections
	TsigSecret   map[string]string // secret(s) for Tsig map[<zonename>]<base64 secret>
}

func NewClient() *Client {
	c := new(Client)
	c.Net = "udp"
	c.Attempts = 1
	c.ChannelReply = DefaultReplyChan
	return c
}

type Query struct {
	ChannelQuery chan *Request // read DNS request from this channel
	Handler      QueryHandler  // handler to invoke, dns.DefaultQueryMux if nil
}

func (q *Query) Query() os.Error {
	handler := q.Handler
	if handler == nil {
		handler = DefaultQueryMux
	}
//forever:
	for {
		select {
		case in := <-q.ChannelQuery:
			w := new(reply)
			w.req = in.Request
			w.addr = in.Addr
			w.client = in.Client
			handler.QueryDNS(w, in.Request)
		}
	}
	return nil
}

func (q *Query) ListenAndQuery() os.Error {
	if q.ChannelQuery == nil {
		q.ChannelQuery = DefaultQueryChan
	}
	return q.Query()
}


// Start listener for firing off the queries. If
// c is nil DefaultQueryChan is used. If handler is nil
// DefaultQueryMux is used.
func ListenAndQuery(c chan *Request, handler QueryHandler) {
	q := &Query{ChannelQuery: c, Handler: handler}
	go q.ListenAndQuery()
}

func (w *reply) Write(m *Msg) {
	w.Client().ChannelReply <- []*Msg{w.req, m}
}

// Do performs an asynchronous query. The result is returned on the
// channel set in the c.
func (c *Client) Do(m *Msg, a string) {
	if c.ChannelQuery == nil {
		DefaultQueryChan <- &Request{Client: c, Addr: a, Request: m}
	} else {
		c.ChannelQuery <- &Request{Client: c, Addr: a, Request: m}
	}
}

// Perform an synchronous query. Send the message m to the address
// contained in a
func (c *Client) Exchange(m *Msg, a string) *Msg {
	w := new(reply)
	w.client = c
	w.addr = a
	out, ok := m.Pack()
	if !ok {
		//
	}
	_, err := w.writeClient(out)
	if err != nil {
		return nil
	}

	// udp / tcp
	p := make([]byte, DefaultMsgSize)
	n, err := w.readClient(p)
	if err != nil {
		return nil
	}
	p = p[:n]
        r := new(Msg)
	if ok := r.Unpack(p); !ok {
		return nil
	}
	return r
}

func (w *reply) WriteMessages(m []*Msg) {
	m1 := append([]*Msg{w.req}, m...)
	w.Client().ChannelReply <- m1
}

func (w *reply) Client() *Client {
	return w.client
}

func (w *reply) Request() *Msg {
	return w.req
}

func (w *reply) Receive() (*Msg, os.Error) {
	var p []byte
	m := new(Msg)
	switch w.Client().Net {
	case "tcp", "tcp4", "tcp6":
		p = make([]byte, MaxMsgSize)
	case "udp", "udp4", "udp6":
		p = make([]byte, DefaultMsgSize)
	}
	n, err := w.readClient(p)
	if err != nil {
		return nil, err
	}
	p = p[:n]
	if ok := m.Unpack(p); !ok {
		return nil, ErrUnpack
	}
	// Tsig
	if m.IsTsig() {
		secret := m.Extra[len(m.Extra)-1].(*RR_TSIG).Hdr.Name
		_, ok := w.Client().TsigSecret[secret]
		if !ok {
			return m, ErrNoSig
		}
		ok, err := TsigVerify(p, w.Client().TsigSecret[secret], w.tsigRequestMAC, w.tsigTimersOnly)
		if !ok {
			return m, err
		}
	}
	return m, nil
}

func (w *reply) readClient(p []byte) (n int, err os.Error) {
	if w.conn == nil {
		panic("no connection")
	}
	switch w.Client().Net {
	case "tcp", "tcp4", "tcp6":
		if len(p) < 1 {
			return 0, io.ErrShortBuffer
		}
		n, err = w.conn.(*net.TCPConn).Read(p[0:2])
		if err != nil || n != 2 {
			return n, err
		}
		l, _ := unpackUint16(p[0:2], 0)
		if l == 0 {
			return 0, ErrShortRead
		}
		if int(l) > len(p) {
			return int(l), io.ErrShortBuffer
		}
		n, err = w.conn.(*net.TCPConn).Read(p[:l])
		if err != nil {
			return n, err
		}
		i := n
		for i < int(l) {
			j, err := w.conn.(*net.TCPConn).Read(p[i:int(l)])
			if err != nil {
				return i, err
			}
			i += j
		}
		n = i
	case "udp", "udp4", "udp6":
		n, _, err = w.conn.(*net.UDPConn).ReadFromUDP(p)
		if err != nil {
			return n, err
		}
	}
	return
}

// Send a msg to the address specified in w.
// If the message m contains a TSIG record the transaction
// signature is calculated.
func (w *reply) Send(m *Msg) os.Error {
	if m.IsTsig() {
		secret := m.Extra[len(m.Extra)-1].(*RR_TSIG).Hdr.Name
		_, ok := w.Client().TsigSecret[secret]
		if !ok {
			return ErrNoSig
		}
		m, _ = TsigGenerate(m, w.Client().TsigSecret[secret], w.tsigRequestMAC, w.tsigTimersOnly)
		w.tsigRequestMAC = m.Extra[len(m.Extra)-1].(*RR_TSIG).MAC // Safe the requestMAC
	}
	out, ok := m.Pack()
	if !ok {
		return ErrPack
	}
	_, err := w.writeClient(out)
	if err != nil {
		return err
	}
	return nil
}

func (w *reply) writeClient(p []byte) (n int, err os.Error) {
	c := w.Client()
	if c.Attempts == 0 {
		panic("c.Attempts 0")
	}
	if c.Net == "" {
		panic("c.Net empty")
	}

	conn, err := net.Dial(c.Net, w.addr)
	if err != nil {
		return 0, err
	}
	w.conn = conn
	switch c.Net {
	case "tcp", "tcp4", "tcp6":
		if len(p) < 2 {
			return 0, io.ErrShortBuffer
		}
		for a := 0; a < c.Attempts; a++ {
			l := make([]byte, 2)
			l[0], l[1] = packUint16(uint16(len(p)))
			n, err = conn.Write(l)
			if err != nil {
				if e, ok := err.(net.Error); ok && e.Timeout() {
					continue
				}
				return n, err
			}
			if n != 2 {
				return n, io.ErrShortWrite
			}
			n, err = conn.Write(p)
			if err != nil {
				if e, ok := err.(net.Error); ok && e.Timeout() {
					continue
				}
				return n, err
			}
			i := n
			if i < len(p) {
				j, err := conn.Write(p[i:len(p)])
				if err != nil {
					if e, ok := err.(net.Error); ok && e.Timeout() {
						// We are half way in our write...
						continue
					}
					return i, err
				}
				i += j
			}
			n = i
		}
	case "udp", "udp4", "udp6":
		for a := 0; a < c.Attempts; a++ {
			n, err = conn.(*net.UDPConn).WriteTo(p, conn.RemoteAddr())
			if err != nil {
				if e, ok := err.(net.Error); ok && e.Timeout() {
					continue
				}
				return 0, err
			}
		}
	}
	return 0, nil
}
