package dns

// A concurrent client implementation. 
// Client sends query to a channel which
// will then handle the query. Returned replys
// are return on another channel. Ready for handling --- same
// setup for server - a HANDLER function that gets run
// when the query returns.

// This completely mirrors server.go impl.
import (
	"os"
	//	"net"
)

type QueryHandler interface {
	QueryDNS(w RequestWriter, q *Msg)
}

// A RequestWriter interface is used by an DNS query handler to
// construct an DNS request.
type RequestWriter interface {
	WriteMessages([]*Msg)
        Write(*Msg)
}

// hijacked connections...?
type reply struct {
	Client *Client
	req    *Msg
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
func newQueryChan() chan *Msg { return make(chan *Msg) }

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

// Helper handlers
// Todo

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
	if pattern[len(pattern)-1] != '.' { // no ending .
		mux.m[pattern+"."] = handler
	} else {
		mux.m[pattern] = handler
	}
}

func (mux *QueryMux) HandleQueryFunc(pattern string, handler func(RequestWriter, *Msg)) {
	mux.Handle(pattern, HandlerQueryFunc(handler))
}

func (mux *QueryMux) QueryDNS(w RequestWriter, request *Msg) {
	h := mux.match(request.Question[0].Name)
	if h == nil {
		//                h = RefusedHandler()
		// something else
	}
	h.QueryDNS(w, request)
}

type Client struct {
	Network      string       // if "tcp" a TCP query will be initiated, otherwise an UDP one
	Attempts     int          // number of attempts
	Retry        bool         // retry with TCP
	ChannelQuery chan *Msg    // read DNS request from this channel
	ChannelReply chan []*Msg    // read DNS request from this channel
	Handler      QueryHandler // handler to invoke, dns.DefaultQueryMux if nil
	ReadTimeout  int64        // the net.Conn.SetReadTimeout value for new connections
	WriteTimeout int64        // the net.Conn.SetWriteTimeout value for new connections
}


// Query accepts incoming DNS request,
// Write to in
// creating a new service thread for each.  The service threads
// read requests and then call handler to reply to them.
// Handler is typically nil, in which case the DefaultServeMux is used.
func Query(c chan *Msg, handler QueryHandler) os.Error {
	client := &Client{ChannelQuery: c, Handler: handler}
	return client.Query()
}

func (c *Client) Query() os.Error {
	handler := c.Handler
	if handler == nil {
		handler = DefaultQueryMux
	}
forever:
	for {
		select {
		case in := <-c.ChannelQuery:
			w := new(reply)
			w.Client = c
			w.req = in
			handler.QueryDNS(w, w.req)
		}
	}
	return nil
}

func (c *Client) ListenAndQuery() os.Error {
	if c.ChannelQuery == nil {
		c.ChannelQuery = DefaultQueryChan
	}
	if c.ChannelReply == nil {
		c.ChannelReply = DefaultReplyChan
	}
	return c.Query()
}

func (c *Client) Do(m *Msg, addr string) {
	// addr !!!
	if c.ChannelQuery == nil {
		DefaultQueryChan <- m
	}
}

func ListenAndQuery(c chan *Msg, handler QueryHandler) {
	client := &Client{ChannelQuery: c, Handler: handler}
	go client.ListenAndQuery()
}

func (w *reply) Write(m *Msg) {
	// Write to the channel
	w.Client.ChannelReply <- []*Msg{w.req, m}
}

func (w *reply) WriteMessages(m []*Msg) {
	// Write to the channel
        m1 := append([]*Msg{w.req}, m...)       // Really the way?
	w.Client.ChannelReply <- m1
}
