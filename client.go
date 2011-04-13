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
	"net"
)

type QueryHandler interface {
	QueryDNS(w RequestWriter, q *Msg)
}

// A RequestWriter interface is used by an DNS query handler to
// construct an DNS request.
type RequestWriter interface {
	RemoteAddr() string     // moet het channel zijn...!

	Write([]byte) (int, os.Error)
}

type qconn struct {
	remoteAddr net.Addr  // address of remote side (sans port)
	port       int       // port of the remote side, needed TODO(mg)
	handler    Handler   // request handler
	request    []byte    //  the request
	w          chan *Msg //
	hijacked   bool      // connection has been hijacked by hander TODO(mg)
}

type reply struct {
	conn *qconn
	req  *Msg
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

func newQueryChan() chan *Msg { return make(chan *Msg) }

// Default channel to use for the resolver
var DefaultQueryChan = newQueryChan()

// The HandlerQueryFunc type is an adapter to allow the use of
// ordinary functions as DNS query handlers.  If f is a function
// with the appropriate signature, HandlerQueryFunc(f) is a
// QeuryHandler object that calls f.
type HandlerQueryFunc func(RequestWriter, *Msg)

// QueryDNS calls f(w, reg)
func (f HandlerQueryFunc) QueryDNS(w RequestWriter, r *Msg) {
	f(w, r)
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
	Handler      QueryHandler // handler to invoke, dns.DefaultQueryMux if nil
	ReadTimeout  int64        // the net.Conn.SetReadTimeout value for new connections
	WriteTimeout int64        // the net.Conn.SetWriteTimeout value for new connections
}


// Query accepts incoming DNS request,
// Write to in
// creating a new service thread for each.  The service threads
// read requests and then call handler to reply to them.
// Handler is typically nil, in which case the DefaultServeMux is used.
func Query(w chan *Msg, handler QueryHandler) os.Error {
	clnt := &Client{Handler: handler}
	return clnt.Query(w)
}

func (clnt *Client) Query(w chan *Msg) os.Error {
	handler := clnt.Handler
	if handler == nil {
		handler = DefaultQueryMux
	}
	return nil
}

func (clnt *Client) ListenAndQuery(w chan *Msg) os.Error {
	/* ... */
	return nil
}
