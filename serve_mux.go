package dns

import "sync"

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
func NewServeMux() *ServeMux {
	return &ServeMux{z: make(map[string]Handler), m: new(sync.RWMutex)}
}

// DefaultServeMux is the default ServeMux used by Serve.
var DefaultServeMux = NewServeMux()

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
			b[i] = q[off+i]
			if b[i] >= 'A' && b[i] <= 'Z' {
				b[i] |= 'a' - 'A'
			}
		}
		if h, ok := mux.z[string(b[:l])]; ok { // causes garbage, might want to change the map key
			if t != TypeDS {
				return h
			}
			// Continue for DS to see if we have a parent too, if so delegeate to the parent
			handler = h
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

// HandleFunc adds a handler function to the ServeMux for pattern.
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

func failedHandler() Handler { return HandlerFunc(HandleFailed) }

// ServeDNS dispatches the request to the handler whose
// pattern most closely matches the request message. If DefaultServeMux
// is used the correct thing for DS queries is done: a possible parent
// is sought.
// If no handler is found a standard SERVFAIL message is returned
// If the request message does not have exactly one question in the
// question section a SERVFAIL is returned, unlesss Unsafe is true.
func (mux *ServeMux) ServeDNS(w ResponseWriter, request *Msg) {
	var h Handler
	if len(request.Question) < 1 { // allow more than one question
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
