package dns

import (
	"context"
	"sync"
)

// handlerContextFromHandler is used internally to wrap a Handler into a
// HandlerContext, to aid in maintaining backwards compatibility.
func handlerContextFromHandler(h Handler) HandlerContext {
	return HandlerFuncContext(func(_ context.Context, w ResponseWriter, r *Msg) {
		h.ServeDNS(w, r)
	})
}

// ServeMuxContext is a context-aware version of ServeMux.
//
// ServeMuxContext is safe for concurrent access from multiple goroutines.
//
// The zero ServeMuxContext is empty and ready for use.
type ServeMuxContext struct {
	z map[string]HandlerContext
	m sync.RWMutex
}

// NewServeMuxContext allocates and returns a new NewServeMuxContext.
func NewServeMuxContext() *ServeMuxContext {
	return new(ServeMuxContext)
}

func (mux *ServeMuxContext) match(q string, t uint16) HandlerContext {
	mux.m.RLock()
	defer mux.m.RUnlock()
	if mux.z == nil {
		return nil
	}

	q = CanonicalName(q)

	var handler HandlerContext
	for off, end := 0, false; !end; off, end = NextLabel(q, off) {
		if h, ok := mux.z[q[off:]]; ok {
			if t != TypeDS {
				return h
			}
			// Continue for DS to see if we have a parent too, if so delegate to the parent
			handler = h
		}
	}

	// Wildcard match, if we have found nothing try the root zone as a last resort.
	if h, ok := mux.z["."]; ok {
		return h
	}

	return handler
}

// Handle adds a handler to the ServeMux for pattern.
func (mux *ServeMuxContext) Handle(pattern string, handler HandlerContext) {
	if pattern == "" {
		panic("dns: invalid pattern " + pattern)
	}
	mux.m.Lock()
	if mux.z == nil {
		mux.z = make(map[string]HandlerContext)
	}
	mux.z[CanonicalName(pattern)] = handler
	mux.m.Unlock()
}

// HandleFunc adds a handler function to the ServeMuxContext for pattern.
func (mux *ServeMuxContext) HandleFunc(pattern string, handler func(context.Context, ResponseWriter, *Msg)) {
	mux.Handle(pattern, HandlerFuncContext(handler))
}

// HandleRemove deregisters the handler specific for pattern from the ServeMuxContext.
func (mux *ServeMuxContext) HandleRemove(pattern string) {
	if pattern == "" {
		panic("dns: invalid pattern " + pattern)
	}
	mux.m.Lock()
	delete(mux.z, CanonicalName(pattern))
	mux.m.Unlock()
}

// ServeDNS is the same as in ServeMux, but also passes on the context
// when calling handlers.
func (mux *ServeMuxContext) ServeDNS(ctx context.Context, w ResponseWriter, req *Msg) {
	var h HandlerContext
	if len(req.Question) >= 1 { // allow more than one question
		h = mux.match(req.Question[0].Name, req.Question[0].Qtype)
	}

	if h != nil {
		h.ServeDNS(ctx, w, req)
	} else {
		handleRefused(w, req)
	}
}

// ServeMux is an DNS request multiplexer. It matches the zone name of
// each incoming request against a list of registered patterns add calls
// the handler for the pattern that most closely matches the zone name.
//
// ServeMux is DNSSEC aware, meaning that queries for the DS record are
// redirected to the parent zone (if that is also registered), otherwise
// the child gets the query.
//
// ServeMux is also safe for concurrent access from multiple goroutines.
//
// The zero ServeMux is empty and ready for use.
type ServeMux struct {
	m ServeMuxContext
}

// NewServeMux allocates and returns a new ServeMux.
func NewServeMux() *ServeMux {
	return new(ServeMux)
}

// DefaultServeMux is the default ServeMux used by Serve.
var DefaultServeMux = NewServeMux()

// Handle adds a handler to the ServeMux for pattern.
func (mux *ServeMux) Handle(pattern string, handler Handler) {
	mux.m.Handle(pattern, HandlerFuncContext(func(_ context.Context, w ResponseWriter, req *Msg) {
		handler.ServeDNS(w, req)
	}))
}

// HandleFunc adds a handler function to the ServeMux for pattern.
func (mux *ServeMux) HandleFunc(pattern string, handler func(ResponseWriter, *Msg)) {
	mux.m.Handle(pattern, HandlerFuncContext(func(_ context.Context, w ResponseWriter, req *Msg) {
		handler(w, req)
	}))
}

// HandleRemove deregisters the handler specific for pattern from the ServeMux.
func (mux *ServeMux) HandleRemove(pattern string) {
	mux.m.HandleRemove(pattern)
}

// ServeDNS dispatches the request to the handler whose pattern most
// closely matches the request message.
//
// ServeDNS is DNSSEC aware, meaning that queries for the DS record
// are redirected to the parent zone (if that is also registered),
// otherwise the child gets the query.
//
// If no handler is found, or there is no question, a standard REFUSED
// message is returned
func (mux *ServeMux) ServeDNS(w ResponseWriter, req *Msg) {
	// Note: context.Background() is a placeholder to satisfy the function interface.
	// The value is never actually used.
	mux.m.ServeDNS(context.Background(), w, req)
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
