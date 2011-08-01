package main

// Keep a local cache of DNS packets. Match incoming
// qname,qclass,qtype and return the saved packet.
// On a cache miss consult the nameserver

import (
	"dns"
)

// Keep everything in the cache for 60 seconds
const (
        CACHETTL = 60
        _CLASS = 2 << 16
)

// Number in the second map denotes the class + type.
func intval(c, t uint16) int {
        return int(c)*_CLASS + int(t)
}

// Ala Zone in zone.go, but slightly different
type Cache map[string]map[int][]byte

func NewCache() Cache {
        c := make(Cache)
        return c
}

// Remove an entry from the cache
func (c Cache) evict(q dns.Msg) {
        // todo
}

// Add an entry from the cache. The old entry (if any) gets
// overwritten
func (c Cache) add(q *dns.Msg) {
        qname := q.Question[0].Name
        i := intval(q.Question[0].Qclass, q.Question[0].Qtype)
        if c[qname] == nil {
                im := make(map[int][]byte)
                c[qname] = im
        }
        buf, _ := q.Pack()
        im := c[qname]
        im[i] = buf
}

// Lookup an entry in the cache. Returns null
// when nothing found.
func (c Cache) lookup(q *dns.Msg) []byte {
        // Use the question section for looking up
        i := intval(q.Question[0].Qclass, q.Question[0].Qtype)
        if im, ok := c[q.Question[0].Name]; ok {
                // we have the name
                if d, ok := im[i]; ok {
                        e := make([]byte, len(d))
                        copy(e, d)
                        return e
                }
        }
        return nil
}

func checkcache(m *dns.Msg) (o []byte) {
        // Check if we have the packet in Cache
        // if so, return it. Otherwise ask the
        // server, return that answer and put it
        // in the cache.
        o = cache.lookup(m)
        if o != nil {
                // octet 1 and 2 contain the Id, set the one for the current pkt
                o[0] = byte(m.MsgHdr.Id >> 8)
                o[1] = byte(m.MsgHdr.Id)
                return
        }
        println("Cache miss")
        var p *dns.Msg
        for _, c := range qr {
                p = c.Client.Exchange(m, c.Addr)
        }
        cache.add(p)
        o, _ = p.Pack()
        return
}

var cache Cache

// Return the configration
func NewFunkenSturm() *FunkenSturm {
	f := new(FunkenSturm)
        f.Funk = make([]*Funk, 1)
	f.Setup = func() bool { cache = NewCache(); return true }
        f.Funk[0] = NewFunk()
        f.Funk[0].Match = func(m *dns.Msg) (*dns.Msg, bool) { return m, true }
	f.Funk[0].Action = checkcache
	return f
}
