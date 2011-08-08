package main

// Keep a local cache of DNS packets. Match incoming
// qname,qclass,qtype and return the saved packet.
// On a cache miss consult the nameserver

import (
	"dns"
        "sync"
        "time"
)

// Keep everything in the cache for 60 seconds
const (
        CACHETTL = 1
        _CLASS = 2 << 16

        INSERT = iota
        DELETE
)

var cache Cache

type item struct {
        epoch int64
        msg []byte
}

// Number in the second map denotes the class + type.
func intval(c, t uint16) int {
        return int(c)*_CLASS + int(t)
}

// Mutex entry in the cache, if non-nill take the lock
// Ala Zone in zone.go, but slightly different
type Cache struct {
        data map[string]map[int]*item
        rw  *sync.RWMutex
}

func NewCache() Cache {
        c := new(Cache)
        c.data = make(map[string]map[int]*item)
        c.rw = new(sync.RWMutex)
        return *c
}

// Add an entry to the cache. The old entry (if any) gets overwritten
func (c Cache) add(q *dns.Msg) {
        c.rw.Lock()
        defer c.rw.Unlock()
        qname := q.Question[0].Name
        i := intval(q.Question[0].Qclass, q.Question[0].Qtype)
        if c.data[qname] == nil {
                im := make(map[int]*item)
                c.data[qname] = im
        }
        buf, _ := q.Pack()
        im := c.data[qname]
        im[i] = &item{time.Seconds(), buf}
}

// Lookup an entry in the cache. Returns nil
// when nothing found.
func (c Cache) lookup(q *dns.Msg) []byte {
        // Use the question section for looking up
        c.rw.RLock()
        defer c.rw.RUnlock()
        i := intval(q.Question[0].Qclass, q.Question[0].Qtype)
        if im, ok := c.data[q.Question[0].Name]; ok {
                // we have the name
                if d, ok := im[i]; ok {
                        // We even have the entry, check cache time
                        if time.Seconds() - d.epoch > CACHETTL {
                                // Too olds means we get a new one
                                return nil
                        }
                        e := make([]byte, len(d.msg))
                        copy(e, d.msg)
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
                p, _ = c.Client.Exchange(m, c.Addr)
        }
        cache.add(p)
        o, _ = p.Pack()
        return
}

// Return the configration
func NewFunkenSturm() *FunkenSturm {
	f := new(FunkenSturm)
        f.Funk = make([]*Funk, 1)
	f.Setup = func() bool { cache = NewCache(); return true }
        f.Funk[0] = new(Funk)
        f.Funk[0].Match = func(m *dns.Msg) (*dns.Msg, bool) { return m, true }
	f.Funk[0].Action = checkcache
	return f
}
