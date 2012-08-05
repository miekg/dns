package main

import (
	"dns"
	"fmt"
	"radix"
	"strings"
	"time"
)

// Cache elements, we using to key (toRadixKey) to distinguish between dns and dnssec
type Packet struct {
	ttl time.Time // insertion time
	d   *dns.Msg  // packet
}

func toRadixKey(d *dns.Msg) string {
	s := fmt.Sprintf("%s,%d,%d", strings.ToLower(d.Question[0].Name), d.Question[0].Qtype, d.Question[0].Qclass)
	for _, r := range d.Extra {
		if r.Header().Rrtype == dns.TypeOPT {
			if r.(*dns.RR_OPT).Do() {
				return s + "D"
			}
		}
	}
	return s + "P" // plain
}

type Cache struct {
	*radix.Radix
}

func NewCache() *Cache {
	return &Cache{Radix: radix.New()}
}

func (c *Cache) Find(d *dns.Msg) *dns.Msg {
	p := c.Radix.Find(toRadixKey(d))
	if p == nil {
		return nil
	}
	return p.Value.(*Packet).d
}

func (c *Cache) Insert(d *dns.Msg) {
	c.Radix.Insert(toRadixKey(d), &Packet{d: d, ttl: time.Now().UTC()})
}

func (c *Cache) Remove(d *dns.Msg) {
	c.Radix.Remove(toRadixKey(d))
}
