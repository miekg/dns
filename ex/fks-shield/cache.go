package main

import (
	"dns"
	"fmt"
	"github.com/miekg/radix"
	"log"
	"strings"
	"time"
)

// Cache elements, we using to key (toRadixKey) to distinguish between dns and dnssec
type Packet struct {
	ttl time.Time // insertion time
	d   []byte    // raw packet, except the first two bytes
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

func (c *Cache) Evict() {
	// A bit tedious, keys() -> find() -> remove()
	for _, key := range c.Radix.Keys() {
		node := c.Radix.Find(key)
		if node == nil || node.Value == nil {
			continue
		}
		if t := time.Since(node.Value.(*Packet).ttl).Seconds(); t > float64(*flagttl) {
			c.Radix.Remove(key)
			if *flaglog {
				log.Printf("fks-shield: evicting %s after %f\n", key, t)
			}
		}
	}
}

func (c *Cache) Find(d *dns.Msg) []byte {
	p := c.Radix.Find(toRadixKey(d))
	if p == nil {
		if *flaglog {
			log.Printf("fsk-shield: cache miss for " + toRadixKey(d))
		}
		return nil
	}
	return p.Value.(*Packet).d
}

func (c *Cache) Insert(d *dns.Msg) {
	if *flaglog {
		log.Printf("fsk-shield: inserting " + toRadixKey(d))
	}
	buf, _ := d.Pack() // Should always work
	c.Radix.Insert(toRadixKey(d), &Packet{d: buf[2:], ttl: time.Now().UTC()})
}

func (c *Cache) Remove(d *dns.Msg) {
	c.Radix.Remove(toRadixKey(d))
}
