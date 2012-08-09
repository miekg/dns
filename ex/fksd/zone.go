package main

import (
	"dns"
	"os"
)

// ReadZoneFile reads a zone and adds it.
func (c *Config) ReadZoneFile(origin, file string) error {
	f, e := os.Open(file)
	if e != nil {
		return e
	}
	z := dns.NewZone(origin)
	for rr := range dns.ParseZone(f, origin, file) {
		if rr.Error == nil {
			if e := z.Insert(rr.RR); e != nil {
				logPrintf("failed to insert record: %s\n", e.Error())
			}
		} else {
			logPrintf("failed to parse: %s\n", rr.Error.Error())
		}
	}
	c.Zones[origin] = z
	dns.HandleFunc(origin, func(w dns.ResponseWriter, req *dns.Msg) { serve(w, req, c.Zones[origin]) })
	return nil
}

// DropZone discards a zone from the config.
func (c *Config) DropZone(origin string) error {
	dns.HandleRemove(origin)
	delete(c.Zones, origin)
	return nil
}

// ReadZoneXfr reads a zone from an axfr.
func (c *Config) ReadZoneXfr(origin, master string) error {
	client := new(dns.Client)
	client.Net = "tcp"
	m := new(dns.Msg)
	m.SetAxfr(origin)

	z := dns.NewZone(origin)
	t, e := client.XfrReceive(m, master)
	if e == nil {
		for r := range t {
			if r.Error == nil {
				// Loop answer section
				for _, rr := range r.Reply.Answer {
					z.Insert(rr)
				}
			}
		}
		c.Zones[origin] = z
		dns.HandleFunc(origin, func(w dns.ResponseWriter, req *dns.Msg) { serve(w, req, c.Zones[origin]) })
		return nil
	}
	return e
}
