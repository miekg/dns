// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// DNS client: see RFC 1035.
// Has to be linked into package net for Dial.

// TODO(rsc):
//	Check periodically whether /etc/resolv.conf has changed.
//	Could potentially handle many outstanding lookups faster.
//	Could have a small cache.
//	Random UDP source port (net.Dial should do that for us).
//	Random request IDs.

package dns

import (
	"os"
	"rand"
	"time"
	"net"
)

// DnsError represents a DNS lookup error.
type DnsError struct {
	Error     string // description of the error
	Name      string // name looked for
	Server    string // server used
	IsTimeout bool
}

func (e *DnsError) String() string {
	s := "lookup " + e.Name
	if e.Server != "" {
		s += " on " + e.Server
	}
	s += ": " + e.Error
	return s
}

func (e *DnsError) Timeout() bool   { return e.IsTimeout }
func (e *DnsError) Temporary() bool { return e.IsTimeout }

const noSuchHost = "no such host"

type Resolver struct {
	Servers  []string // servers to use
	Search   []string // suffixes to append to local name
	Ndots    int      // number of dots in name to trigger absolute lookup
	Timeout  int      // seconds before giving up on packet
	Attempts int      // lost packets before giving up on server
	Rotate   bool     // round robin among servers
}

// Send a request on the connection and hope for a reply.
// Up to res.Attempts attempts.
func Exchange(res *Resolver, c net.Conn, name string, qtype uint16, qclass uint16) (*Msg, os.Error) {
	if len(name) >= 256 {
		return nil, &DnsError{Error: "name too long", Name: name}
	}
	out := new(Msg)
	out.id = uint16(rand.Int()) ^ uint16(time.Nanoseconds())
	out.Question = []Question{
		Question{name, qtype, qclass},
	}
	out.recursion_desired = true
	msg, ok := out.Pack()
	if !ok {
		return nil, &DnsError{Error: "internal error - cannot pack message", Name: name}
	}

	for attempt := 0; attempt < res.Attempts; attempt++ {
		n, err := c.Write(msg)
		if err != nil {
			return nil, err
		}

		c.SetReadTimeout(int64(res.Timeout) * 1e9) // nanoseconds
		// EDNS
		buf := make([]byte, 2000) // More than enough.
		n, err = c.Read(buf)
		if err != nil {
			//			if e, ok := err.(Error); ok && e.Timeout() {
			//				continue
			//			}
			return nil, err
		}
		buf = buf[0:n]
		in := new(Msg)
		if !in.Unpack(buf) || in.id != out.id {
			continue
		}
		return in, nil
	}
	var server string
	if a := c.RemoteAddr(); a != nil {
		server = a.String()
	}
	return nil, &DnsError{Error: "no answer from server", Name: name, Server: server, IsTimeout: true}
}

// Find answer for name in dns message.
// On return, if err == nil, addrs != nil.
func answer(name, server string, dns *Msg, qtype uint16) (addrs []RR, err os.Error) {
	addrs = make([]RR, 0, len(dns.Answer))

	if dns.rcode == RcodeNameError && dns.recursion_available {
		return nil, &DnsError{Error: noSuchHost, Name: name}
	}
	if dns.rcode != RcodeSuccess {
		// None of the error codes make sense
		// for the query we sent.  If we didn't get
		// a name error and we didn't get success,
		// the server is behaving incorrectly.
		return nil, &DnsError{Error: "server misbehaving", Name: name, Server: server}
	}

	// Look for the name.
	// Presotto says it's okay to assume that servers listed in
	// /etc/resolv.conf are recursive resolvers.
	// We asked for recursion, so it should have included
	// all the answers we need in this one packet.
Cname:
	for cnameloop := 0; cnameloop < 10; cnameloop++ {
		addrs = addrs[0:0]
		for i := 0; i < len(dns.Answer); i++ {
			rr := dns.Answer[i]
			h := rr.Header()
			if h.Class == ClassINET && h.Name == name {
				switch h.Rrtype {
				case qtype:
					n := len(addrs)
					addrs = addrs[0 : n+1]
					addrs[n] = rr
				case TypeCNAME:
					// redirect to cname
					name = rr.(*RR_CNAME).Cname
					continue Cname
				}
			}
		}
		if len(addrs) == 0 {
			return nil, &DnsError{Error: noSuchHost, Name: name, Server: server}
		}
		return addrs, nil
	}

	return nil, &DnsError{Error: "too many redirects", Name: name, Server: server}
}

// Look up a single name

func (res *Resolver) Query(name string, qtype uint16, qclass uint16) (msg *Msg, err os.Error) {
	if len(res.Servers) == 0 {
		return nil, &DnsError{Error: "no DNS servers", Name: name}
	}
	for i := 0; i < len(res.Servers); i++ {
		// Calling Dial here is scary -- we have to be sure
		// not to dial a name that will require a DNS lookup,
		// or Dial will call back here to translate it.
		// The DNS config parser has already checked that
		// all the res.Servers[i] are IP addresses, which
		// Dial will use without a DNS lookup.
		server := res.Servers[i] + ":53"
		c, cerr := net.Dial("udp", "", server)
		if cerr != nil {
			err = cerr
			continue
		}
		msg, err = Exchange(res, c, name, qtype, qclass)
		c.Close()
		if err != nil {
			continue
		}
	}
	return
}

// Do a lookup for a single name, which must be rooted
// (otherwise answer will not find the answers).
func (res *Resolver) TryOneName(name string, qtype uint16) (addrs []RR, err os.Error) {
	if len(res.Servers) == 0 {
		return nil, &DnsError{Error: "no DNS servers", Name: name}
	}
	for i := 0; i < len(res.Servers); i++ {
		// Calling Dial here is scary -- we have to be sure
		// not to dial a name that will require a DNS lookup,
		// or Dial will call back here to translate it.
		// The DNS config parser has already checked that
		// all the res.Servers[i] are IP addresses, which
		// Dial will use without a DNS lookup.
		server := res.Servers[i] + ":53"
		c, cerr := net.Dial("udp", "", server)
		if cerr != nil {
			err = cerr
			continue
		}
		msg, merr := Exchange(res, c, name, qtype, ClassINET)
		c.Close()
		if merr != nil {
			err = merr
			continue
		}
		addrs, err = answer(name, server, msg, qtype)
		if err == nil || err.(*DnsError).Error == noSuchHost {
			break
		}
	}
	return
}

var res *Resolver
var dnserr os.Error

func isDomainName(s string) bool {
	// Requirements on DNS name:
	//	* must not be empty.
	//	* must be alphanumeric plus - and .
	//	* each of the dot-separated elements must begin
	//	  and end with a letter or digit.
	//	  RFC 1035 required the element to begin with a letter,
	//	  but RFC 3696 says this has been relaxed to allow digits too.
	//	  still, there must be a letter somewhere in the entire name.
	if len(s) == 0 {
		return false
	}
	if s[len(s)-1] != '.' { // simplify checking loop: make name end in dot
		s += "."
	}

	last := byte('.')
	ok := false // ok once we've seen a letter
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		default:
			return false
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z':
			ok = true
		case '0' <= c && c <= '9':
			// fine
		case c == '-':
			// byte before dash cannot be dot
			if last == '.' {
				return false
			}
		case c == '.':
			// byte before dot cannot be dot, dash
			if last == '.' || last == '-' {
				return false
			}
		}
		last = c
	}

	return ok
}

func lookup(name string, qtype uint16) (cname string, addrs []RR, err os.Error) {
	if !isDomainName(name) {
		return name, nil, &DnsError{Error: "invalid domain name", Name: name}
	}

	if dnserr != nil || res == nil {
		err = dnserr
		return
	}
	// If name is rooted (trailing dot) or has enough dots,
	// try it by itself first.
	rooted := len(name) > 0 && name[len(name)-1] == '.'
	if rooted || count(name, '.') >= res.Ndots {
		rname := name
		if !rooted {
			rname += "."
		}
		// Can try as ordinary name.
		addrs, err = res.TryOneName(rname, qtype)
		if err == nil {
			cname = rname
			return
		}
	}
	if rooted {
		return
	}

	// Otherwise, try suffixes.
	for i := 0; i < len(res.Search); i++ {
		rname := name + "." + res.Search[i]
		if rname[len(rname)-1] != '.' {
			rname += "."
		}
		addrs, err = res.TryOneName(rname, qtype)
		if err == nil {
			cname = rname
			return
		}
	}

	// Last ditch effort: try unsuffixed.
	rname := name
	if !rooted {
		rname += "."
	}
	addrs, err = res.TryOneName(rname, qtype)
	if err == nil {
		cname = rname
		return
	}
	return
}
