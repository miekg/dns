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
