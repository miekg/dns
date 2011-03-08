// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Read system DNS config from /etc/resolv.conf

package dns

import (
	"os"
	"bufio"
	"strconv"
	"strings"
	"net"
)

// See resolv.conf(5) on a Linux machine.
// Set the resolver configuration from a /etc/resolv.conf like file.
func (r *Resolver) FromFile(conf string) os.Error {
	file, err := os.Open(conf, os.O_RDONLY, 0)
	defer file.Close()
	if err != nil {
		return err
	}
	b := bufio.NewReader(file)
	r.Servers = make([]string, 3)[0:0] // small, but the standard limit
	r.Search = make([]string, 0)
	r.Ndots = 1
	r.Timeout = 5
	r.Attempts = 2
	for line, ok := b.ReadString('\n'); ok == nil; line, ok = b.ReadString('\n') {
		f := strings.Fields(line)
		if len(f) < 1 {
			continue
		}
		switch f[0] {
		case "nameserver": // add one name server
			a := r.Servers
			n := len(a)
			if len(f) > 1 && n < cap(a) {
				// One more check: make sure server name is
				// just an IP address.  Otherwise we need DNS
				// to look it up.
				name := f[1]
				switch len(net.ParseIP(name)) {
				case 16:
					name = "[" + name + "]"
					fallthrough
				case 4:
					a = a[0 : n+1]
					a[n] = name
					r.Servers = a
				}
			}

		case "domain": // set search path to just this domain
			if len(f) > 1 {
				r.Search = make([]string, 1)
				r.Search[0] = f[1]
			} else {
				r.Search = make([]string, 0)
			}

		case "search": // set search path to given servers
			r.Search = make([]string, len(f)-1)
			for i := 0; i < len(r.Search); i++ {
				r.Search[i] = f[i+1]
			}

		case "options": // magic options
			for i := 1; i < len(f); i++ {
				s := f[i]
				switch {
				case len(s) >= 6 && s[:6] == "ndots:":
					n, _ := strconv.Atoi(s[6:])
					if n < 1 {
						n = 1
					}
					r.Ndots = n
				case len(s) >= 8 && s[:8] == "timeout:":
					n, _ := strconv.Atoi(s[8:])
					if n < 1 {
						n = 1
					}
					r.Timeout = n
				case len(s) >= 8 && s[:9] == "attempts:":
					n, _ := strconv.Atoi(s[9:])
					if n < 1 {
						n = 1
					}
					r.Attempts = n
				case s == "rotate":
                                        /* not imp */
				}
			}
		}
	}
	return nil
}
