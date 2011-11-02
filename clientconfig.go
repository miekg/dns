// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Read system DNS config from /etc/resolv.conf
// Extend this further, but need to thinks about Conn

package dns

import (
	"os"
	"bufio"
	"strconv"
	"strings"
	"net"
)

// Wraps the contents of the /etc/resolv.conf.
type ClientConfig struct {
	Servers  []string // servers to use
	Search   []string // suffixes to append to local name
	Port     string   // what port to use
	Ndots    int      // number of dots in name to trigger absolute lookup
	Timeout  int      // seconds before giving up on packet
	Attempts int      // lost packets before giving up on server
}

// See resolv.conf(5) on a Linux machine.
// Parse a /etc/resolv.conf like file and return a filled out ClientConfig. Note
// that all nameservers will have the default port number appended (:53)
func ClientConfigFromFile(conf string) (*ClientConfig, error) {
	file, err := os.Open(conf)
	defer file.Close()
	if err != nil {
		return nil, err
	}
	c := new(ClientConfig)
	b := bufio.NewReader(file)
	c.Servers = make([]string, 3)[0:0] // small, but the standard limit
	c.Search = make([]string, 0)
	c.Port = "53"
	c.Ndots = 1
	c.Timeout = 5
	c.Attempts = 2
	for line, ok := b.ReadString('\n'); ok == nil; line, ok = b.ReadString('\n') {
		f := strings.Fields(line)
		if len(f) < 1 {
			continue
		}
		switch f[0] {
		case "nameserver": // add one name server
			a := c.Servers
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
					a[n] = name + ":53"
					c.Servers = a
				}
			}

		case "domain": // set search path to just this domain
			if len(f) > 1 {
				c.Search = make([]string, 1)
				c.Search[0] = f[1]
			} else {
				c.Search = make([]string, 0)
			}

		case "search": // set search path to given servers
			c.Search = make([]string, len(f)-1)
			for i := 0; i < len(c.Search); i++ {
				c.Search[i] = f[i+1]
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
					c.Ndots = n
				case len(s) >= 8 && s[:8] == "timeout:":
					n, _ := strconv.Atoi(s[8:])
					if n < 1 {
						n = 1
					}
					c.Timeout = n
				case len(s) >= 8 && s[:9] == "attempts:":
					n, _ := strconv.Atoi(s[9:])
					if n < 1 {
						n = 1
					}
					c.Attempts = n
				case s == "rotate":
					/* not imp */
				}
			}
		}
	}
	return c, nil
}
