// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Read system DNS config from /etc/resolv.conf

package resolver

import ( "os"; "net" )

// See resolv.conf(5) on a Linux machine.
// TODO(rsc): Supposed to call uname() and chop the beginning
// of the host name to get the default search domain.
// We assume it's in resolv.conf anyway.
func dnsReadConfig() (*Resolver, os.Error) {
	file, err := open("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}
	conf := new(Resolver)
	conf.Servers = make([]string, 3)[0:0] // small, but the standard limit
	conf.Search = make([]string, 0)
	conf.Ndots = 1
	conf.Timeout = 5
	conf.Attempts = 2
	conf.Rotate = false
	for line, ok := file.readLine(); ok; line, ok = file.readLine() {
		f := getFields(line)
		if len(f) < 1 {
			continue
		}
		switch f[0] {
		case "nameserver": // add one name server
			a := conf.Servers
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
					conf.Servers = a
				}
			}

		case "domain": // set search path to just this domain
			if len(f) > 1 {
				conf.Search = make([]string, 1)
				conf.Search[0] = f[1]
			} else {
				conf.Search = make([]string, 0)
			}

		case "search": // set search path to given servers
			conf.Search = make([]string, len(f)-1)
			for i := 0; i < len(conf.Search); i++ {
				conf.Search[i] = f[i+1]
			}

		case "options": // magic options
			for i := 1; i < len(f); i++ {
				s := f[i]
				switch {
				case len(s) >= 6 && s[0:6] == "ndots:":
					n, _, _ := dtoi(s, 6)
					if n < 1 {
						n = 1
					}
					conf.Ndots = n
				case len(s) >= 8 && s[0:8] == "timeout:":
					n, _, _ := dtoi(s, 8)
					if n < 1 {
						n = 1
					}
					conf.Timeout = n
				case len(s) >= 8 && s[0:9] == "attempts:":
					n, _, _ := dtoi(s, 9)
					if n < 1 {
						n = 1
					}
					conf.Attempts = n
				case s == "rotate":
					conf.Rotate = true
				}
			}
		}
	}
	file.close()
	return conf, nil
}
