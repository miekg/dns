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
