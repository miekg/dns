// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Q is a small utility which acts and behaves like 'dig' from BIND.
// It is meant to stay lean and mean, while having a bunch of handy
// features, like -check which checks if a packet is correctly signed (without
// checking the chain of trust).
package main

import (
	"flag"
	"fmt"
	"github.com/miekg/dns"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// TODO: serial in ixfr

var (
	dnskey *dns.DNSKEY
	short  *bool
)

func main() {
	short = flag.Bool("short", false, "abbreviate long DNSSEC records")
	dnssec := flag.Bool("dnssec", false, "request DNSSEC records")
	query := flag.Bool("question", false, "show question")
	check := flag.Bool("check", false, "check internal DNSSEC consistency")
	raw := flag.Bool("raw", false, "do not strip 'http://' from the qname")
	six := flag.Bool("6", false, "use IPv6 only")
	four := flag.Bool("4", false, "use IPv4 only")
	anchor := flag.String("anchor", "", "use the DNSKEY in this file for interal DNSSEC consistency")
	tsig := flag.String("tsig", "", "request tsig with key: [hmac:]name:key")
	port := flag.Int("port", 53, "port number to use")
	aa := flag.Bool("aa", false, "set AA flag in query")
	ad := flag.Bool("ad", false, "set AD flag in query")
	cd := flag.Bool("cd", false, "set CD flag in query")
	rd := flag.Bool("rd", true, "set RD flag in query")
	fallback := flag.Bool("fallback", false, "fallback to 4096 bytes bufsize and after that TCP")
	tcp := flag.Bool("tcp", false, "TCP mode")
	nsid := flag.Bool("nsid", false, "set edns nsid option")
	client := flag.String("client", "", "set edns client-subnet option")
	//serial := flag.Int("serial", 0, "perform an IXFR with this serial")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] [@server] [qtype] [qclass] [name ...]\n", os.Args[0])
		flag.PrintDefaults()
	}

	qtype := uint16(0)
	qclass := uint16(dns.ClassINET)
	var qname []string

	flag.Parse()
	if *anchor != "" {
		f, err := os.Open(*anchor)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failure to open %s: %s\n", *anchor, err.Error())
		}
		r, err := dns.ReadRR(f, *anchor)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failure to read an RR from %s: %s\n", *anchor, err.Error())
		}
		if k, ok := r.(*dns.DNSKEY); !ok {
			fmt.Fprintf(os.Stderr, "No DNSKEY read from %s\n", *anchor)
		} else {
			dnskey = k
		}
	}

	var nameserver string

Flags:
	for i := 0; i < flag.NArg(); i++ {
		// If it starts with @ it is a nameserver
		if flag.Arg(i)[0] == '@' {
			nameserver = flag.Arg(i)
			continue Flags
		}
		// First class, then type, to make ANY queries possible
		// And if it looks like type, it is a type
		if k, ok := dns.StringToType[strings.ToUpper(flag.Arg(i))]; ok {
			qtype = k
			continue Flags
		}
		// If it looks like a class, it is a class
		if k, ok := dns.StringToClass[strings.ToUpper(flag.Arg(i))]; ok {
			qclass = k
			continue Flags
		}
		// If it starts with TYPExxx it is unknown rr
		if strings.HasPrefix(flag.Arg(i), "TYPE") {
			i, e := strconv.Atoi(string([]byte(flag.Arg(i))[4:]))
			if e == nil {
				qtype = uint16(i)
				continue Flags
			}
		}

		// Anything else is a qname
		qname = append(qname, flag.Arg(i))
	}
	if len(qname) == 0 {
		qname = make([]string, 1)
		qname[0] = "."
		qtype = dns.TypeNS
	}
	if qtype == 0 {
		qtype = dns.TypeA
	}

	if len(nameserver) == 0 {
		conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		nameserver = "@" + conf.Servers[0]
	}

	nameserver = string([]byte(nameserver)[1:]) // chop off @
	// if the nameserver is from /etc/resolv.conf the [ and ] are already
	// added, thereby breaking net.ParseIP. Check for this and don't
	// fully qualify such a name
	if nameserver[0] == '[' && nameserver[len(nameserver)-1] == ']' {
		nameserver = nameserver[1 : len(nameserver)-1]
	}
	if i := net.ParseIP(nameserver); i != nil {
		nameserver = net.JoinHostPort(nameserver, strconv.Itoa(*port))
	} else {
		nameserver = dns.Fqdn(nameserver) + ":" + strconv.Itoa(*port)
	}
	c := new(dns.Client)
	if *tcp {
		c.Net = "tcp"
		if *four {
			c.Net = "tcp4"
		}
		if *six {
			c.Net = "tcp6"
		}
	} else {
		c.Net = "udp"
		if *four {
			c.Net = "udp4"
		}
		if *six {
			c.Net = "udp6"
		}
	}

	m := new(dns.Msg)
	m.MsgHdr.Authoritative = *aa
	m.MsgHdr.AuthenticatedData = *ad
	m.MsgHdr.CheckingDisabled = *cd
	m.MsgHdr.RecursionDesired = *rd
	m.Question = make([]dns.Question, 1)

	if *dnssec || *nsid || *client != "" {
		o := new(dns.OPT)
		o.Hdr.Name = "."
		o.Hdr.Rrtype = dns.TypeOPT
		if *dnssec {
			o.SetDo()
			o.SetUDPSize(dns.DefaultMsgSize)
		}
		if *nsid {
			e := new(dns.EDNS0_NSID)
			e.Code = dns.EDNS0NSID
			o.Option = append(o.Option, e)
			// NSD will not return nsid when the udp message size is too small
			o.SetUDPSize(dns.DefaultMsgSize)
		}
		if *client != "" {
			e := new(dns.EDNS0_SUBNET)
			e.Code = dns.EDNS0SUBNET
			e.SourceScope = 0
			e.Address = net.ParseIP(*client)
			if e.Address == nil {
				fmt.Fprintf(os.Stderr, "Failure to parse IP address: %s\n", *client)
				return
			}
			e.Family = 1 // IP4
			e.SourceNetmask = net.IPv4len * 8
			if e.Address.To4() == nil {
				e.Family = 2 // IP6
				e.SourceNetmask = net.IPv6len * 8
			}
			o.Option = append(o.Option, e)
		}
		m.Extra = append(m.Extra, o)
	}

	for _, v := range qname {
		if !*raw && strings.HasPrefix(v, "http://") {
			v = v[7:]
			if v[len(v)-1] == '/' {
				v = v[:len(v)-1]
			}
		}

		m.Question[0] = dns.Question{dns.Fqdn(v), qtype, qclass}
		m.Id = dns.Id()
		// Add tsig
		if *tsig != "" {
			if algo, name, secret, ok := tsigKeyParse(*tsig); ok {
				m.SetTsig(name, algo, 300, time.Now().Unix())
				c.TsigSecret = map[string]string{name: secret}
			} else {
				fmt.Fprintf(os.Stderr, "TSIG key data error\n")
				return
			}
		}
		if *query {
			fmt.Printf("%s", m.String())
			fmt.Printf("\n;; size: %d bytes\n\n", m.Len())
		}
		if qtype == dns.TypeAXFR {
			c.Net = "tcp"
			doXfr(c, m, nameserver)
			continue
		}
		if qtype == dns.TypeIXFR {
			doXfr(c, m, nameserver)
			continue
		}
		r, rtt, e := c.Exchange(m, nameserver)
	Redo:
		if e != nil {
			fmt.Printf(";; %s\n", e.Error())
			continue
		}
		if r.Id != m.Id {
			fmt.Fprintf(os.Stderr, "Id mismatch\n")
			return
		}
		if r.MsgHdr.Truncated && *fallback {
			if c.Net != "tcp" {
				if !*dnssec {
					fmt.Printf(";; Truncated, trying %d bytes bufsize\n", dns.DefaultMsgSize)
					o := new(dns.OPT)
					o.Hdr.Name = "."
					o.Hdr.Rrtype = dns.TypeOPT
					o.SetUDPSize(dns.DefaultMsgSize)
					m.Extra = append(m.Extra, o)
					r, rtt, e = c.Exchange(m, nameserver)
					*dnssec = true
					goto Redo
				} else {
					// First EDNS, then TCP
					fmt.Printf(";; Truncated, trying TCP\n")
					c.Net = "tcp"
					r, rtt, e = c.Exchange(m, nameserver)
					goto Redo
				}
			}
		}
		if r.MsgHdr.Truncated && !*fallback {
			fmt.Printf(";; Truncated\n")
		}
		if *check {
			sigCheck(r, nameserver, *tcp)
		}
		if *short {
			r = shortMsg(r)
		}

		fmt.Printf("%v", r)
		fmt.Printf("\n;; query time: %.3d µs, server: %s(%s), size: %d bytes\n", rtt/1e3, nameserver, c.Net, r.Len())
	}
}

func tsigKeyParse(s string) (algo, name, secret string, ok bool) {
	s1 := strings.SplitN(s, ":", 3)
	switch len(s1) {
	case 2:
		return "hmac-md5.sig-alg.reg.int.", s1[0], s1[1], true
	case 3:
		switch s1[0] {
		case "hmac-md5":
			return "hmac-md5.sig-alg.reg.int.", s1[1], s1[2], true
		case "hmac-sha1":
			return "hmac-sha1.", s1[1], s1[2], true
		case "hmac-sha256":
			return "hmac-sha256.", s1[1], s1[2], true
		}
	}
	return
}

func sectionCheck(set []dns.RR, server string, tcp bool) {
	var key *dns.DNSKEY
	for _, rr := range set {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			rrset := getRRset(set, rr.Header().Name, rr.(*dns.RRSIG).TypeCovered)
			if dnskey == nil {
				key = getKey(rr.(*dns.RRSIG).SignerName, rr.(*dns.RRSIG).KeyTag, server, tcp)
			} else {
				key = dnskey
			}
			if key == nil {
				fmt.Printf(";? DNSKEY %s/%d not found\n", rr.(*dns.RRSIG).SignerName, rr.(*dns.RRSIG).KeyTag)
				continue
			}
			where := "net"
			if dnskey != nil {
				where = "disk"
			}
			if err := rr.(*dns.RRSIG).Verify(key, rrset); err != nil {
				fmt.Printf(";- Bogus signature, %s does not validate (DNSKEY %s/%d/%s) [%s]\n",
					shortSig(rr.(*dns.RRSIG)), key.Header().Name, key.KeyTag(), where, err.Error())
			} else {
				fmt.Printf(";+ Secure signature, %s validates (DNSKEY %s/%d/%s)\n", shortSig(rr.(*dns.RRSIG)), key.Header().Name, key.KeyTag(), where)
			}
		}
	}
}

// Check the sigs in the msg, get the signer's key (additional query), get the 
// rrset from the message, check the signature(s)
func sigCheck(in *dns.Msg, server string, tcp bool) {
	sectionCheck(in.Answer, server, tcp)
	sectionCheck(in.Ns, server, tcp)
	sectionCheck(in.Extra, server, tcp)
}

// Return the RRset belonging to the signature with name and type t
func getRRset(l []dns.RR, name string, t uint16) []dns.RR {
	l1 := make([]dns.RR, 0)
	for _, rr := range l {
		if strings.ToLower(rr.Header().Name) == strings.ToLower(name) && rr.Header().Rrtype == t {
			l1 = append(l1, rr)
		}
	}
	return l1
}

// Get the key from the DNS (uses the local resolver) and return them.
// If nothing is found we return nil
func getKey(name string, keytag uint16, server string, tcp bool) *dns.DNSKEY {
	c := new(dns.Client)
	if tcp {
		c.Net = "tcp"
	}
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeDNSKEY)
	m.SetEdns0(4096, true)
	r, _, err := c.Exchange(m, server)
	if err != nil {
		return nil
	}
	for _, k := range r.Answer {
		if k1, ok := k.(*dns.DNSKEY); ok {
			if k1.KeyTag() == keytag {
				return k1
			}
		}
	}
	return nil
}

// shorten RRSIG to "miek.nl RRSIG(NS)"
func shortSig(sig *dns.RRSIG) string {
	return sig.Header().Name + " RRSIG(" + dns.TypeToString[sig.TypeCovered] + ")"
}

// Walk trough message and short Key data and Sig data
func shortMsg(in *dns.Msg) *dns.Msg {
	for i := 0; i < len(in.Answer); i++ {
		in.Answer[i] = shortRR(in.Answer[i])
	}
	for i := 0; i < len(in.Ns); i++ {
		in.Ns[i] = shortRR(in.Ns[i])
	}
	for i := 0; i < len(in.Extra); i++ {
		in.Extra[i] = shortRR(in.Extra[i])
	}
	return in
}

func shortRR(r dns.RR) dns.RR {
	switch t := r.(type) {
	case *dns.DS:
		t.Digest = "..."
	case *dns.DNSKEY:
		t.PublicKey = "..."
	case *dns.RRSIG:
		t.Signature = "..."
	case *dns.NSEC3:
		t.Salt = "." // Nobody cares
		if len(t.TypeBitMap) > 5 {
			t.TypeBitMap = t.TypeBitMap[1:5]
		}
	}
	return r
}

func doXfr(c *dns.Client, m *dns.Msg, nameserver string) {
	if t, e := c.TransferIn(m, nameserver); e == nil {
		for r := range t {
			if r.Error == nil {
				for _, rr := range r.RR {
					if *short {
						rr = shortRR(rr)
					}
					fmt.Printf("%v\n", rr)
				}
			} else {
				fmt.Fprintf(os.Stderr, "Failure to read XFR: %s\n", r.Error.Error())
			}
		}
	} else {
		fmt.Fprintf(os.Stderr, "Failure to read XFR: %s\n", e.Error())
	}
}
