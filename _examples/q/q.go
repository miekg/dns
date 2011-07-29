package main

import (
	"dns"
	"os"
	"flag"
	"fmt"
	"strconv"
	"strings"
)

func q(w dns.RequestWriter, m *dns.Msg) {
	w.Send(m)
	r, _ := w.Receive()
	w.Write(r)
}

func main() {
	var dnssec *bool = flag.Bool("dnssec", false, "request DNSSEC records")
	var query *bool = flag.Bool("question", false, "show question")
	var short *bool = flag.Bool("short", false, "abbriate long DNSKEY and RRSIG RRs")
	var aa *bool = flag.Bool("aa", false, "set AA flag in query")
	var ad *bool = flag.Bool("ad", false, "set AD flag in query")
	var cd *bool = flag.Bool("cd", false, "set CD flag in query")
	var rd *bool = flag.Bool("rd", true, "unset RD flag in query")
	var tcp *bool = flag.Bool("tcp", false, "TCP mode")
	var nsid *bool = flag.Bool("nsid", false, "ask for NSID")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [@server(:port)] [qtype] [qclass] [name ...]\n", os.Args[0])
		flag.PrintDefaults()
	}

	// Need to think about it... Config
	conf, _ := dns.ClientConfigFromFile("/etc/resolv.conf")
	nameserver := "@" + conf.Servers[0]
	qtype := uint16(0)
	qclass := uint16(dns.ClassINET) // Default qclass
	var qname []string

	flag.Parse()

Flags:
	for i := 0; i < flag.NArg(); i++ {
		// If it starts with @ it is a nameserver
		if flag.Arg(i)[0] == '@' {
			nameserver = flag.Arg(i)
			continue Flags
		}
		// First class, then type, to make ANY queries possible
		// And if it looks like type, it is a type
		for k, v := range dns.Rr_str {
			if v == strings.ToUpper(flag.Arg(i)) {
				qtype = k
				continue Flags
			}
		}
		// If it looks like a class, it is a class
		for k, v := range dns.Class_str {
			if v == strings.ToUpper(flag.Arg(i)) {
				qclass = k
				continue Flags
			}
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

	nameserver = string([]byte(nameserver)[1:]) // chop off @
	if !strings.HasSuffix(nameserver, ":53") {
		nameserver += ":53"
	}
	// ipv6 todo

        // We use the async query handling, just to show how
        // it is to be used.
	dns.HandleQueryFunc(".", q)
	dns.ListenAndQuery(nil, nil)
	c := dns.NewClient()
	if *tcp {
		c.Net = "tcp"
	}

	m := new(dns.Msg)
	m.MsgHdr.Authoritative = *aa
	m.MsgHdr.AuthenticatedData = *ad
	m.MsgHdr.CheckingDisabled = *cd
	m.MsgHdr.RecursionDesired = *rd
	m.Question = make([]dns.Question, 1)
	if *dnssec || *nsid {
                opt := dns.NewRR(dns.TypeOPT).(*dns.RR_OPT)
                opt.Hdr.Rrtype = 0
		opt.SetDo()
		opt.SetVersion(0)
		opt.SetUDPSize(dns.DefaultMsgSize)
		if *nsid {
			opt.SetNsid("")
		}
		m.Extra = make([]dns.RR, 1)
		m.Extra[0] = opt
	}
	for _, v := range qname {
		m.Question[0] = dns.Question{v, qtype, qclass}
		m.Id = dns.Id()
                if *query {
                        fmt.Printf("%s\n", m.String())
                }
		c.Do(m, nameserver)
	}

	i := 0
forever:
	for {
		select {
		case r := <-dns.DefaultReplyChan:
			if r[1] != nil {
				if r[0].Id != r[1].Id {
					fmt.Printf("Id mismatch\n")
				}
				if *short {
					r[1] = shortMsg(r[1])
				}
				fmt.Printf("%v", r[1])
			}
			i++
			if i == len(qname) {
				break forever
			}
		}
	}
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
	case *dns.RR_DNSKEY:
		t.PublicKey = "( ... )"
	case *dns.RR_RRSIG:
		t.Signature = "( ... )"
	case *dns.RR_NSEC3:
		t.Salt = "-" // nobody cares
	}
	return r
}
