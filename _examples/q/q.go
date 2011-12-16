package main

import (
	"dns"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func q(w dns.RequestWriter, m *dns.Msg) {
	w.Send(m)
	r, err := w.Receive()
	if err != nil {
		fmt.Printf("%s\n", err.String())
	}
	w.Write(r)
}

func main() {
	dnssec := flag.Bool("dnssec", false, "request DNSSEC records")
	query := flag.Bool("question", false, "show question")
	short := flag.Bool("short", false, "abbreviate long DNSKEY and RRSIG RRs")
	aa := flag.Bool("aa", false, "set AA flag in query")
	ad := flag.Bool("ad", false, "set AD flag in query")
	cd := flag.Bool("cd", false, "set CD flag in query")
	rd := flag.Bool("rd", true, "unset RD flag in query")
	tcp := flag.Bool("tcp", false, "TCP mode")
	nsid := flag.Bool("nsid", false, "ask for NSID")
	fp := flag.Bool("fingerprint", false, "enable server detection")
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
		o := new(dns.RR_OPT)
		o.Hdr.Name = "."
		o.Hdr.Rrtype = dns.TypeOPT
		if *dnssec {
			o.SetDo()
			o.SetUDPSize(dns.DefaultMsgSize)
		}
		if *nsid {
			o.SetNsid("")
		}
		m.Extra = append(m.Extra, o)
		//m.SetEdns0(dns.DefaultMsgSize, true)
	}

	if *fp {
		startParse(nameserver)
		return
	}
	for _, v := range qname {
		m.Question[0] = dns.Question{v, qtype, qclass}
		m.Id = dns.Id()
		if *query {
			fmt.Printf("%s\n", msgToFingerprint(m))
			fmt.Printf("%s\n", m.String())
		}
		c.Do(m, nameserver)
	}

	i := 0
forever:
	for {
		select {
		case r := <-dns.DefaultReplyChan:
			if r.Reply != nil {
				if r.Reply.Rcode == dns.RcodeSuccess {
					if r.Request.Id != r.Reply.Id {
						fmt.Printf("Id mismatch\n")
					}
				}
				if *short {
					r.Reply = shortMsg(r.Reply)
				}
				if *fp {
					fmt.Printf("%s\n", msgToFingerprint(r.Reply))
				}
				fmt.Printf("%v", r.Reply)
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
	case *dns.RR_NSEC3:
		t.Salt = "-" // nobody cares
	case *dns.RR_DS:
		t.Digest = "..."
	case *dns.RR_DNSKEY:
		t.PublicKey = "..."
	case *dns.RR_RRSIG:
		t.Signature = "..."
		t.Inception = 0 // For easy grepping
		t.Expiration = 0
	case *dns.RR_NSEC3:
		if len(t.TypeBitMap) > 5 {
			t.TypeBitMap = t.TypeBitMap[1:5]
		}
	}
	return r
}
