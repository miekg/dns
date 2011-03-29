package main

import (
	"dns"
	"os"
	"flag"
	"fmt"
	"strconv"
	"strings"
)

func main() {
	var dnssec *bool = flag.Bool("dnssec", false, "Request DNSSEC records")
	var short *bool = flag.Bool("short", false, "Abbriate long DNSKEY and RRSIG RRs")
	var port *string = flag.String("port", "53", "Set the query port")
	var aa *bool = flag.Bool("aa", false, "Set AA flag in query")
	var ad *bool = flag.Bool("ad", false, "Set AD flag in query")
	var cd *bool = flag.Bool("cd", false, "Set CD flag in query")
	var rd *bool = flag.Bool("rd", true, "Unset RD flag in query")
	var tcp *bool = flag.Bool("tcp", false, "TCP mode")
	var nsid *bool = flag.Bool("nsid", false, "Ask for the NSID")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [@server] [qtype] [qclass] [name ...]\n", os.Args[0])
		flag.PrintDefaults()
	}

        // Need to think about it... Config
        server, _ := dns.FromFile("/etc/resolv.conf")
	nameserver := "@" + server[0]
	qtype := uint16(dns.TypeA)      // Default qtype
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

	nameserver = string([]byte(nameserver)[1:]) // chop off @

        d := new(dns.Conn)
        d.RemoteAddr = nameserver + ":" + *port
        d.Attempts = 1

	m := new(dns.Msg)
	m.MsgHdr.Authoritative = *aa
	m.MsgHdr.AuthenticatedData = *ad
	m.MsgHdr.CheckingDisabled = *cd
	m.MsgHdr.RecursionDesired = *rd
	m.Question = make([]dns.Question, 1)
	if *dnssec || *nsid {
		opt := new(dns.RR_OPT)
		opt.SetDo()
		opt.SetVersion(0)
		opt.SetUDPSize(dns.DefaultMsgSize)
		if *nsid {
			opt.SetNsid("")
		}
		m.Extra = make([]dns.RR, 1)
		m.Extra[0] = opt
	}

        in := make(chan dns.Query)
        var out chan dns.Query
        if *tcp {
                out = dns.QueryAndServeTCP(in, nil)
        } else {
                out = dns.QueryAndServeUDP(in, nil)
        }

	for _, v := range qname {
                m.Question[0] = dns.Question{v, qtype, qclass}
		m.Id = dns.Id()
                in <- dns.Query{Msg: m, Conn: d}

                r := <-out

		if r.Msg != nil {
			if r.Msg.Id != m.Id {
				fmt.Printf("Id mismatch\n")
			}
			if *short {
				r.Msg = shortMsg(r.Msg)
			}
			fmt.Printf("%v", r.Msg)
		} else {
			fmt.Printf("%v\n", r.Err.String())
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
