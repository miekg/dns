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
	var aa *bool = flag.Bool("aa", false, "Set AA flag in query")
	var ad *bool = flag.Bool("ad", false, "Set AD flag in query")
	var cd *bool = flag.Bool("cd", false, "Set CD flag in query")
	var rd *bool = flag.Bool("rd", true, "Unset RD flag in query")
	var tcp *bool = flag.Bool("tcp", false, "TCP mode")
	var nsid *bool = flag.Bool("nsid", false, "Ask for the NSID")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [@server(:port)] [qtype] [qclass] [name ...]\n", os.Args[0])
		flag.PrintDefaults()
	}

	// Need to think about it... Config
	c, _ := dns.ClientConfigFromFile("/etc/resolv.conf")
	nameserver := "@" + c.Servers[0]
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
	if !strings.HasSuffix(nameserver, ":53") {
		nameserver += ":53"
	}

	err := make(chan os.Error)
	if *tcp {
		go query("tcp", err)
	} else {
		go query("udp", err)
	}

	dns.InitQueryChannels()
	// Start the querier in a closure
	go func() {
		for _, v := range qname {
                        d, m := newConnMsg(v, nameserver, c.Attempts, qtype, qclass, *aa, *ad, *cd, *rd, *dnssec, *nsid)
			dns.QueryRequest <- &dns.Query{Query: m, Conn: d}
		}
	}()

	i := 0
forever:
	for {
		select {
		case r := <-dns.QueryReply:
			if r.Reply != nil {
				if r.Query.Id != r.Reply.Id {
					fmt.Printf("Id mismatch\n")
				}
				if *short {
					r.Reply = shortMsg(r.Reply)
				}
				fmt.Printf("%v", r.Reply)
			} else {
				fmt.Printf("%v\n", r.Err.String())
			}
			i++
			if i == len(qname) {
				break forever
			}
		case e := <-err:
			fmt.Printf("%v", e.String())
			break forever
		}
	}
}

func query(tcp string, e chan os.Error) {
	switch tcp {
	case "tcp":
		err := dns.QueryAndServeTCP(qhandle)
		e <- err
	case "udp":
		err := dns.QueryAndServeUDP(qhandle)
		e <- err
	}
}

// reply checking 'n stuff
func qhandle(d *dns.Conn, i *dns.Msg) {
	o, err := d.ExchangeMsg(i, false)
	dns.QueryReply <- &dns.Query{Query: i, Reply: o, Conn: d, Err: err}
        d.Close()
}

func newConnMsg(qname, nameserver string, attempts int, qtype, qclass uint16, aa, ad, cd, rd, dnssec, nsid bool) (*dns.Conn, *dns.Msg) {
	d := new(dns.Conn)
	d.RemoteAddr = nameserver
	d.Attempts = attempts

	m := new(dns.Msg)
	m.MsgHdr.Authoritative = aa
	m.MsgHdr.AuthenticatedData = ad
	m.MsgHdr.CheckingDisabled = cd
	m.MsgHdr.RecursionDesired = rd
	m.Question = make([]dns.Question, 1)
	if dnssec || nsid {
		opt := new(dns.RR_OPT)
		opt.SetDo()
		opt.SetVersion(0)
		opt.SetUDPSize(dns.DefaultMsgSize)
		if nsid {
			opt.SetNsid("")
		}
		m.Extra = make([]dns.RR, 1)
		m.Extra[0] = opt
	}
	m.Question[0] = dns.Question{qname, qtype, qclass}
	m.Id = dns.Id()
        return d, m
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
