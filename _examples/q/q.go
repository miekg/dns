package main

import (
	"net"
	"dns"
	"os"
	"flag"
	"fmt"
	"strconv"
	"strings"
)

func main() {
	var dnssec *bool = flag.Bool("dnssec", false, "Request DNSSEC records")
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

	nameserver := "@127.0.0.1"      // Default nameserver
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
	r := new(dns.Resolver)
	r.FromFile("/etc/resolv.conf")
	r.Timeout = 2
	r.Port = *port
	r.Tcp = *tcp
	r.Attempts = 1
	// @server may be a name, resolv that 
	var err os.Error
	nameserver = string([]byte(nameserver)[1:]) // chop off @
	_, addr, err := net.LookupHost(nameserver)
	if err == nil {
		r.Servers = addr
	} else {
		r.Servers = []string{nameserver}
	}

	m := new(dns.Msg)
	m.MsgHdr.Authoritative = *aa
	m.MsgHdr.AuthenticatedData = *ad
	m.MsgHdr.CheckingDisabled = *cd
	m.MsgHdr.RecursionDesired = *rd
	m.Question = make([]dns.Question, 1)
	if *dnssec || *nsid {
		opt := new(dns.RR_OPT)
		opt.Hdr = dns.RR_Header{Name: "", Rrtype: dns.TypeOPT}
		opt.SetVersion(0)
		opt.SetDo()
		opt.SetUDPSize(dns.DefaultMsgSize)
		if *nsid {
			opt.SetNsid("")
		}
                if *tcp {
                        opt.SetUDPSize(dns.MaxMsgSize-1)
                }
		m.Extra = make([]dns.RR, 1)
		m.Extra[0] = opt
	}

	for _, v := range qname {
		m.Question[0] = dns.Question{v, qtype, qclass}
		m.SetId()
		in, err := r.Query(m)
		if in != nil {
			if m.Id != in.Id {
				fmt.Printf("Id mismatch\n")
			}
			fmt.Printf("%v\n", in)
		} else {
			fmt.Printf("%v\n", err.String())
		}
	}
}
/*
41 func (m *Meta) String() string {
42         s := ";; Query time: " + strconv.Itoa(int(m.QueryEnd-m.QueryStart)) + " nsec"
43         s += "\n;; MSG SIZE  rcvd: " + strconv.Itoa(m.RLen) + ", sent: " + strconv.Itoa(m.QLen)
44         rf := float32(m.RLen)
45         qf := float32(m.QLen)
46         if qf != 0 {
47                 s += " (" + strconv.Ftoa32(rf/qf, 'f', 2) + ":1)"
48         }
49         // WHEN??
50         return s
51 }
*/
