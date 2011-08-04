package main

import (
	"dns"
	"os"
	"flag"
        "log"
	"fmt"
        "time"
	"strconv"
	"strings"
        "runtime"
        "runtime/pprof"
)

func main() {
	dnssec := flag.Bool("dnssec", false, "request DNSSEC records")
	tcp := flag.Bool("tcp", false, "TCP mode")
	nsid := flag.Bool("nsid", false, "ask for NSID")
	queries := flag.Int("queries", 20, "number of concurrent queries to perform")
	maxproc := flag.Int("maxproc", 4, "set GOMAXPROCS to this value")
        looptime := flag.Int("time", 2, "number of seconds to query")
        cpuprofile := flag.String("cpuprofile", "", "write cpu profile to file")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [@server(:port)] [qtype] [qclass] [name ...]\n", os.Args[0])
		flag.PrintDefaults()
	}

        queries_send := int64(0)
        qid := uint16(1)
	qtype := uint16(0)
	qclass := uint16(dns.ClassINET) // Default qclass
        nameserver := "@127.0.0.1:53"
	var qname []string

	flag.Parse()
        if *cpuprofile != "" {
                f, err := os.Create(*cpuprofile)
                if err != nil {
                        log.Fatal(err)
                }
                pprof.StartCPUProfile(f)
                defer pprof.StopCPUProfile()
        }
        runtime.GOMAXPROCS(*maxproc)

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
        start := time.Nanoseconds()
        for i := 0; i < *queries; i++ {
                go func() {
                        println("starting querier")
                        pktbuf := make([]byte, dns.DefaultMsgSize)
                        c := dns.NewClient()
                        if *tcp {
                                c.Net = "tcp"
                        }
                        m := new(dns.Msg)
                        m.Question = make([]dns.Question, 1)
                        m.Question[0] = dns.Question{qname[0], qtype, qclass}
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
                        mbuf, _ := m.Pack()
                        for {
                                // set Id
                                mbuf[0], mbuf[1] = byte(qid >> 8), byte(qid)
                                if ok := c.ExchangeBuffer(mbuf, nameserver, pktbuf); !ok {
                                        println("weird reply", qid)
                                }
                                queries_send++  // global var...???
                                qid++   // let it overflow and wrap
                        }
                }()
        }

        t := time.NewTicker(int64(*looptime) * 1e9)
wait:
        for {
                select {
                case <-t.C:
                        // time is up
                        break wait
                }
        }
        delta := float32(time.Nanoseconds() - start) / 1e9
        fmt.Printf("%d queries in %.4f s (%.4f qps)\n", queries_send, delta, float32(queries_send)/delta)
}
