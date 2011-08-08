package main

import (
	"dns"
	"os"
	"flag"
        "log"
	"fmt"
        "time"
        "runtime"
        "runtime/pprof"
)

func main() {
	queries := flag.Int("queries", 20, "number of concurrent queries to perform")
	maxproc := flag.Int("maxproc", 4, "set GOMAXPROCS to this value")
        looptime := flag.Int("time", 2, "number of seconds to query")
        nameserver := flag.String("ns", "127.0.0.1:53", "the nameserver to query")
        cpuprofile := flag.String("cpuprofile", "", "write cpu profile to file")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [qtype] [qclass] [name]", os.Args[0])
		flag.PrintDefaults()
	}

        queries_send := int64(0)
        qid := uint16(1)
        qtype := uint16(dns.TypeMX)
	qclass := uint16(dns.ClassINET) // Default qclass
	qname := "miek.nl"
//	nameserver := "127.0.0.1:53"
//        nameserver = "193.0.14.129:53" // k.root-server.net
//        nameserver = "213.154.224.1:53"    // open.nlnetlabs.nl
//        nameserver = "193.110.157.135:53"     // xelerance.com
//        nameserver = "195.169.221.157:53"       // Jelte, bind10-devel

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
        start := time.Nanoseconds()
        fmt.Printf("Starting %d query functions. GOMAXPROCS set to %d\n", *queries, *maxproc)
        fmt.Printf("Querying %s\n", *nameserver)
        for i := 0; i < *queries; i++ {
                go func() {
                        pktbuf := make([]byte, dns.DefaultMsgSize)
                        m := new(dns.Msg)
                        m.Question = make([]dns.Question, 1)
                        m.Question[0] = dns.Question{qname, qtype, qclass}
                        qbuf, _ := m.Pack()
                        c := dns.NewClient()
                        if err := c.Dial(*nameserver); err != nil {
                                return
                        }
                        defer c.Close()
                        r := new(dns.Msg)
                        for {
                                // set Id
                                dns.RawSetId(qbuf, 0, qid)
                                n, err := c.ExchangeBuffer(qbuf, *nameserver, pktbuf)
                                if err != nil {
                                        log.Print(err)
                                        continue
                                }
                                r.Unpack(pktbuf[:n])
                                //println(r.MsgHdr.String())
                                n=n
                                r=r
                                queries_send++
                                qid++
                                //break           // stop after 1 query
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
