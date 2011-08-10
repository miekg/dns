package main

import (
	"dns"
	"os"
	"os/signal"
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
        reflect := flag.Bool("reflect", false, "enable reflection")
        tcp := flag.Bool("tcp", false, "use tcp")
        nameserver := flag.String("ns", "127.0.0.1:53", "the nameserver to query")
        cpuprofile := flag.String("cpuprofile", "", "write cpu profile to file")
        qname := flag.String("qname", "miek.nl", "which qname to use")

	flag.Usage = func() {
		flag.PrintDefaults()
	}
        queries_send := int64(0)
        qid := uint16(1)
        qtype := dns.TypeMX
	qclass := uint16(dns.ClassINET) // Default qclass
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
        fmt.Printf("Starting %d query functions. GOMAXPROCS set to %d. *reflection set to %v* [tcp = %v]\n", *queries, *maxproc, *reflect, *tcp)
        fmt.Printf("Querying %s\n", *nameserver)
        for i := 0; i < *queries; i++ {
                go func() {
                        pktbuf := make([]byte, dns.DefaultMsgSize)
                        m := new(dns.Msg)
                        m.Question = make([]dns.Question, 1)
                        m.Question[0] = dns.Question{*qname, qtype, qclass}
                        qbuf, _ := m.Pack()
                        c := dns.NewClient()
                        if *tcp {
                                c.Net = "tcp"
                        }

                        if !*tcp {
                                // For UDP give each goroutine a socket.
                                // With TCP we re-dial every time

                                if err := c.Dial(*nameserver); err != nil {
                                        return
                                }
                                defer c.Close()
                        }

                        r := new(dns.Msg)
                        for {
                                // set Id
                                dns.RawSetId(qbuf, 0, qid)
                                n, err := c.ExchangeBuffer(qbuf, *nameserver, pktbuf)
                                if err != nil {
                                        log.Print(err)
                                        break   // something went wrong
                                }
                                if *reflect {
                                        r.Unpack(pktbuf[:n])
//                                        println(r.String())
                                }
                                queries_send++
                                qid++
                        }
                }()
        }

        t := time.NewTicker(int64(*looptime) * 1e9)
wait:
        for {
                select {
                case <-signal.Incoming:
                        log.Printf("Signal received, stopping")
                        break wait
                case <-t.C:
                        break wait
                }
        }
        delta := float32(time.Nanoseconds() - start) / 1e9
        fmt.Printf("%d queries in %.4f s (%.4f qps)\n", queries_send, delta, float32(queries_send)/delta)
}
