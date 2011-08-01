/* 
 * Funkensturm, a versatile DNS proxy
 * Miek Gieben <miek@miek.nl> (c) 2011
 * GPLv2
 */

package main

import (
	"os"
	"log"
	"flag"
	"dns"
	"os/signal"
	"strings"
	"runtime/pprof"
)

var qr []*FunkClient
var f *FunkenSturm
var verbose *bool

// A small wrapper to keep the address together
// with a client.
type FunkClient struct {
	Client *dns.Client
	Addr   string
}

// A FunkAction combines a set of matches and an action. If
// the matches are successfull (return true) the action is
// performed
type Funk struct {
	Match  func(*dns.Msg) (*dns.Msg, bool)
	Action func(*dns.Msg) []byte
}

// Hold the information.
type FunkenSturm struct {
	Setup   func() bool           // Inital setup (for extra resolvers, or loading keys, or ...)
	Default func(*dns.Msg) []byte // Default action is all fails
	Funk    []*Funk               // The configuration
}

func doFunkenSturm(pkt *dns.Msg) (ret []byte) {
	// No matter what, we refuse to answer requests with the response bit set.
	if pkt.MsgHdr.Response == true {
		return nil
	}

	// Loop through the Funks and decide what to do with the packet.
	for _, f := range f.Funk {
		if m, ok := f.Match(pkt); ok {
			ret = f.Action(m)
			return
		}
	}
        if f.Default == nil {
                println("No f.Default set!")
                return
        }
	ret = f.Default(pkt)
	return
}

func serve(w dns.ResponseWriter, req *dns.Msg) {
	if out := doFunkenSturm(req); out != nil {
		w.Write(out)
	}
}

func listenAndServe(add, net string) {
	if err := dns.ListenAndServe(add, net, nil); err != nil {
		println("Failed to setup:", net, add)
	}
}

func main() {
	sserver := flag.String("sserver", "127.0.0.1:8053", "set the listener address")
	rserver := flag.String("rserver", "127.0.0.1:53", "remote server address(es), seperate with commas")
	cpuprofile := flag.String("cpuprofile", "", "write cpu profile to file")
	verbose = flag.Bool("verbose", false, "Print packet as it flows through")
	flag.Usage = func() {
		flag.PrintDefaults()
	}
	flag.Parse()
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	clients := strings.Split(*rserver, ",", -1)
	qr = make([]*FunkClient, len(clients))
	for i, ra := range clients {
		qr[i] = new(FunkClient)
		qr[i].Client = dns.NewClient()
		qr[i].Addr = ra
	}

	f = NewFunkenSturm()
	ok := f.Setup()
	if !ok {
		println("Setup failed")
		return
	}

	dns.HandleFunc(".", serve)
	go listenAndServe(*sserver, "tcp")
	go listenAndServe(*sserver, "udp")

forever:
	for {
		select {
		case <-signal.Incoming:
			println("Signal received, stopping")
			break forever
		}
	}
}
