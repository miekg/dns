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
	"fmt"
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
	Match func(*dns.Msg) (*dns.Msg, bool)
	Action  func(*dns.Msg) []byte
}

func NewFunk() *Funk {
	f := new(Funk)
	return f
}

// A complete config for Funkensturm. All matches in the Matches slice are
// chained together: incoming dns.Msg -> Match[0] -> dns.Msg -> Match[1] -> dns.Msg -> ...
// The dns.Msg output of Match[n] is the input for Match[n+1]. 
//
// The final outcome (does a packet match or not?) is calculated as follows:
// true Match[0].Op Match[0].Func() Match[1].Op Match[1].Func() ...
// The result of this matching is given to the action function. That last
// function decides "what to do with the packet" is the match(es) return 'true'
// There is no NewFunkenSturm() because that is what needs to be done in the
// configuration file.
type FunkenSturm struct {
	Setup func() bool // Inital setup (for extra resolvers, or loading keys, or ...)
        Default func(*dns.Msg) []byte    // Default action is all fails
	Funk  []*Funk     // The configuration
}

func doFunkenSturm(pkt *dns.Msg) (ret []byte) {
	// No matter what, we refuse to answer requests with the response bit set.
	if pkt.MsgHdr.Response == true {
		return nil
	}

	// Loop through the Funks and decide what to do with
	// the packet.
	for _, f := range f.Funk {
                if m, ok := f.Match(pkt); ok {
			ret = f.Action(m)
			return
		}
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
		fmt.Printf("Failed to setup: " + net + " " + add + "\n")
	}
}

func main() {
	sserver := flag.String("sserver", "127.0.0.1:8053", "set the listener address")
	rserver := flag.String("rserver", "127.0.0.1:53", "remote server address(es), seperate with commas")
	cpuprofile := flag.String("cpuprofile", "", "write cpu profile to file")
	verbose = flag.Bool("verbose", false, "Print packet as it flows through")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s\n", os.Args[0])
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
		fmt.Fprintf(os.Stderr, "Setup failed")
		return
	}

	dns.HandleFunc(".", serve)
	go listenAndServe(*sserver, "tcp")
	go listenAndServe(*sserver, "udp")

forever:
	for {
		select {
		case <-signal.Incoming:
			fmt.Printf("Signal received, stopping\n")
			break forever
		}
	}
}
