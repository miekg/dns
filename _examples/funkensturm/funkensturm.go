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

const (
	OR  = iota // chain match functions with logical 'or'
	AND        // chain match functions with logical 'and'
)

// A Match function is used on a DNS packet and
// returns (a possibly modified) DNS packet. It should
// return true when the packets matches the criteria set in 
// the function.
// Op is used in chaining Match-functions together
type Match struct {
	Op   int // boolean op: OR, AND
	Func func(*dns.Msg) (*dns.Msg, bool)
}

// A FunkAction combines a set of matches and an action. If
// the matches are successfull (return true) the action is
// performed
type Funk struct {
	Matches []Match
	Action  func(*dns.Msg) []byte
}

func NewFunk(m int) *Funk {
	f := new(Funk)
	f.Matches = make([]Match, m)
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
		ok := true
		for _, m := range f.Matches {
			var ok1 bool
			pkt, ok1 = m.Func(pkt)
			switch m.Op {
			case AND:
				ok = ok && ok1
			case OR:
				ok = ok || ok1
			}
		}
		if ok {
			ret = f.Action(pkt)
			return
		}
	}
        // If still alive, non of the action did something.
        // So we do it ourselves
        var o *dns.Msg
        for _, c := range qr {
                o = c.Client.Exchange(pkt, c.Addr)
        }
        ret, _ = o.Pack()
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
