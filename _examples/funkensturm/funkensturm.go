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

var qr []*Funk
var f *Funkensturm
var verbose *bool

// A small wrapper to keep the address together
// with a client.
type Funk struct {
	Client *dns.Client
	Addr   string
}

// Where does the packet come from? 
// IN: initial packet received by the Responder
// any modifications here will reflect what kind of
// pkt is sent through.
// OUT: pkt as received back from a server. Modifications here will reflect
// how the packet is send back to the original requester.
const (
	IN  = iota // set when receiving a packet
	OUT        // set when sending a packet

	OR  // chain match functions with logical 'or'
	AND // chain match functions with logical 'and'
)

// A Match function is used on a DNS packet and
// returns (a possibly modified) DNS packet. It should
// return true when the packets matches the criteria set in 
// the function.
// Op is used in chaining Match-functions together
type Match struct {
	Op   int // boolean op: OR, AND
	Func func(*dns.Msg, int) (*dns.Msg, bool)
}

// An action is something that is done with a packet. Funkensturm
// does not impose any restriction on what this can be, except that
// is must remain a valid DNS packet.
type Action struct {
	Func func(*dns.Msg, bool) *dns.Msg
}

type ActionRaw struct {
	FuncRaw func(*dns.Msg, bool) []byte
}

// A complete config for Funkensturm. All matches in the Matches slice are
// chained together: incoming dns.Msg -> Match[0] -> dns.Msg -> Match[1] -> dns.Msg -> ...
// The dns.Msg output of Match[n] is the input for Match[n+1]. 
//
// The final outcome (does a packet match or not?) is calculated as follows:
// true Match[0].Op Match[0].Func() Match[1].Op Match[1].Func() ...
// The result of this matching is given to the action function(s). They can then
// decide what to do with a packet in the 'true' and in the 'false' case.
type Funkensturm struct {
	Setup      func() bool // Inital setup (for extra resolvers, or loading keys, or ...)
	Matches    []Match     // Match- and modify functions
	Actions    []Action    // What to do with the packets
	ActionsRaw []ActionRaw // Raw action, return []byte not *dns.Msg
}

func verboseprint(i *dns.Msg, indent string) {
	for _, line := range strings.Split(i.String(), "\n", -1) {
		fmt.Printf("%s%s\n", indent, line)
	}
	fmt.Println()
}

func doFunkensturm(pkt *dns.Msg) ([]byte, os.Error) {
	if *verbose {
		verboseprint(pkt, "> ")
	}
	// No matter what, we refuse to answer requests with the response bit set.
	if pkt.MsgHdr.Response == true {
		return nil, &dns.Error{Error: "Response bit set, not replying"}
	}

	// Loop through the Match* functions and decide what to do
	// Note the packet can be changed by these function, this 
	// change is cumulative.
	ok, ok1 := true, true
	pkt1 := pkt
	for _, m := range f.Matches {
		pkt1, ok1 = m.Func(pkt1, IN)
		switch m.Op {
		case AND:
			ok = ok && ok1
		case OR:
			ok = ok || ok1
		}
	}
	if *verbose { //modified
		verboseprint(pkt1, ">> ")
	}

	// Loop through the Actions.Func* and do something with the
	// packet. Note there can only be one returned packet. 
	// We use 'ok' to signal what the above match did: true or false
	var resultpkt *dns.Msg
	for _, a := range f.Actions {
		resultpkt = a.Func(pkt1, ok)
	}

	if *verbose { //orignal out
		verboseprint(resultpkt, "< ")
	}

	// loop again for matching, but now with OUT, this is done
	// for some last minute packet changing. Note the boolean return
	// code isn't used any more, i.e No more actions are allowed
	// anymore
        if len(f.Matches) > 0 {
                pkt1 = resultpkt
                for _, m := range f.Matches {
                        pkt1, _ = m.Func(pkt1, OUT)
                }
                if pkt1 == nil {
                        // don't need to send something back
                        return nil, nil
                }
        }

        if len(f.ActionsRaw) > 0 {
                var buf []byte
                for _, r := range f.ActionsRaw {
                        buf = r.FuncRaw(pkt, ok)
                }
                if buf != nil {
                        // send the buffer back at once
                        return buf, nil
                }
        }

	if *verbose { // modified out
		verboseprint(pkt1, "<< ")
	}

	out, ok1 := pkt1.Pack()
	if !ok1 {
		return nil, &dns.Error{Error: "Packing packet failed"}
	}
	// Some final byte changing function here? 
	return out, nil
}

func serve(w dns.ResponseWriter, req *dns.Msg) {
	out, err := doFunkensturm(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err.String())
		return
	}
	if out != nil {
		w.Write(out)
	}
}

func listenAndServe(add, net string) {
	err := dns.ListenAndServe(add, net, nil)
	if err != nil {
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
	qr = make([]*Funk, len(clients))
	for i, ra := range clients {
		qr[i] = new(Funk)
		qr[i].Client = dns.NewClient()
		qr[i].Addr = ra
	}

	f = funkensturm()
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
