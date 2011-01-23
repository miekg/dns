/* 
 * Funkensturm
 * Miek Gieben <miek@miek.nl> (c) 2011
 * GPLv2
 */

package main

import (
	"os"
	"flag"
	"net"
	"log"
	"dns"
	"dns/resolver"
	"dns/responder"
	"os/signal"
)

// Setup a responder takes takes care of the incoming queries.
type server responder.Server

// Setup a initial resolver for sending the queries somewhere else.
var qr chan resolver.Msg

// The configuration of Funkensturm
var f *Funkensturm

// Where does the packet come from? 
// IN: initial packet received by the Responder
// any modifications here will reflect what kind of
// pkt is sent through. Normally there is no modification here.
// OUT: pkt as received back from a server. Modifications here will reflect
// how the packet is send back to the original requester.
const (
	IN  = iota // set when receiving a packet
	OUT        // set when sending a packet

	OR  // chain match functions with logical or
	AND // chain match functions with logical and
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

// A complete config for Funkensturm. All matches in the Matches slice are
// chained together: incoming dns.Msg -> Match[0] -> dns.Msg -> Match[1] -> dns.Msg -> ...
// The dns.Msg output of Match[n] is the input for Match[n+1]. 
//
// The final outcome (does a packet match or not?) is calculated as follows:
// true Match[0].Op Match[0].Func() Match[1].Op Match[1].Func() ...
// The result of this macthing is given to the action function(s). They can then
// decide what to do with a packet in the 'true' and in the 'false' case.
type Funkensturm struct {
	Setup   func() bool // Inital setup (for extra resolvers, or loading keys, or ...)
	Matches []Match     // Match- and modify functions
	Actions []Action    // What to do with the packets
}

// No matter what, we refuse to answer request with the response bit set.
func doFunkensturm(i []byte) ([]byte, os.Error) {
	pkt := new(dns.Msg)
	if !pkt.Unpack(i) {
		return nil, &dns.Error{Error: "Unpacking packet failed"}
	}
	if *verbose {
		fmt.Printf(">>>>>> ORIGINAL INCOMING\n")
		fmt.Printf("%v\n", pkt)
	}
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
	if *verbose {
		fmt.Printf(">>>>>> MODIFIED INCOMING\n")
		fmt.Printf("%v\n", pkt1)
	}

	// Loop through the Actions.Func* and do something with the
	// packet. Note there can only be one returned packet. 
	// We use 'ok' to signal what the above match did: true or false
	var resultpkt *dns.Msg
	for _, a := range f.Actions {
		resultpkt = a.Func(pkt1, ok)
	}

	if resultpkt == nil {
		return nil, &dns.Error{Error: "Action function returned nil packet"}
	}

	if *verbose {
		fmt.Printf(">>>>>> ORIGINAL OUTGOING\n")
		fmt.Printf("%v\n", resultpkt)
	}

	// loop again for matching, but now with OUT, this is done
	// for some last minute packet changing. Note the boolean return
	// code isn't used any more, i.e No more actions are allowed
	// anymore
	pkt1 = resultpkt
	for _, m := range f.Matches {
		pkt1, _ = m.Func(pkt1, OUT)
	}

	if *verbose {
		fmt.Printf(">>>>>> MODIFIED OUTGOING\n")
		fmt.Printf("%v\n", pkt1)
	}

	out, ok1 := pkt1.Pack()
	if !ok1 {
		return nil, &dns.Error{Error: "Packing packet failed"}
	}
	// Some final byte changing function here? 
	return out, nil

}

func (s *server) ResponderUDP(c *net.UDPConn, a net.Addr, i []byte) {
	out, err := doFunkensturm(i)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err.String())
		return
	}

	if out != nil {
		responder.SendUDP(out, c, a)
	}
	// nothing is send back
}

func (s *server) ResponderTCP(c *net.TCPConn, i []byte) {
	out, err := doFunkensturm(i)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err.String())
		return
	}

	if out != nil {
		responder.SendTCP(out, c)
	}
	// nothing is send back
}

var verbose *bool

func main() {
	var sserver *string = flag.String("sserver", "127.0.0.1", "Set the listener address")
	var sport *string = flag.String("sport", "8053", "Set the listener port")
	var rserver *string = flag.String("rserver", "127.0.0.1", "Remote server address")
	// multiple rservers??
	var rport *string = flag.String("rpost", "53", "Remote server port to forward queries to")
	verbose = flag.Bool("verbose", false, "Print packet as the flow through")       // needs to be global
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	f = funkensturm()
	ok := f.Setup()
	if !ok {
		fmt.Fprintf(os.Stderr, "Setup failed")
		return
	}
	// The resolver
	r := new(resolver.Resolver)
	r.Servers = []string{*rserver}
	r.Port = *rport
	qr = r.NewQuerier() // connect to global qr

	// The responder
	s := new(responder.Server)
	s.Address = *sserver
	s.Port = *sport
	var srv *server
	rs := make(chan bool)
	go s.NewResponder(srv, rs)

forever:
	for {
		// Wait for a signal to stop
		select {
		case <-signal.Incoming:
			println("Signal received, stopping")
			break forever
		}
	}
	rs <- true // shutdown responder and resolver
	qr <- resolver.Msg{}
	<-rs // wait for confirmation
	<-qr
}
