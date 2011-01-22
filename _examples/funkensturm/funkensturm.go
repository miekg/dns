/* 
 * Funkensturm
 * Miek Gieben <miek@miek.nl>
 */

package main

import (
	"net"
	"fmt"
	"dns"
        "dns/resolver"
	"dns/responder"
	"os/signal"
)

// Where does the packet come from? 
// IN: initial packet received by the Responder
// any modifications here will reflect what kind of
// pkt is sent through. Normally there is no modification here.
// OUT: pkt as received back. Modifications here will reflect
// how the packet is send back to the original requester.
const (
	IN = iota       // set when receiving a packet
	OUT             // set when sending a packet

	OR
	AND
)

// A Match function is let loose on a DNS packet and
// returns (a possibly modified) DNS packet. It should
// return true when the packets matches the criteria in 
// the function.
// Op is used in chaining Match-structures together
type Match struct {
	Op   int // boolean op: OR, AND
	Func func(*dns.Msg, int) (*dns.Msg, bool)
}

// An action is something that is done with a packet. Funkensturm
// does not impose any restriction on what this can be.
type Action struct {
	Func func(*dns.Msg, bool) (*dns.Msg, bool)
}

// A complete config for Funkensturm. All matches in the Matches slice are
// chained together: Match[0] -> dns.Msg -> Match[1] -> dns.Msg -> ...
// The dns.Msg output of Match[n] is the input for Match[n+1]. 
// The final outcome (does a packet match or not?) is calculated as follows:
// true Match[0].Op Match[0].Func() Match[1].Op Match[1].Func()
// If the final result is true the action(s) are called. Note that
// at least one of these action functions should send the actual message!
type Funkensturm struct {
        Setup func() bool        // Inital setup (for extra resolver or ...)
	Matches []Match          // Match- and mangle functions
	Actions []Action         // What to do wit the packets
}

func (s *server) ResponderUDP(c *net.UDPConn, a net.Addr, i []byte) {
	pkt := reply(a, i)
	if pkt == nil {
		return
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

        // Loop through the Actions.Func* and do something with the
        // packet. Note there can only be one returned packet. 
        // We use 'ok' to signal what the above match did, true or false
        var resultpkt *dns.Msg
	for _, a := range f.Actions {
		resultpkt, ok1 = a.Func(pkt1, ok)
	}
        // what to do with the bool??

        // loop again for matching, but now with OUT, this is done
        // for some last minute packet changing. Note the boolean return
        // code isn't used any more, i.e No more actions are allowed
        // anymore
        pkt1 = resultpkt
	for _, m := range f.Matches {
		pkt1, _ = m.Func(pkt1, OUT)
	}

        if pkt1 == nil {
                return
        }
	out, ok1 := pkt1.Pack()
	if !ok1 {
		println("Failed to pack")
		return
	}
	responder.SendUDP(out, c, a)
}

func (s *server) ResponderTCP(c *net.TCPConn, in []byte) {
        /* todo */
}

// Small helper function
func reply(a net.Addr, in []byte) *dns.Msg {
	inmsg := new(dns.Msg)
	if !inmsg.Unpack(in) {
		println("Unpacking failed")
		return nil
	}
	if inmsg.MsgHdr.Response == true {
		return nil // Don't answer responses
	}
	return inmsg
}

// Setup a responder takes takes care of the incoming queries.
type server responder.Server

// Setup a initial resolver for sending the queries somewhere else.
var qr chan resolver.Msg

// The configuration of Funkensturm
var f *Funkensturm

func main() {
        f = funkensturm()
        ok := f.Setup()
        if !ok {
                fmt.Printf("Setup failed")
                return
        }
        // The resolver
        r := new(resolver.Resolver)
        r.Servers = []string{"127.0.0.1"}
        r.Port = "53"
        qr = r.NewQuerier()             // connect to global qr

        // The responder
	s := new(responder.Server)
	s.Address = "127.0.0.1"
	s.Port = "8053"
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
        rs <- true              // shut down responder
        qr <- resolver.Msg{}    // shut down resolver
        <-rs
        <-qr
}
