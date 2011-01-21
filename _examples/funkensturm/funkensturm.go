/* 
 * Funkensturm
 * Miek Gieben <miek@miek.nl>
 */

package main

import (
	"net"
	"fmt"
	"dns"
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
	IN = iota
	OUT

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
	Func func(in *dns.Msg) (*dns.Msg, bool)
}

// A complete config for Funkensturm. All matches in the Matches slice are
// chained together: Match[0] -> dns.Msg -> Match[1] -> dns.Msg -> ...
// The dns.Msg output of Match[n] is the input for Match[n+1]. 
// The final outcome (does a packet match or not?) is calculated as follows:
// true Match[0].Op Match[0].Func() Match[1].Op Match[1].Func()
// If the final result is true the action(s) are called. Note that
// at least one of these action functions should send the actual message!
type Funkensturm struct {
	Matches []Match
	Actions []Action
}

type server responder.Server

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

func (s *server) ResponderUDP(c *net.UDPConn, a net.Addr, i []byte) {
	pkt := reply(a, i)
	if pkt == nil {
		return
	}
        // here I need to call funkensturm
	matches := getMatches()

	ok, ok1 := true, true
        pkt1 := pkt
	for _, m := range matches {
		pkt1, ok1 = m.Func(pkt1, IN)
		switch m.Op {
		case AND:
			ok = ok && ok1
		case OR:
			ok = ok || ok1
		}
	}

        if !ok {
                fmt.Println("We doen niks")
                return
        }
        println("uitkomst: ", ok)
        fmt.Printf("%v\n", pkt1)

        /*
	out, ok := in.Dns.Pack()
	if !ok {
		println("Failed to pack")
		return
	}
	responder.SendUDP(out, c, a)
        */
}

func (s *server) ResponderTCP(c *net.TCPConn, in []byte) {
}

func main() {
        // Start the stuff the needs started, call init()
        Funkinit()

	s := new(responder.Server)
	s.Address = "127.0.0.1"
	s.Port = "8053"
	var srv *server
	ch := make(chan bool)
	go s.NewResponder(srv, ch)

forever:
	for {
		// Wait for a signal to stop
		select {
		case <-signal.Incoming:
			println("Signal received, stopping")
			break forever
		}
	}
}
