/* 
 * Funkensturm 
 * Miek Gieben <miek@miek.nl>
 */

package main

import (
	"net"
	_ "fmt"
	"dns"
	_ "strconv"
	"dns/resolver"
	"dns/responder"
	"runtime"
	"os/signal"
)

// Strip the Addtional section of a pkt
func stripExtra(m *dns.Msg) *dns.Msg {
        m.Extra = []dns.RR{}
        return m
}

// Strip the Authority section of a pkt
func stripNs(m *dns.Msg) *dns.Msg {
        m.Ns = []dns.RR{}
        return m
}

type server responder.Server

func reply(a net.Addr, in []byte, tcp bool) *dns.Msg {
	inmsg := new(dns.Msg)
	if !inmsg.Unpack(in) {
		println("Unpacking failed")
		return nil
	}
	if inmsg.MsgHdr.Response == true {
		return nil // Don't answer responses
	}

	// it's valid mesg, return it
	return inmsg
}

func (s *server) ResponderUDP(c *net.UDPConn, a net.Addr, i []byte) {
	m := reply(a, i, false)
	if m == nil {
		return
	}
	// okay, send it using the resolver
	qr <- resolver.Msg{m, nil, nil}
	in := <-qr

        in.Dns = stripExtra(in.Dns)
//        in.Dns = stripNs(in.Dns)

	// in may be nil
	out, ok := in.Dns.Pack()
	if !ok {
		println("Failed to pack")
		return
	}
	responder.SendUDP(out, c, a)
}

func (s *server) ResponderTCP(c *net.TCPConn, in []byte) {
}

var qr chan resolver.Msg

func main() {
	runtime.GOMAXPROCS(5)

	r := new(resolver.Resolver)
	r.Servers = []string{"127.0.0.1"}
	r.Port = "53"
	qr = r.NewQuerier()

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
