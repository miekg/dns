/* 
 * Funkensturm 
 * Miek Gieben <miek@miek.nl>
 */

package main

import (
	"net"
	_ "fmt"
	"dns"
	"strconv"
	"dns/resolver"
	"dns/responder"
	"runtime"
	"os/signal"
)

type server responder.Server

func reply(a net.Addr, in []byte, tcp bool) *dns.Msg {
	inmsg := new(dns.Msg)
	if !inmsg.Unpack(in) {
		println("Unpacking failed")
		return nil
	}

	// it's valid mesg, return it
	return inmsg

	if inmsg.MsgHdr.Response == true {
		return nil // Don't answer responses
	}
	m := new(dns.Msg)
	m.MsgHdr.Id = inmsg.MsgHdr.Id
	m.MsgHdr.Authoritative = true
	m.MsgHdr.Response = true
	m.MsgHdr.Opcode = dns.OpcodeQuery

	m.MsgHdr.Rcode = dns.RcodeSuccess
	m.Question = make([]dns.Question, 1)
	m.Answer = make([]dns.RR, 1)
	m.Extra = make([]dns.RR, 1)

	r := new(dns.RR_A)
	r.Hdr = dns.RR_Header{Name: "whoami.miek.nl.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0}
	ip, _ := net.ResolveUDPAddr(a.String()) // No general variant for both upd and tcp
	r.A = ip.IP.To4()                       // To4 very important

	t := new(dns.RR_TXT)
	t.Hdr = dns.RR_Header{Name: "whoami.miek.nl.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0}
	if tcp {
		t.Txt = "Port: " + strconv.Itoa(ip.Port) + " (tcp)"
	} else {
		t.Txt = "Port: " + strconv.Itoa(ip.Port) + " (udp)"
	}

	m.Question[0] = inmsg.Question[0]
	m.Answer[0] = r
	m.Extra[0] = t

	return m
}

func (s *server) ResponderUDP(c *net.UDPConn, a net.Addr, i []byte) {
	m := reply(a, i, false)
	if m == nil {
		return
	}
	// okay, send it using the resolver
	qr <- resolver.Msg{m, nil, nil}
	in := <-qr

        // Okay, not strip the additional section
        if len(in.Dns.Extra) > 0 {
                println("Stripping additional section")
                in.Dns.Extra = []dns.RR{}
        }

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
