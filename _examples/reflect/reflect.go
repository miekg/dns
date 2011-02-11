/* 
 * A name server which sends back the IP address of its client, the
 * recursive resolver. When queried for type TXT, it sends back the text
 * form of the address.  When queried for type A (resp. AAAA), it sends
 * back the IPv4 (resp. v6) address.
 *
 * Similar services: whoami.ultradns.net, whoami.akamai.net. Also (but it
 * is not their normal goal): rs.dns-oarc.net, porttest.dns-oarc.net,
 * amiopen.openresolvers.org.
 *
 * Stephane Bortzmeyer <stephane+grong@bortzmeyer.org>
 *
 * Adapted to Go DNS (i.e. completely rewritten)
 * Miek Gieben <miek@miek.nl>
 */

package main

import (
	"os"
	"net"
	"dns"
        "fmt"
	"strconv"
	"runtime"
	"os/signal"
)

func reply(a net.Addr, in *dns.Msg, tcp bool) *dns.Msg {
	if in.MsgHdr.Response == true {
		return nil // Don't answer responses
	}
	m := new(dns.Msg)
	m.MsgHdr.Id = in.MsgHdr.Id
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

	m.Question[0] = in.Question[0]
	m.Answer[0] = r
	m.Extra[0] = t
	return m
}

func replyUDP(c *net.UDPConn, a net.Addr, in *dns.Msg) {
	m := reply(a, in, false)
	if m == nil {
		return
	}
        fmt.Fprintf(os.Stderr, "%v\n", m)
	out, ok := m.Pack()
	if !ok {
		println("Failed to pack")
		return
	}
	dns.SendUDP(out, c, a)
}

func replyTCP(c *net.TCPConn, a net.Addr, in *dns.Msg) {
	m := reply(a, in, true)
	if m == nil {
		return
	}
        fmt.Fprintf(os.Stderr, "%v\n", m)
	out, ok := m.Pack()
	if !ok {
		println("Failed to pack")
		return
	}
	dns.SendTCP(out, c, a)
}


func main() {
        dns.ListenAndServeUDP("127.0.0.1:8053", replyUDP)
}
