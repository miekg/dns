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
	"net"
        "strconv"
	"dns"
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
        r.A = ip.IP.To4()        // To4 very important

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

func (s *server) ResponderUDP(c *net.UDPConn, a net.Addr, in []byte) {
        m := reply(a, in, false)
        if m == nil {
                return
        }
        out, ok := m.Pack()
        if !ok {
                println("Failed to pack")
                return
        }
        responder.SendUDP(out, c, a)
}

func (s *server) ResponderTCP(c *net.TCPConn, in []byte) {
        m := reply(c.RemoteAddr(), in, true)
        if m == nil {
                return
        }
        out, ok := m.Pack()
        if !ok {
                println("Failed to pack")
                return
        }
        responder.SendTCP(out, c)
}

func main() {
        runtime.GOMAXPROCS(10)          // Be bold

        s := new(responder.Server)
        s.Address = "127.0.0.1"
        s.Port = "8053"
        var srv *server
        ch := make(chan bool)
        go s.NewResponder(srv, ch)

        t := new(responder.Server)
        t.Address = "127.0.0.1"
        t.Port = "8053"
        t.Tcp = true
        var srvt *server
        cht := make(chan bool)
        go t.NewResponder(srvt, cht)

forever:
        for {
                // Wait for a signal to stop
                select {
                case <-signal.Incoming:
                        println("Signal received, stopping")
                        ch <- true
                        cht <- true
                        break forever
                case <-cht:
                        // last message from tcp channel
                case <-ch:
                        // last message from udp channel
                }
        }
        close(cht)
        close(ch)
}
