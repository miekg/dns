/* 
 * Send back REFUSED
 *
 * Stephane Bortzmeyer <stephane+grong@bortzmeyer.org>
 *
 * Adapted to Go DNS (i.e. completely rewritten)
 * Miek Gieben <miek@miek.nl>
 */

package main

import (
	"net"
        "time"
	"dns"
        "dns/responder"
)

type server responder.Server

func (s *server) ResponderUDP(c *net.UDPConn, a net.Addr, in []byte) {
        inmsg := new(dns.Msg)
        if !inmsg.Unpack(in) {
                // FormError
                // NXdomain 'n stuff
                println("Unpacking failed")
        }
        m := new(dns.Msg)
        m.MsgHdr.Id = inmsg.MsgHdr.Id
        m.MsgHdr.Response = true
        m.MsgHdr.Opcode = dns.OpcodeQuery

        m.MsgHdr.Rcode = dns.RcodeRefused
        m.Question = make([]dns.Question, 1)
        m.Question[0] = inmsg.Question[0]
        out, b := m.Pack()
        if !b {
                println("Failed to pack")
        }
        responder.SendUDP(out, c, a)
}

func (s *server) ResponderTCP(c *net.TCPConn, in []byte) {
        return
}

func main() {
        s := new(responder.Server)
        s.Address = "127.0.0.1"
        s.Port = "8053"
        var srv *server
        ch := make(chan bool)
        go s.NewResponder(srv, ch)

        time.Sleep(100 * 1e9)


}
