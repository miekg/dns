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
	"dns"
	"os/signal"
)

type server dns.Server

func (s *server) ReplyUDP(c *net.UDPConn, a net.Addr, in []byte) {
	inmsg := new(dns.Msg)
	if !inmsg.Unpack(in) {
		// FormError
		// NXdomain 'n stuff
		println("Unpacking failed")
	}
	if inmsg.MsgHdr.Response == true {
		return // don't answer responses
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
	dns.SendUDP(out, c, a)
}

func (s *server) ReplyTCP(c *net.TCPConn, a net.Addr, in []byte) {
	return
}

func main() {
	var srv *server
	ch := make(chan bool)
	e := make(chan os.Error)
	go dns.ListenAndServe("127.0.0.1:8053", srv, ch, e)

forever:
	for {
		// Wait for a signal to stop
		select {
                case err := <-e:
                        fmt.Printf("Error received, stopping: %s\n", err.String())
                        break forever
		case <-signal.Incoming:
                        fmt.Printf("Signal received, stopping")
			ch <- true
			break forever
		}
	}
	close(ch)
}
