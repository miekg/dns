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
	"os/signal"
	"strconv"
)

func reply(c *dns.Conn, in *dns.Msg) []byte {
	m := new(dns.Msg)
	m.SetReply(in.MsgHdr.Id)

	m.Question = make([]dns.Question, 1)
	m.Answer = make([]dns.RR, 1)
	m.Extra = make([]dns.RR, 1)

	m.Question[0] = in.Question[0]

        var ad net.IP
        if c.UDP != nil {
                ad = c.Addr.(*net.UDPAddr).IP
        } else {
                ad = c.Addr.(*net.TCPAddr).IP
        }
        if ad.To4() != nil {
                r := new(dns.RR_A)
                r.Hdr = dns.RR_Header{Name: "whoami.miek.nl.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0}
                if c.UDP != nil {
                        r.A = c.Addr.(*net.UDPAddr).IP
                } else {
                        r.A = c.Addr.(*net.TCPAddr).IP
                }
                m.Answer[0] = r
        } else {
                r := new(dns.RR_AAAA)
                r.Hdr = dns.RR_Header{Name: "whoami.miek.nl.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0}
                if c.UDP != nil {
                        r.AAAA = c.Addr.(*net.UDPAddr).IP
                } else {
                        r.AAAA = c.Addr.(*net.TCPAddr).IP
                }
                m.Answer[0] = r
        }

	t := new(dns.RR_TXT)
	t.Hdr = dns.RR_Header{Name: "whoami.miek.nl.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0}
	if c.TCP != nil {
		t.Txt = "Port: " + strconv.Itoa(c.Port) + " (tcp)"
	} else {
		t.Txt = "Port: " + strconv.Itoa(c.Port) + " (udp)"
	}
	m.Extra[0] = t

	b, _ := m.Pack()
        return b
}

func handle(c *dns.Conn, in *dns.Msg) {
	if in.MsgHdr.Response == true {
		return      // We don't do responses
	}
	answer := reply(c, in)
	c.Write(answer)
}

func tcp(addr string, e chan os.Error) {
	err := dns.ListenAndServeTCP(addr, handle)
	e <- err
	return
}

func udp(addr string, e chan os.Error) {
        err := dns.ListenAndServeUDP(addr, handle)
	e <- err
	return
}

func main() {
	e := make(chan os.Error)
	go udp("127.0.0.1:8053", e)
	go udp("[::1]:8053", e)
	go tcp("127.0.0.1:8053", e)
	go tcp("[::1]:8053", e)

forever:
	for {
		// Wait for a signal to stop
		select {
		case err := <-e:
			fmt.Printf("Error received, stopping: %s\n", err.String())
			break forever
		case <-signal.Incoming:
			fmt.Printf("Signal received, stopping\n")
			break forever
		}
	}
	close(e)
}
