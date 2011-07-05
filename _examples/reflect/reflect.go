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
	"dns"
	"fmt"
	//	"os"
	//	"os/signal"
//	"strconv"
)

func handleReflect(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Extra = make([]dns.RR, 1)
//	m.Answer = make([]dns.RR, 1)

        println(w.RemoteAddr())
	ad := net.ParseIP(w.RemoteAddr())
        println(ad.String())
//	if ad.To4() != nil {
//		rr := new(dns.RR_A)
//		rr.Hdr = dns.RR_Header{Name: "whoami.miek.nl.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0}
//		rr.A = ad
//		m.Answer[0] = rr
//	} else {
//		r := new(dns.RR_AAAA)
//		r.Hdr = dns.RR_Header{Name: "whoami.miek.nl.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 0}
//		r.AAAA = ad
//		m.Answer[0] = r
//	}

	t := new(dns.RR_TXT)
	t.Hdr = dns.RR_Header{Name: "whoami.miek.nl.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0}
//	t.Txt = "Port: " + strconv.Itoa(w.RemotePort()) + " (" + w.RemoteTransport() + ")"
	t.Txt = "Port: " + " (" + w.RemoteTransport() + ")"
	m.Extra[0] = t

	b, _ := m.Pack()
	w.Write(b)
}

func main() {
	dns.HandleFunc(".", handleReflect)
	err := dns.ListenAndServe(":8053", "udp", nil)
	if err != nil {
		fmt.Printf("Failed to setup the server")
	}
}
