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
 * Original version from:
 * Stephane Bortzmeyer <stephane+grong@bortzmeyer.org>
 *
 * Adapted to Go DNS (i.e. completely rewritten)
 * Miek Gieben <miek@miek.nl>
 */

package main

import (
	"dns"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime/pprof"
	"strconv"
)

var printf *bool
const dom = "whoami.miek.nl."

func handleReflect(w dns.ResponseWriter, r *dns.Msg) {
	var (
		v4  bool
		rr  dns.RR
		str string
		a   net.IP
	)
	m := new(dns.Msg)
	m.SetReply(r)
	if ip, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		str = "Port: " + strconv.Itoa(ip.Port) + " (udp)"
		a = ip.IP
		v4 = a.To4() != nil
	}
	if ip, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		str = "Port: " + strconv.Itoa(ip.Port) + " (tcp)"
		a = ip.IP
		v4 = a.To4() != nil
	}

	if v4 {
		rr = new(dns.RR_A)
		rr.(*dns.RR_A).Hdr = dns.RR_Header{Name: dom, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0}
		rr.(*dns.RR_A).A = a.To4()
	} else {
		rr = new(dns.RR_AAAA)
		rr.(*dns.RR_AAAA).Hdr = dns.RR_Header{Name: dom, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 0}
		rr.(*dns.RR_AAAA).AAAA = a
	}

	t := new(dns.RR_TXT)
	t.Hdr = dns.RR_Header{Name: dom, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0}
	t.Txt = []string{str}

        switch r.Question[0].Qtype {
        case dns.TypeTXT:
		m.Answer = append(m.Answer, t)
		m.Extra = append(m.Extra, rr)
        default: fallthrough
        case dns.TypeAAAA, dns.TypeA:
		m.Answer = append(m.Answer, rr)
		m.Extra = append(m.Extra, t)

        }
        /*
        nsec3 := new(dns.RR_NSEC3)
        nsec3.Hdr = dns.RR_Header{Name: dom, Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 0}
        nsec3.Hash = dns.SHA1
        nsec3.Flags = 0
        nsec3.Iterations = 1
        nsec3.Salt = "AABB"
        nsec3.SaltLength = uint8(len(nsec3.Salt)/2)
        nsec3.NextDomain = "miek.nl."
        nsec3.TypeBitMap = []uint16{dns.TypeA, dns.TypeNS, dns.TypeSOA, dns.TypeTXT, dns.TypeRRSIG, 4000, 4001, 5949}
        nsec3.HashNames("miek.nl.")
        m.Extra = append(m.Extra, nsec3)
        */

	b, ok := m.Pack()
        if *printf {
                fmt.Printf("%v\n", m.String())
        }
	if !ok {
		log.Print("Packing failed")
                m.SetRcode(r, dns.RcodeServerFailure)
                m.Extra = nil
                m.Answer = nil
                b, _ = m.Pack()
	}
	w.Write(b)
}

func serve(net string) {
	err := dns.ListenAndServe(":8053", net, nil)
	if err != nil {
		fmt.Printf("Failed to setup the "+net+" server: %s\n", err.Error())
	}
}

func main() {
	cpuprofile := flag.String("cpuprofile", "", "write cpu profile to file")
	printf = flag.Bool("print", false, "print replies")
	flag.Usage = func() {
		flag.PrintDefaults()
	}
	flag.Parse()
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	dns.HandleFunc(".", handleReflect)
	go serve("tcp")
	go serve("udp")
	sig := make(chan os.Signal)
	signal.Notify(sig)
forever:
	for {
		select {
		case <-sig:
			fmt.Printf("Signal received, stopping\n")
			break forever
		}
	}
}
