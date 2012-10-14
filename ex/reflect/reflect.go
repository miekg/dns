// Reflect is a small name server which sends back the IP address of its client, the
// recursive resolver. 
// When queried for type A (resp. AAAA), it sends back the IPv4 (resp. v6) address.
// In the additional section the port number and transport are shown.
// 
// Basic use pattern:
// 
//	dig @localhost -p 8053 whoami.miek.nl A
//
//	;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 2157
//	;; flags: qr rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
//	;; QUESTION SECTION:
//	;whoami.miek.nl.			IN	A
//
//	;; ANSWER SECTION:
//	whoami.miek.nl.		0	IN	A	127.0.0.1
//
//	;; ADDITIONAL SECTION:
//	whoami.miek.nl.		0	IN	TXT	"Port: 56195 (udp)"
//
// Similar services: whoami.ultradns.net, whoami.akamai.net. Also (but it
// is not their normal goal): rs.dns-oarc.net, porttest.dns-oarc.net,
// amiopen.openresolvers.org.
// 
// Original version is from: Stephane Bortzmeyer <stephane+grong@bortzmeyer.org>.
// 
// Adapted to Go (i.e. completely rewritten) by Miek Gieben <miek@miek.nl>.
package main

import (
	"flag"
	"fmt"
	"../../../dns"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime/pprof"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var (
	printf   *bool
	compress *bool
	tsig     *string
	dyn_rr   map[string]dns.RR
)

const dom = "whoami.miek.nl."

func handleUpdate(w dns.ResponseWriter, r *dns.Msg) {
	fmt.Println("got request %s %s\n", w, r)
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = *compress

	// if no TSIG at all, fail with NOTAUTH
	tsig := r.IsTsig()
	if tsig == nil {
		m.SetRcode(r, dns.RcodeNotAuth)
		w.Write(m)
		return
	}
	// if signature is invalid, fail with BADKEY
	if w.TsigStatus() != nil {
		m.SetRcode(r, dns.RcodeBadKey)
		w.Write(m)
		return
	}
	// if we made it this far, the TSIG is valid, add signature on response
	m.SetTsig(r.Extra[len(r.Extra)-1].(*dns.RR_TSIG).Hdr.Name, dns.HmacMD5, 300, time.Now().Unix())

	// this will be the name of the key, which we will make the zone
	// zone := tsig.Hdr.Name

	if r.MsgHdr.Opcode == dns.OpcodeUpdate && len(r.Ns) > 0 {
		for i := 0; i < len(r.Ns); i++ {
			name := r.Ns[i].Header().Name
			dyn_rr[name] = r.Ns[i]
		}
	}
	if r.MsgHdr.Opcode == dns.OpcodeQuery && len(r.Question) > 0 {
		for i := 0; i < len(r.Question); i++ {
			if rr, ok := dyn_rr[r.Question[i].Name]; ok {
				fmt.Printf("POLVI %s\n", rr)
				m.Answer = append(m.Answer, rr)
			}
		}
	}
	if *printf {
		fmt.Printf("Incoming msg:\n%v\n", r.String())
		fmt.Printf("Outgoing msg:\n%v\n", m.String())
	}
	w.Write(m)
}

func handleReflect(w dns.ResponseWriter, r *dns.Msg) {
	var (
		v4  bool
		rr  dns.RR
		str string
		a   net.IP
	)
	// TC must be done here
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = *compress
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
	case dns.TypeAXFR:
		c := make(chan *dns.XfrToken)
		var e *error
		if err := dns.XfrSend(w, r, c, e); err != nil {
			close(c)
			return
		}
		soa, _ := dns.NewRR(`whoami.miek.nl. IN SOA elektron.atoom.net. miekg.atoom.net. (
			2009032802 
			21600 
			7200 
			604800 
			3600)`)
		c <- &dns.XfrToken{RR: []dns.RR{soa, t, rr, soa}}
		close(c)
		w.Hijack()
		// w.Close() // Client closes
		return
	case dns.TypeSOA:
		soa, _ := dns.NewRR(`whoami.miek.nl. IN SOA ns.polvi. ns.polvi. (
			2009032802 
			21600 
			7200 
			604800 
			3600)`)
		m.Answer = append(m.Answer, soa)
	case dns.TypeTXT:
		m.Answer = append(m.Answer, t)
		m.Extra = append(m.Extra, rr)
	default:
		fallthrough
	case dns.TypeAAAA, dns.TypeA:
		m.Answer = append(m.Answer, rr)
		m.Extra = append(m.Extra, t)
	}

	if r.IsTsig() != nil {
		if w.TsigStatus() == nil {
			m.SetTsig(r.Extra[len(r.Extra)-1].(*dns.RR_TSIG).Hdr.Name, dns.HmacMD5, 300, time.Now().Unix())
		} else {
			println("Status", w.TsigStatus().Error())
		}
	}
	if *printf {
		fmt.Printf("%v\n", m.String())
	}
	w.Write(m)
}

func serve(net, name, secret string) {
	switch name {
	case "":
		err := dns.ListenAndServe(":53", net, nil)
		if err != nil {
			fmt.Printf("Failed to setup the "+net+" server: %s\n", err.Error())
		}
	default:
		server := &dns.Server{Addr: ":53", Net: net, TsigSecret: map[string]string{name: secret}}
		err := server.ListenAndServe()
		if err != nil {
			fmt.Printf("Failed to setup the "+net+" server: %s\n", err.Error())
		}
	}
}

func main() {
	cpuprofile := flag.String("cpuprofile", "", "write cpu profile to file")
	printf = flag.Bool("print", false, "print replies")
	compress = flag.Bool("compress", false, "compress replies")
	tsig = flag.String("tsig", "", "use MD5 hmac tsig: keyname:base64")
	var name, secret string
	flag.Usage = func() {
		flag.PrintDefaults()
	}
	flag.Parse()
	if *tsig != "" {
		a := strings.SplitN(*tsig, ":", 2)
		name, secret = dns.Fqdn(a[0]), a[1]	// fqdn the name, which everybody forgets...
	}
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	dns.HandleFunc("miek.nl.", handleReflect)
	dns.HandleFunc("polvi.", handleUpdate)
	dyn_rr = make(map[string]dns.RR)
	dns.HandleFunc("authors.bind.", dns.HandleAuthors)
	dns.HandleFunc("authors.server.", dns.HandleAuthors)
	dns.HandleFunc("version.bind.", dns.HandleVersion)
	dns.HandleFunc("version.server.", dns.HandleVersion)
	go serve("tcp", name, secret)
	go serve("udp", name, secret)
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
forever:
	for {
		select {
		case s:=<-sig:
			fmt.Printf("Signal (%d) received, stopping\n", s)
			break forever
		}
	}
}
