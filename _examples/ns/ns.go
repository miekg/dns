package main

import (
	"os"
	"dns"
        "net"
	"fmt"
	"flag"
        "os/signal"
//	"json"
)

var counter int

func main() {
//	var zone *string = flag.String("zone", "", "The zone to serve")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s zone...\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	m := new(dns.Msg)
	m.MsgHdr.Id = dns.Id()
	m.MsgHdr.Authoritative = true
	m.MsgHdr.AuthenticatedData = false
	m.MsgHdr.RecursionAvailable = true
	m.MsgHdr.Response = true
	m.MsgHdr.Opcode = dns.OpcodeQuery
	m.MsgHdr.Rcode = dns.RcodeSuccess
	m.Question = make([]dns.Question, 1)
	m.Question[0] = dns.Question{"miek.nl.", dns.TypeTXT, dns.ClassINET}
	m.Answer = make([]dns.RR, 1)
	t := new(dns.RR_TXT)
	t.Hdr = dns.RR_Header{Name: "miek.nl.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600}
	t.Txt = "Een antwoord"
	m.Answer[0] = t

        errchan := make(chan os.Error)
        go udp("127.0.0.1:8054", errchan)
        go tcp("127.0.0.1:8054", errchan)

        forever:
                for {
                        select {
                        case e := <-errchan:
                                fmt.Printf("Error received, stopping: %s\n", e.String())
                                break forever
                        case <-signal.Incoming:
                                fmt.Printf("Signal received, stopping\n")
                                break forever
                        }
                }
        close(errchan)
        fmt.Printf("Queries answered: %d\n", counter)
}

func tcp(addr string, e chan os.Error) {
        a, err := net.ResolveTCPAddr(addr)
        if err != nil {
                e <- err
        }
        l, err := net.ListenTCP("tcp", a)
        if err != nil {
                e <- err
        }
        err = dns.ServeTCP(l, replyTCP)
        e <- err
        return
}

func udp(addr string, e chan os.Error) {
        a, err := net.ResolveUDPAddr(addr)
        if err != nil {
                e <- err
        }
        l, err := net.ListenUDP("udp", a)
        if err != nil {
                e <- err
        }
        err = dns.ServeUDP(l, replyUDP)
        e <- err
        return
}


func createpkg(id uint16, tcp bool, remove net.Addr) []byte {
        m := new(dns.Msg)
        m.MsgHdr.Id = id
        m.MsgHdr.Authoritative = true
        m.MsgHdr.AuthenticatedData = false
        m.MsgHdr.RecursionAvailable = true
        m.MsgHdr.Response = true
        m.MsgHdr.Opcode = dns.OpcodeQuery
        m.MsgHdr.Rcode = dns.RcodeSuccess
        m.Question = make([]dns.Question, 1)
        m.Question[0] = dns.Question{"miek.nl.", dns.TypeTXT, dns.ClassINET}
        m.Answer = make([]dns.RR, 1)
        t := new(dns.RR_TXT)
        t.Hdr = dns.RR_Header{Name: "miek.nl.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600}
        if tcp {
                t.Txt = "Dit is iets anders TCP"
        } else {
                t.Txt = "Dit is iets anders UDP"
        }
        m.Answer[0] = t
        out, _ := m.Pack()
        return out
}

func replyUDP(c *net.UDPConn, a net.Addr, in *dns.Msg) {
        if in.MsgHdr.Response == true {
                // Uh... answering to an response??
                // dont think so
                return
        }
        out := createpkg(in.MsgHdr.Id, false, a)
        dns.SendUDP(out, c, a)
        counter++
}

func replyTCP(c *net.TCPConn, a net.Addr, in *dns.Msg) {
        if in.MsgHdr.Response == true {
                return
        }
        out := createpkg(in.MsgHdr.Id, true, a)
        dns.SendTCP(out, c, a)
        counter++
}

