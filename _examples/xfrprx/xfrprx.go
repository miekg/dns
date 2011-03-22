package main

// Xfrprx is a proxy that intercepts notify messages
// and then performs a ixfr/axfr to get the new 
// zone contents. 
// This zone is then checked cryptographically is
// everything is correct.
// If a new DNSKEY record is seen for the apex and
// it validates it writes this record to disk and
// this new key will be used in future validations.

import (
        "os"
        "os/signal"
        "net"
	"fmt"
	"dns"
)

// Initiate an AXFR from the server. Everything is
// hardcoded atm
func doTransfer() []dns.Xfr {
        res := new(dns.Resolver)
        res.Servers[0] = "127.0.0.1:53"

        c := make(chan dns.Xfr)
        m := new(dns.Msg)
        m.SetAxfrRequest("miek.nl", dns.ClassINET)

        go res.Axfr(m, c)
        var ret []dns.Xfr
        for x:= range c {
                ret = append(ret, x)
        }
        return ret
}

func replyUDP(c *net.UDPConn, a net.Addr, i *dns.Msg) {
        if i.IsNotify() {
                //doNotifyReply()
                doTransfer()
                //if checkTransfer(rtf, key) {
                        // Success
                        // Notify remote end
                        // send axfr
                //}

        }
        out, ok := i.Pack()
        if ok {
	        dns.SendUDP(out, c, a)
        }
}

func replyTCP(c *net.TCPConn, a net.Addr, i *dns.Msg) {
        out, ok := i.Pack()
        if ok {
	        dns.SendTCP(out, c, a)
        }
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

// Step 1. Create server that sees an notify and
// performs an AXFR.
// Test with ldns-notify

func main() {
	err := make(chan os.Error)
	go udp("127.0.0.1:8053", err)
	go tcp("127.0.0.1:8053", err)

forever:
	for {
		select {
		case e := <-err:
			fmt.Printf("Error received, stopping: %s\n", e.String())
			break forever
		case <-signal.Incoming:
			fmt.Printf("Signal received, stopping")
			break forever
		}
	}
	close(err)

}
