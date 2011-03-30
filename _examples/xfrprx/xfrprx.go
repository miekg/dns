package main

// Xfrprx is a proxy that intercepts notify messages
// and then performs a ixfr/axfr to get the new 
// zone contents. 
// This zone is then checked cryptographically is
// everything is correct.
// When the message is deemed correct a remote 
// server is sent a notify to retrieve the ixfr/axfr.
// If a new DNSKEY record is seen for the apex and
// it validates it writes this record to disk and
// this new key will be used in future validations.

import (
	"os"
	"os/signal"
	"fmt"
	"dns"
)

// Static amount of RRs...
type zone struct {
	name string
	rrs  [10000]dns.RR
	size int
        correct bool
}

var Zone zone

func handle(d *dns.Conn, i *dns.Msg) {
	if i.MsgHdr.Response == true {
		return
	}
	handleNotify(d, i)
//        handleNotifyOut("127.0.0.1:53") // 
	handleXfrOut(d, i)
        if Zone.name != "" {
                // We have transfered a zone and can check it. For now assume ok.
                Zone.correct = true
        }
}

func qhandle(d *dns.Conn, i *dns.Msg) {
        o, err := d.ExchangeMsg(i, false)
        dns.QueryReply <- &dns.Query{Query: i, Reply: o, Conn: d, Err: err}
        d.Close()
}

func listen(addr string, e chan os.Error, tcp string) {
	switch tcp {
	case "tcp":
		err := dns.ListenAndServeTCP(addr, handle)
		e <- err
	case "udp":
		err := dns.ListenAndServeUDP(addr, handle)
		e <- err
	}
	return
}

func query(e chan os.Error, tcp string) {
        switch tcp {
        case "tcp":
                err := dns.QueryAndServeTCP(qhandle)
                e <- err
        case "udp":
                err := dns.QueryAndServeUDP(qhandle)
                e <- err
        }
        return
}

func main() {
	err := make(chan os.Error)

	// Outgoing queries
        dns.InitQueryChannels()
	go query(err, "tcp")
        go query(err, "udp")

	// Incoming queries
	go listen("127.0.0.1:8053", err, "tcp")
	go listen("[::1]:8053", err, "tcp")
	go listen("127.0.0.1:8053", err, "udp")
	go listen("[::1]:8053", err, "udp")

forever:
	for {
		select {
		case e := <-err:
			fmt.Printf("Error received, stopping: %s\n", e.String())
			break forever
		case <-signal.Incoming:
			fmt.Printf("Signal received, stopping\n")
			break forever
                case q := <-dns.QueryReply:
                        fmt.Printf("Query received:\n%v\n", q.Reply)
		}
	}
	close(err)
}
