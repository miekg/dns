package main

// Send a DNS notify
// (c) Miek Gieben - 2011
import (
	"dns"
        "dns/resolver"
	"os"
	"fmt"
)

func main() {
	r := new(resolver.Resolver)
	qr := r.NewQuerier()
	r.Servers = []string{"127.0.0.1"}
	r.Timeout = 2
	r.Attempts = 1
	var in resolver.Msg

	if len(os.Args) != 2 {
		fmt.Printf("%s NAMESERVER\n", os.Args[0])
		os.Exit(1)
	}

	m := new(dns.Msg)
	m.Question = make([]dns.Question, 1)
        m.Question[0] = dns.Question{"miek.nl", dns.TypeSOA, dns.ClassINET}
        m.MsgHdr.Opcode = dns.OpcodeNotify
        qr <- resolver.Msg{m, nil}
        in = <-qr
//        if in.Dns != nil && in.Dns.Answer != nil {
        if in.Dns != nil {
//                fmt.Printf("%v\n", in.Dns.Answer[0])
                fmt.Printf("%v\n", in.Dns)
        }

	// Stop the resolver, send it a null mesg
	qr <- resolver.Msg{nil, nil}
	<-qr
}
