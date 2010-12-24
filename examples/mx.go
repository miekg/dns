package main

// Print the MX records of a domain
import (
	"dns"
        "os"
        "fmt"
)

func main() {
	r := new(dns.Resolver)
	qr := dns.NewQuerier(r)
        r.Servers = []string{"127.0.0.1"}
        r.Timeout = 2
        r.Attempts = 1

        if len(os.Args) != 2 {
                fmt.Printf("%s DOMAIN\n", os.Args[0])
                os.Exit(1)
        }

        m := new(dns.Msg)
        m.MsgHdr.Recursion_desired = true //only set this bit
        m.Question = make([]dns.Question, 1)
        m.Question[0] = dns.Question{os.Args[1], dns.TypeMX, dns.ClassINET}

        qr <- dns.DnsMsg{m, nil}
        in := <-qr

        if in.Dns.Rcode != dns.RcodeSuccess {
                fmt.Printf(" *** invalid answer name %s after MX query for %s\n", os.Args[1], os.Args[1])
                os.Exit(1)
        }
        // Stuff must be in the answer section
        for _, a := range in.Dns.Answer {
                fmt.Printf("%v\n", a)
        }

        // Stop the resolver, send it a null mesg
        qr <- dns.DnsMsg{nil, nil}
        <-qr
}
