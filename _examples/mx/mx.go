package main

// Print the MX records of a domain
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
        r.FromFile("/etc/resolv.conf")
        if len(os.Args) != 2 {
                fmt.Printf("%s DOMAIN\n", os.Args[0])
                os.Exit(1)
        }

        m := new(dns.Msg)
        m.MsgHdr.RecursionDesired = true //only set this bit
        m.Question = make([]dns.Question, 1)
        m.Question[0] = dns.Question{os.Args[1], dns.TypeMX, dns.ClassINET}

        qr <- resolver.Msg{m, nil}
        in := <-qr
        if in.Dns != nil {
                if in.Dns.Rcode != dns.RcodeSuccess {
                        fmt.Printf(" *** invalid answer name %s after MX query for %s\n", os.Args[1], os.Args[1])
                        os.Exit(1)
                }
                // Stuff must be in the answer section
                for _, a := range in.Dns.Answer {
                        fmt.Printf("%v\n", a)
                }
        } else {
                fmt.Printf("*** error: %s\n", in.Error.String())
        }

        // Stop the resolver, send it a null mesg
        qr <- resolver.Msg{nil, nil}
        <-qr
}
