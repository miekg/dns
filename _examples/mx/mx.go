package main

// Print the MX records of a domain
// (c) Miek Gieben - 2011
import (
	"dns"
        "os"
        "fmt"
)

func main() {
	r := new(dns.Resolver)
        r.FromFile("/etc/resolv.conf")
        if len(os.Args) != 2 {
                fmt.Printf("%s DOMAIN\n", os.Args[0])
                os.Exit(1)
        }

        m := new(dns.Msg)
        m.MsgHdr.RecursionDesired = true //only set this bit
        m.Question = make([]dns.Question, 1)
        m.Question[0] = dns.Question{os.Args[1], dns.TypeMX, dns.ClassINET}

        in, err := r.Query(m)
        if in != nil {
                if in.Rcode != dns.RcodeSuccess {
                        fmt.Printf(" *** invalid answer name %s after MX query for %s\n", os.Args[1], os.Args[1])
                        os.Exit(1)
                }
                // Stuff must be in the answer section
                for _, a := range in.Answer {
                        fmt.Printf("%v\n", a)
                }
        } else {
                fmt.Printf("*** error: %s\n", err.String())
        }
}
