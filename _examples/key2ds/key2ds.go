package main

// Print the DNSKEY records of a domain as DS records
// (c) Miek Gieben - 2011
import (
	"dns"
        "os"
        "fmt"
)

func main() {
	c, err := dns.ClientConfigFromFile("/etc/resolv.conf")
        if len(os.Args) != 2 || err != nil {
                fmt.Printf("%s DOMAIN\n", os.Args[0])
                os.Exit(1)
        }
        m := new(dns.Msg)
        m.MsgHdr.RecursionDesired = true //only set this bit
        m.Question = make([]dns.Question, 1)
        m.Question[0] = dns.Question{os.Args[1], dns.TypeDNSKEY, dns.ClassINET}

        d := new(dns.Conn)
        d.RemoteAddr = c.Servers[0]
        in, err := dns.QuerySimple("udp", d, m)
        if in != nil {
                if in.Rcode != dns.RcodeSuccess {
                        fmt.Printf(" *** invalid answer name %s after DNSKEY query for %s\n", os.Args[1], os.Args[1])
                        os.Exit(1)
                }
                // Stuff must be in the answer section
                for _, k := range in.Answer {
                        // Foreach key would need to provide a DS records, both sha1 and sha256
                        if key, ok := k.(*dns.RR_DNSKEY); ok {
                                ds := key.ToDS(dns.HashSHA1)
                                ds.Hdr.Ttl = 0
                                fmt.Printf("%v\n", ds)
                                ds = key.ToDS(dns.HashSHA256)
                                ds.Hdr.Ttl = 0
                                fmt.Printf("%v\n", ds)
                        }
                }
        } else {
                fmt.Printf("*** error: %s\n", err.String())
        }
}
