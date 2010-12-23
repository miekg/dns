package main

// Test EDNS RR records
import (
        "fmt"
        "dns"
)

func main() {
        sig := new(dns.RR_RRSIG)
        sig.Hdr.Name = "miek.nl."
        sig.Hdr.Rrtype = dns.TypeRRSIG
        sig.Hdr.Class = dns.ClassINET
        sig.Hdr.Ttl = 3600
        sig.TypeCovered = dns.TypeDNSKEY
        sig.Algorithm = dns.AlgRSASHA1
        sig.Labels = 2
        sig.OrigTtl = 4000
        sig.Expiration = 1000
        sig.Inception = 800
        sig.KeyTag = 34641
        sig.SignerName = "miek.nl."
        sig.Sig = "AwEAAaHIwpx3w4VHKi6i1LHnTaWeHCL154Jug0Rtc9ji5qwPXpBo6A5sRv7cSsPQKPIwxLpyCrbJ4mr2L0EPOdvP6z6YfljK2ZmTbogU9aSU2fiq/4wjxbdkLyoDVgtO+JsxNN4bjr4WcWhsmk1Hg93FV9ZpkWb0Tbad8DFqNDzr//kZ"

        fmt.Printf("%v\n", sig)

        edns := new(dns.RR_OPT)
        edns.Hdr.Name = "miek.nl."
        edns.Hdr.Rrtype = dns.TypeOPT
        edns.Hdr.Class = dns.ClassINET
        edns.Hdr.Ttl = 3600
        edns.Option = make([]dns.Option, 1)
        edns.Option[0].Code = dns.OptionCodeNSID
        edns.Option[0].Data = "lalalala"
        fmt.Printf("%v\n", edns)
}
