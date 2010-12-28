package main

import (
        "dns"
	"fmt"
)

func main() {
	key := new(dns.RR_DNSKEY)
	key.Hdr.Name = "miek.nl"
	key.Hdr.Rrtype = dns.TypeDNSKEY
	key.Hdr.Class = dns.ClassINET
	key.Hdr.Ttl = 3600
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = dns.AlgRSASHA256
	key.PubKey = "AwEAAcNEU67LJI5GEgF9QLNqLO1SMq1EdoQ6E9f85ha0k0ewQGCblyW2836GiVsm6k8Kr5ECIoMJ6fZWf3CQSQ9ycWfTyOHfmI3eQ/1Covhb2y4bAmL/07PhrL7ozWBW3wBfM335Ft9xjtXHPy7ztCbV9qZ4TVDTW/Iyg0PiwgoXVesz"

        tag := key.KeyTag()
        fmt.Printf("%v\n", key)
        fmt.Printf("Wrong key tag: %d\n", tag)

        m := new(dns.Msg)
        m.Ns = make([]dns.RR, 1)
        m.Ns[0] = key
        m.Pack()
}
