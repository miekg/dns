package main

// This is a signing proxy. 

// Lots of hardcoded stuff. The first record in the answer section is
// signed with the key for example.org. The RRSIG is added to the packet.
// We could also use one 1 key for multiple domains.
import (
	"dns"
	"dns/resolver"
        "crypto/rsa"
)

func sign(m *dns.Msg) *dns.Msg {
        sg := new(dns.RR_RRSIG)
        sg.Hdr = dns.RR_Header{"www.example.org.", dns.TypeRRSIG, dns.ClassINET, 14400, 0}
        sg.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
        sg.Inception = 1293942305  // date -u '+%s' -d"2011-01-02 04:25:05"
        sg.KeyTag = pubkey.KeyTag()   // Get the keyfrom the Key
        sg.SignerName = pubkey.Hdr.Name
        sg.Algorithm = dns.AlgRSASHA256

        if len(m.Answer) > 0 {
                // sign the first record
                an := m.Answer[0]
                sg.TypeCovered = an.Header().Rrtype
                sg.Labels = dns.LabelCount(an.Header().Name)
                sg.OrigTtl = an.Header().Ttl
                switch p:=privkey.(type) {
                        case *rsa.PrivateKey:
                        sg.Sign(p, []dns.RR{an})
                }
        }
        m.Answer = append(m.Answer, sg)
        return m
}

func match(m *dns.Msg, d int) (*dns.Msg, bool) {
	// Matching criteria
        switch d {
        case IN:
                // nothing
        case OUT:
                // Note that when sending back only the mangling is important
                // the actual return code of these function isn't checked by
                // funkensturm
        }

	// Packet Mangling
	switch d {
	case IN:
		// nothing
	case OUT:
                if m.Question[0].Name == "www.example.org." {
                        // On the way out sign the packet
                        m = sign(m) // keys are global
                }
	}
	return m, true
}

func send(m *dns.Msg, ok bool) *dns.Msg {
	switch ok {
	case true, false:
		qr[0] <- resolver.Msg{m, nil, nil}
		in := <-qr[0]
		return in.Dns
	}
	return nil
}

var pubkey *dns.RR_DNSKEY
var privkey dns.PrivateKey

func setup() bool {
        privdata := `Private-key-format: v1.3
Algorithm: 5 (RSASHA1)
Modulus: AaTnz33zSgSIWzUBSJwerZiUdsTmfQNaB+AKpN8FnVlhGOfabJ6ZCi123hjOr3ucE/LWfPGtmEppuFf2dmuJW/yO6s8td5q5b81PUOt+uPMNBGJ1T4DUO8sOQQp4SXw76Q7KIgcrj2RSuNt9qv3JC4VlQB6j7bgVF8er2gbKxbvR
PublicExponent: AQAB
PrivateExponent: /IkdBCupeEi7uHS5tPnvHAHPtNm5nf4xhWm9fBYpT0wjnlB+JTYbViXgoa+4uAhwK54nPvXxzovZz+UPLfwvFBoG3D0vYS+M9WWOBCnEuDK0MfcBWfTE2hlV13xDll1o7Pj/fvpRQ7paBhjpP6uBwlVI1vH6GR9kNXQRfWK1NQU=
Prime1: AdG+8ixEeDzHKI2GRD7lGhrQ8EzN4Tc0mek1u6ioFZ0imohaPqtqNq7RWVo35cWuvYflhFQYzFn99HGRvfGfDv8=
Prime2: 51psvlotBXuaqzrgfb5I6u7DG9JhU5WO68PZf1RMmq2e2xLvKvDGXCP5oFur9AOsHdbmahnzgFC1s18vg7kFLw==
Exponent1: glXRJ5oxm7CQJKrCRmeOmpqF5Lhooi5SM/UZguUmx0Z7wFSg3Q9oJhvnyVuDLYLs/y63jWEzLqvm0DFc2lUMuQ==
Exponent2: Aq3qan3y3Yhj7y28YdhtUcM4IT9bfzNRN2vKPg5E4Nm36EOc33twYKrN/kxxfl74hFPz0TDBwC+vGwe0LitbYw==
Coefficient: AZX3xIGzo/3fw4ouA6nAjpiWGpTK+OdFRkZtvbmzwgqnFDQopB0SweVnd1shpKCXkPTkdvpLTdmhU/84CW5m7cQ=
Created: 20110122104659
Publish: 20110122104659
Activate: 20110122104659`
        pubkey = new(dns.RR_DNSKEY)
        privkey, _ = pubkey.PrivateKeySetString(privdata)
        pubkey.Hdr = dns.RR_Header{"miek.nl.", dns.TypeDNSKEY, dns.ClassINET, 3600, 0}
        pubkey.Protocol = 3
        pubkey.Flags = 256
        return true
}

// Return the configration
func funkensturm() *Funkensturm {
	f := new(Funkensturm)

	f.Setup = setup

	f.Matches = make([]Match, 1)
	f.Matches[0].Op = AND
	f.Matches[0].Func = match

	f.Actions = make([]Action, 1)
	f.Actions[0].Func = send
	return f
}
