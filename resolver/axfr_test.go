package resolver

import (
	"testing"
        "fmt"
        "dns"
)


func TestAXFR(t *testing.T) {
	res := new(Resolver)
	ch := NewXfer(res)

	res.Servers = []string{"127.0.0.1"}
	m := new(dns.Msg)
	m.Question = make([]dns.Question, 1)
	// ask something
	m.Question[0] = dns.Question{"miek.nl", dns.TypeAXFR, dns.ClassINET}

        ch <- DnsMsg{m, nil}
	for dm := range ch {
                fmt.Printf("%v\n",dm.Dns)
        }
}
