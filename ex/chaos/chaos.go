package main

// Print the version.bind and hostname.bind for each
// address of NAMESERVER
// (c) Miek Gieben - 2011
import (
	"dns"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("%s NAMESERVER\n", os.Args[0])
		os.Exit(1)
	}
	conf, _ := dns.ClientConfigFromFile("/etc/resolv.conf")

	m := new(dns.Msg)
	m.Question = make([]dns.Question, 1)
	c := dns.NewClient()

	addr := addresses(conf, c, os.Args[1])
	if len(addr) == 0 {
		fmt.Printf("No address found for %s\n", os.Args[1])
		os.Exit(1)
	}
	for _, a := range addr {
		m.Question[0] = dns.Question{"version.bind.", dns.TypeTXT, dns.ClassCHAOS}
		in, _ := c.Exchange(m, a)
		if in != nil && len(in.Answer) > 0  {
			fmt.Printf("%v\n", in.Answer[0])
		}
		m.Question[0] = dns.Question{"hostname.bind.", dns.TypeTXT, dns.ClassCHAOS}
		in, _ = c.Exchange(m, a)
		if in != nil && len(in.Answer) > 0 {
			fmt.Printf("%v\n", in.Answer[0])
		}
	}
}

func qhandler(w dns.RequestWriter, m *dns.Msg) {
	w.Dial()
	defer w.Close()
	if err := w.Send(m); err != nil {
                w.Write(nil)
                return
        }
        r, _ := w.Receive()
	w.Write(r)
}

func addresses(conf *dns.ClientConfig, c *dns.Client, name string) []string {
	dns.HandleQueryFunc(os.Args[1], qhandler)
	dns.ListenAndQuery(nil, nil)

	m4 := new(dns.Msg)
	m4.SetQuestion(dns.Fqdn(os.Args[1]), dns.TypeA)
	m6 := new(dns.Msg)
	m6.SetQuestion(dns.Fqdn(os.Args[1]), dns.TypeAAAA)
        c.Do(m4, conf.Servers[0] + ":" + conf.Port)
        c.Do(m6, conf.Servers[0] + ":" + conf.Port)

	var ips []string
	i := 2 // two outstanding queries
forever:
	for {
		select {
		case r := <-dns.DefaultReplyChan:
			if r.Reply != nil && r.Reply.Rcode == dns.RcodeSuccess {
				for _, aa := range r.Reply.Answer {
					switch aa.(type) {
					case *dns.RR_A:
						ips = append(ips, aa.(*dns.RR_A).A.String()+":53")
					case *dns.RR_AAAA:
						ips = append(ips, "["+aa.(*dns.RR_AAAA).AAAA.String()+"]:53")
					}
				}
			} else {
				fmt.Printf("Nothing recevied for %s\n", name)
			}
			i--
			if i == 0 {
				break forever
			}
		}
	}
	return ips
}
