// Go equivalent of the "DNS & BIND" book check-soa program.
// Created by Stephane Bortzmeyer.
package main

import (
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"os"
	"strings"
	"time"
)

const (
	TIMEOUT time.Duration = 5 // seconds
)

var (
	localm *dns.Msg
	localc *dns.Client
	conf   *dns.ClientConfig
)

func localQuery(qname string, qtype uint16) (*dns.Msg, error) {
	localm.SetQuestion(qname, qtype)
	for i := range conf.Servers {
		server := conf.Servers[i]
		r, _, err := localc.Exchange(localm, server+":"+conf.Port)
		if r == nil || r.Rcode == dns.RcodeNameError || r.Rcode == dns.RcodeSuccess {
			return r, err
		}
	}
	return nil, errors.New("No name server to answer the question")
}

func main() {
	var err error
	if len(os.Args) != 2 {
		fmt.Printf("%s ZONE\n", os.Args[0])
		os.Exit(1)
	}
	conf, err = dns.ClientConfigFromFile("/etc/resolv.conf")
	if conf == nil {
		fmt.Printf("Cannot initialize the local resolver: %s\n", err)
		os.Exit(1)
	}
	localm = new(dns.Msg)
	localm.RecursionDesired = true
	localm.Question = make([]dns.Question, 1)
	localc = new(dns.Client)
	localc.ReadTimeout = TIMEOUT * 1e9
	r, err := localQuery(dns.Fqdn(os.Args[1]), dns.TypeNS)
	if r == nil {
		fmt.Printf("Cannot retrieve the list of name servers for %s: %s\n", dns.Fqdn(os.Args[1]), err)
		os.Exit(1)
	}
	if r.Rcode == dns.RcodeNameError {
		fmt.Printf("No such domain %s\n", dns.Fqdn(os.Args[1]))
		os.Exit(1)
	}
	m := new(dns.Msg)
	m.RecursionDesired = false
	m.Question = make([]dns.Question, 1)
	c := new(dns.Client)
	c.ReadTimeout = TIMEOUT * 1e9
	success := true
	numNS := 0
	for _, ans := range r.Answer {
		switch ans.(type) {
		case *dns.NS:
			nameserver := ans.(*dns.NS).Ns
			numNS += 1
			ips := make([]string, 0)
			fmt.Printf("%s : ", nameserver)
			ra, err := localQuery(nameserver, dns.TypeA)
			if ra == nil {
				fmt.Printf("Error getting the IPv4 address of %s: %s\n", nameserver, err)
				os.Exit(1)
			}
			if ra.Rcode != dns.RcodeSuccess {
				fmt.Printf("Error getting the IPv4 address of %s: %s\n", nameserver, dns.RcodeToString[ra.Rcode])
				os.Exit(1)
			}
			for _, ansa := range ra.Answer {
				switch ansa.(type) {
				case *dns.A:
					ips = append(ips, ansa.(*dns.A).A.String())
				}
			}
			raaaa, err := localQuery(nameserver, dns.TypeAAAA)
			if raaaa == nil {
				fmt.Printf("Error getting the IPv6 address of %s: %s\n", nameserver, err)
				os.Exit(1)
			}
			if raaaa.Rcode != dns.RcodeSuccess {
				fmt.Printf("Error getting the IPv6 address of %s: %s\n", nameserver, dns.RcodeToString[raaaa.Rcode])
				os.Exit(1)
			}
			for _, ansaaaa := range raaaa.Answer {
				switch ansaaaa.(type) {
				case *dns.AAAA:
					ips = append(ips, ansaaaa.(*dns.AAAA).AAAA.String())
				}
			}
			if len(ips) == 0 {
				success = false
				fmt.Printf("No IP address for this server")
			}
			for _, ip := range ips {
				m.Question[0] = dns.Question{dns.Fqdn(os.Args[1]), dns.TypeSOA, dns.ClassINET}
				nsAddressPort := ""
				if strings.ContainsAny(":", ip) {
					// IPv6 address
					nsAddressPort = "[" + ip + "]:53"
				} else {
					nsAddressPort = ip + ":53"
				}
				soa, _, err := c.Exchange(m, nsAddressPort)
				// TODO: retry if timeout? Otherwise, one lost UDP packet and it is the end
				if soa == nil {
					success = false
					fmt.Printf("%s (%s) ", ip, err)
					goto Next
				}
				if soa.Rcode != dns.RcodeSuccess {
					success = false
					fmt.Printf("%s (%s) ", ips, dns.RcodeToString[soa.Rcode])
					goto Next
				}
				if len(soa.Answer) == 0 { // May happen if the server is a recursor, not authoritative, since we query with RD=0 
					success = false
					fmt.Printf("%s (0 answer) ", ip)
					goto Next
				}
				rsoa := soa.Answer[0]
				switch rsoa.(type) {
				case *dns.SOA:
					if soa.Authoritative {
						// TODO: test if all name servers have the same serial ?
						fmt.Printf("%s (%d) ", ips, rsoa.(*dns.SOA).Serial)
					} else {
						success = false
						fmt.Printf("%s (not authoritative) ", ips)
					}
				}
			}
		Next:
			fmt.Printf("\n")
		}
	}
	if numNS == 0 {
		fmt.Printf("No NS records for \"%s\". It is probably a CNAME to a domain but not a zone\n", dns.Fqdn(os.Args[1]))
		os.Exit(1)
	}
	if success {
		os.Exit(0)
	}
	os.Exit(1)
}
