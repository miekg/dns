/* A name server which sends back the IP address of its client, the
recursive resolver. When queried for type TXT, it sends back the text
form of the address.  When queried for type A (resp. AAAA), it sends
back the IPv4 (resp. v6) address.

Similar services: whoami.ultradns.net, whoami.akamai.net. Also (but it
is not their normal goal): rs.dns-oarc.net, porttest.dns-oarc.net,
amiopen.openresolvers.org.

Stephane Bortzmeyer <stephane+grong@bortzmeyer.org>

*/

package responder

import (
	"net"
	"reflect"
	"./types"
)

// Compile-time options
const includesPort = false // If false, sends only the address for TXT queries.
// If true, includes the UDP or TCP port.
// TODO: allow to secify the Qname it must respond to

func txtRecord(client net.Addr) []byte {
	sclient := client.String()
	if !includesPort {
		tcpAddr, _ := net.ResolveTCPAddr(sclient)
		sclient = tcpAddr.IP.String()
	}
	return types.ToTXT(sclient)
}

func txtSection(qname string, client net.Addr) (result types.RR) {
	result.Name = qname
	result.Type = types.TXT
	result.Class = types.IN
	result.TTL = 0
	result.Data = txtRecord(client)
	return
}

func addressSection(qname string, client net.IP) (result types.RR) {
	result.Name = qname
	result.Type = types.A
	result.Class = types.IN
	result.TTL = 0
	result.Data = client
	return
}

func aaaaSection(qname string, client net.IP) (result types.RR) {
	result.Name = qname
	result.Type = types.AAAA
	result.Class = types.IN
	result.TTL = 0
	result.Data = client
	return
}

func Respond(query types.DNSquery, config map[string]interface{}) types.DNSresponse {
	var (
		result types.DNSresponse
	)
	result.Ansection = nil
	tcpAddr, _ := net.ResolveTCPAddr(query.Client.String())
	ipaddressV4 := tcpAddr.IP.To4()
	zonei, zoneset := config["zonename"]
	zone := ""
	if zoneset {
		zone = reflect.NewValue(zonei).(*reflect.StringValue).Get()
	}
	switch {
	case query.Qclass != types.IN:
		result.Responsecode = types.SERVFAIL
	case zone != "" && query.Qname != zone:
		result.Responsecode = types.SERVFAIL
	case query.Qtype == types.A:
		result.Responsecode = types.NOERROR
		if ipaddressV4 != nil {
			ancount := 1
			result.Ansection = make([]types.RR, ancount)
			result.Ansection[0] = addressSection(query.Qname, ipaddressV4)
		} else {
			// ancount := 0
		}
	case query.Qtype == types.AAAA:
		result.Responsecode = types.NOERROR
		if ipaddressV4 == nil {
			ancount := 1
			result.Ansection = make([]types.RR, ancount)
			result.Ansection[0] = aaaaSection(query.Qname, tcpAddr.IP)
		} else {
			// ancount := 0
		}
	case query.Qtype == types.TXT:
		result.Responsecode = types.NOERROR
		ancount := 1
		result.Ansection = make([]types.RR, ancount)
		result.Ansection[0] = txtSection(query.Qname, query.Client)
	case query.Qtype == types.ALL:
		result.Responsecode = types.NOERROR
		ancount := 2
		result.Ansection = make([]types.RR, ancount)
		result.Ansection[0] = txtSection(query.Qname, query.Client)
		if ipaddressV4 == nil {
			result.Ansection[1] = aaaaSection(query.Qname, tcpAddr.IP)
		} else {
			result.Ansection[1] = addressSection(query.Qname, ipaddressV4)
		}
	default:
		result.Responsecode = types.NOERROR
	}
	return result
}

func Init(firstoption int) {
}
