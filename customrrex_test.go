package dns_test

import (
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"log"
	"net"
)

const TypeAPAIR = 0x0F99

type APAIR struct {
	addr [2]net.IP
}

func NewAPAIR() dns.PrivateRdata { return new(APAIR) }

func (rd *APAIR) String() string { return rd.addr[0].String() + " " + rd.addr[1].String() }
func (rd *APAIR) ParseTextSlice(txt []string) error {
	if len(txt) != 2 {
		return errors.New("Two addresses required for APAIR")
	}
	for i, s := range txt {
		ip := net.ParseIP(s)
		if ip == nil {
			return errors.New("Invalid IP in APAIR text representation")
		}
		rd.addr[i] = ip
	}
	return nil
}

func (rd *APAIR) WriteByteSlice(buf []byte) (int, error) {
	b := append([]byte(rd.addr[0]), []byte(rd.addr[1])...)
	n := copy(buf, b)
	if n != len(b) {
		return n, dns.ErrBuf
	}
	return n, nil
}

func (rd *APAIR) ParseByteSlice(buf []byte) (int, error) {
	ln := net.IPv4len * 2
	if len(buf) != ln {
		return 0, errors.New("Invalid length of APAIR rdata")
	}
	cp := make([]byte, ln)
	copy(cp, buf) // clone bytes to use them in IPs

	rd.addr[0] = net.IP(cp[:3])
	rd.addr[1] = net.IP(cp[4:])

	return len(buf), nil
}

func (rd *APAIR) PasteRdata(dest dns.PrivateRdata) error {
	cp := make([]byte, rd.RdataLen())
	_, err := rd.WriteByteSlice(cp)
	if err != nil {
		return err
	}

	d := dest.(*APAIR)
	d.addr[0] = net.IP(cp[:3])
	d.addr[1] = net.IP(cp[4:])
	return nil
}

func (rd *APAIR) RdataLen() int {
	return net.IPv4len * 2
}

func ExampleNewPrivateRR() {
	dns.NewPrivateRR("APAIR", TypeAPAIR, NewAPAIR)
	defer dns.DelPrivateRR(TypeAPAIR)

	rr, err := dns.NewRR("miek.nl. APAIR (1.2.3.4    1.2.3.5)")
	if err != nil {
		log.Fatal("Could not parse APAIR record: ", err)
	}
	fmt.Println(rr)
	// Output: miek.nl.	3600	IN	APAIR	1.2.3.4 1.2.3.5

	m := new(dns.Msg)
	m.Id = 12345
	m.SetQuestion("miek.nl.", TypeAPAIR)
	m.Answer = append(m.Answer, rr)

	fmt.Println(m)
	// ;; opcode: QUERY, status: NOERROR, id: 12345
	// ;; flags: rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
	//
	// ;; QUESTION SECTION:
	// ;miek.nl.	IN	 APAIR
	//
	// ;; ANSWER SECTION:
	// miek.nl.	3600	IN	APAIR	1.2.3.4 1.2.3.5
}
