// Package main provides ...
package main

import (
	"dns"
	"fmt"
	"os"
	"strconv"
	"strings"
)

const (
	// Detected software types
	NSD  = "NSD"
	BIND = "BIND"

	// Vendors
	ISC       = "ISC"
	NLNETLABS = "NLnet Labs"
	MICROSOFT = "Microsoft"
)

func startParse(addr string) {
	l := &lexer{
		addr:   addr,
		client: dns.NewClient(),
		fp:     new(fingerprint),
		items:  make(chan item),
		state:  dnsAlive,
		debug:  true,
	}

	l.run()

	// Not completely sure about this code..
	for {
		item := <-l.items
		fmt.Printf("%v\n", item)
		if l.state == nil {
			break
		}
	}
}

// SendProbe creates a packet and sends it to the nameserver. It
// returns a fingerprint.
func sendProbe(c *dns.Client, addr string, f *fingerprint, q dns.Question) *fingerprint {
	m := f.toProbe(q)
	r, err := c.Exchange(m, addr)
	if err != nil {
		return errorToFingerprint(err)
	}
	return msgToFingerprint(r)
}

// This leads to strings like: "QUERY,NOERROR,qr,aa,tc,RD,ad,cd,z,1,0,0,1,DO,4096"
type fingerprint struct {
	Error              os.Error
	Opcode             int
	Rcode              int
	Response           bool
	Authoritative      bool
	Truncated          bool
	RecursionDesired   bool
	RecursionAvailable bool
	AuthenticatedData  bool
	CheckingDisabled   bool
	Zero               bool
	Question           int
	Answer             int
	Ns                 int
	Extra              int
	Do                 bool
	UDPSize            int
}

// String creates a (short) string representation of a dns message.
// If a bit is set we uppercase the name 'AD' otherwise it's lowercase 'ad'.
// This leads to strings like: "QUERY,NOERROR,qr,aa,tc,RD,ad,cd,z,1,0,0,1,DO,4096"
func (f *fingerprint) String() string {
	if f == nil {
		return "<nil>"
	}
	// Use the same order as in Perl's fpdns. But use more flags.
	s := dns.Opcode_str[f.Opcode]
	s += "," + dns.Rcode_str[f.Rcode]
	s += valueOfBool(f.Response, ",qr")
	s += valueOfBool(f.Authoritative, ",aa")
	s += valueOfBool(f.Truncated, ",tc")
	s += valueOfBool(f.RecursionDesired, ",rd")
	s += valueOfBool(f.RecursionAvailable, ",ra")
	s += valueOfBool(f.AuthenticatedData, ",ad")
	s += valueOfBool(f.CheckingDisabled, ",cd")
	s += valueOfBool(f.Zero, ",z")

	s += valueOfInt(f.Question)
	s += valueOfInt(f.Answer)
	s += valueOfInt(f.Ns)
	s += valueOfInt(f.Extra)

	s += valueOfBool(f.Do, ",do")
	s += valueOfInt(f.UDPSize)
	return s
}

// SetString set the string to fp.. todo
func (f *fingerprint) setString(str string) {
	for i, s := range strings.Split(str, ",") {
		switch i {
		case 0:
			f.Opcode = dns.Str_opcode[s]
		case 1:
			f.Rcode = dns.Str_rcode[s]
		case 2:
			f.Response = false
			if s == strings.ToUpper("qr") {
				f.Response = true
			}
		case 3:
			f.Authoritative = false
			if s == strings.ToUpper("aa") {
				f.Authoritative = true
			}
		case 4:
			f.Truncated = false
			if s == strings.ToUpper("tc") {
				f.Truncated = true
			}
		case 5:
			f.RecursionDesired = false
			if s == strings.ToUpper("rd") {
				f.RecursionDesired = true
			}
		case 6:
			f.RecursionAvailable = false
			if s == strings.ToUpper("ra") {
				f.RecursionAvailable = true
			}
		case 7:
			f.AuthenticatedData = false
			if s == strings.ToUpper("ad") {
				f.AuthenticatedData = true
			}
		case 8:
			f.CheckingDisabled = false
			if s == strings.ToUpper("cd") {
				f.CheckingDisabled = true
			}
		case 9:
			f.Zero = false
			if s == strings.ToUpper("z") {
				f.Zero = true
			}
		case 10, 11, 12, 13:
			// Can not set content of the message
		case 14:
			f.Do = false
			if s == strings.ToUpper("do") {
				f.Do = true
			}
		case 15:
			f.UDPSize = 0
			f.UDPSize = valueOfString(s)
		default:
			panic("unhandled fingerprint")
		}
	}
	return
}

func (f *fingerprint) ok() bool {
	return f.Error == nil
}

func (f *fingerprint) error() string {
	if f.Error == nil {
		panic("error is nil")
	}
	return f.Error.String()
}

func errorToFingerprint(e os.Error) *fingerprint {
	f := new(fingerprint)
	f.Error = e
	return f
}

func msgToFingerprint(m *dns.Msg) *fingerprint {
	if m == nil {
		return nil
	}
	h := m.MsgHdr
	f := new(fingerprint)

	f.Opcode = h.Opcode
	f.Rcode = h.Rcode
	f.Response = h.Response
	f.Authoritative = h.Authoritative
	f.Truncated = h.Truncated
	f.RecursionDesired = h.RecursionDesired
	f.RecursionAvailable = h.RecursionAvailable
	f.AuthenticatedData = h.AuthenticatedData
	f.CheckingDisabled = h.CheckingDisabled
	f.Zero = h.Zero

	f.Question = len(m.Question)
	f.Answer = len(m.Answer)
	f.Ns = len(m.Ns)
	f.Extra = len(m.Extra)
	f.Do = false
	f.UDPSize = 0

	for _, r := range m.Extra {
		if r.Header().Rrtype == dns.TypeOPT {
			// version is always 0 - and I cannot set it anyway
			f.Do = r.(*dns.RR_OPT).Do()
			f.UDPSize = int(r.(*dns.RR_OPT).UDPSize())
		}
	}
	return f
}

// Create a dns message from a fingerprint string and
// a DNS question. The order of a string is always the same.
// QUERY,NOERROR,qr,aa,tc,RD,ad,ad,z,1,0,0,1,DO,4096
func (f *fingerprint) toProbe(q dns.Question) *dns.Msg {
	m := new(dns.Msg)
	m.MsgHdr.Id = dns.Id()
	m.Question = make([]dns.Question, 1)
	m.Question[0] = q
	m.MsgHdr.Opcode = f.Opcode
	m.MsgHdr.Rcode = f.Rcode
	m.MsgHdr.Response = f.Response
	m.MsgHdr.Authoritative = f.Authoritative
	m.MsgHdr.Truncated = f.Truncated
	m.MsgHdr.RecursionDesired = f.RecursionDesired
	m.MsgHdr.AuthenticatedData = f.AuthenticatedData
	m.MsgHdr.CheckingDisabled = f.CheckingDisabled
	m.MsgHdr.Zero = f.Zero

	if f.Do {
		// Add an OPT section.
		m.SetEdns0(0, true)
		// We have added an OPT RR, set the size.
		m.Extra[0].(*dns.RR_OPT).SetUDPSize(uint16(f.UDPSize))
	}
	return m
}

func valueOfBool(b bool, w string) string {
	if b {
		return strings.ToUpper(w)
	}
	return strings.ToLower(w)
}

func valueOfInt(i int) string {
	return "," + strconv.Itoa(i)
}

func valueOfString(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}
