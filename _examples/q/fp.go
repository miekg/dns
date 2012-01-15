// Package main provides ...
package main

import (
	"dns"
	"fmt"
	"strconv"
	"strings"
)

const (
	// Detected software types
	NSD        = "NSD"
	BIND       = "BIND"
	POWERDNS   = "PowerDNS"
	WINDOWSDNS = "Windows DNS"
	MARADNS    = "MaraDNS"
	NEUSTARDNS = "Neustar DNS"
	ATLAS      = "Atlas"
        ULTRADNS   = "UltraDNS"

	// Vendors
	ISC       = "ISC"
	MARA      = "MaraDNS.org" // check
	NLNETLABS = "NLnet Labs"
	MICROSOFT = "Microsoft"
	POWER     = "PowerDNS.com"
	NEUSTAR   = "Neustar"
	VERISIGN  = "Verisign"
        ULTRA     = "UltraDNS"
)

func startParse(addr string) {
	l := &lexer{
		addr:      addr,
		client:    dns.NewClient(),
		fp:        new(fingerprint),
		items:     make(chan item),
		state:     dnsAlive,
		verbose:   true,
		debugging: false,
	}

	l.run()
	items := make([]item, 0)
	for {
		items = append(items, <-l.items)
		if l.state == nil {
			break
		}
	}
	// Print out what we've gathered
        fmt.Println()
	for _, i := range items {
		fmt.Printf("{%s %s}\n", itemString[i.typ], i.val)
	}
}

// SendProbe creates a packet and sends it to the nameserver. It
// returns a fingerprint.
func sendProbe(c *dns.Client, addr string, f *fingerprint, q dns.Question) (*fingerprint, dns.Question) {
	m := f.toProbe(q)
	r, err := c.Exchange(m, addr)
	if err != nil {
		return errorToFingerprint(err), dns.Question{}
	}
	return msgToFingerprint(r), r.Question[0]
}

// This leads to strings like: "QUERY,NOERROR,qr,aa,tc,RD,ad,cd,z,1,0,0,1,DO,4096,NSID"
type fingerprint struct {
	Error              error
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
	Nsid               bool
}

// String creates a (short) string representation of a dns message.
// If a bit is set we uppercase the name 'AD' otherwise it's lowercase 'ad'.
// This leads to strings like: "QUERY,NOERROR,qr,aa,tc,RD,ad,cd,z,1,0,0,1,DO,4096,NSID"
func (f *fingerprint) String() string {
	if f == nil {
		return "<nil>"
	}
	// Use the same order as in Perl's fpdns. But use more flags.
	var s string
	if op, ok := dns.Opcode_str[f.Opcode]; ok {
		s = op
	} else { // number
		s = valueOfInt(f.Opcode)
	}

	if op, ok := dns.Rcode_str[f.Rcode]; ok {
		s += "," + op
	} else { // number
		s += "," + valueOfInt(f.Rcode)
	}

	s += valueOfBool(f.Response, ",qr")
	s += valueOfBool(f.Authoritative, ",aa")
	s += valueOfBool(f.Truncated, ",tc")
	s += valueOfBool(f.RecursionDesired, ",rd")
	s += valueOfBool(f.RecursionAvailable, ",ra")
	s += valueOfBool(f.AuthenticatedData, ",ad")
	s += valueOfBool(f.CheckingDisabled, ",cd")
	s += valueOfBool(f.Zero, ",z")

	s += "," + valueOfInt(f.Question)
	s += "," + valueOfInt(f.Answer)
	s += "," + valueOfInt(f.Ns)
	s += "," + valueOfInt(f.Extra)

	s += valueOfBool(f.Do, ",do")
	s += "," + valueOfInt(f.UDPSize)
	s += valueOfBool(f.Nsid, ",nsid")
	return s
}

// fingerStringNoSections returns the strings representation
// without the sections' count and the EDNS0 stuff
func (f *fingerprint) StringNoSections() string {
	s := strings.SplitN(f.String(), ",", 11)
	return strings.Join(s[:10], ",")
}

// SetString set the string to fp.. todo
func (f *fingerprint) setString(str string) {
        println("STR:", str)
	for i, s := range strings.Split(str, ",") {
                println("I", i, "S", s)
		switch i {
		case 0:
			if op, ok := dns.Str_opcode[s]; ok {
				f.Opcode = op
			} else { // number
				f.Opcode = valueOfString(s)
			}
		case 1:
			if op, ok := dns.Str_rcode[s]; ok {
				f.Rcode = op
			} else { // number
				f.Rcode = valueOfString(s)
			}
		case 2:
			f.Response = s == strings.ToUpper("qr")
		case 3:
			f.Authoritative = s == strings.ToUpper("aa")
		case 4:
			f.Truncated = s == strings.ToUpper("tc")
		case 5:
			f.RecursionDesired = s == strings.ToUpper("rd")
		case 6:
			f.RecursionAvailable = s == strings.ToUpper("ra")
		case 7:
			f.AuthenticatedData = s == strings.ToUpper("ad")
		case 8:
			f.CheckingDisabled = s == strings.ToUpper("cd")
		case 9:
			f.Zero = s == strings.ToUpper("z")
		case 10, 11, 12, 13:
			// Can not set content of the message
		case 14:
			f.Do = s == strings.ToUpper("do")
		case 15:
			f.UDPSize = valueOfString(s)
		case 16:
			f.Nsid = s == strings.ToUpper("nsid")
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
	return f.Error.Error()
}

func errorToFingerprint(e error) *fingerprint {
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
			if len(r.(*dns.RR_OPT).Option) == 1 {
				// Only support NSID atm
				f.Nsid = r.(*dns.RR_OPT).Option[0].Code == dns.OptionCodeNSID
			}
		}
	}
	return f
}

// Create a dns message from a fingerprint string and
// a DNS question. The order of a string is always the same.
// QUERY,NOERROR,qr,aa,tc,RD,ad,ad,z,1,0,0,1,DO,4096,nsid
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
		if f.Nsid {
			m.Extra[0].(*dns.RR_OPT).SetNsid("")
		}
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
	return strconv.Itoa(i)
}

func valueOfString(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}
