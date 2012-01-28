// Package main provides ...
package main

import (
	"bufio"
	"dns"
	"os"
	"strconv"
	"strings"
)

// .,IN,NS,QUERY,NOERROR,qr,aa,tc,rd,ra,ad,cd,z,0,0,0,0,do,0,nsid

const (
	// Detected software types
	NSD        = "NSD"
	BIND       = "BIND"
	POWERDNS   = "PowerDNS"
	WINDOWSDNS = "Windows DNS"
	MARADNS    = "MaraDNS"
	NEUSTARDNS = "Neustar DNS"
	ATLAS      = "Atlas"
	YADIFA     = "Yadifa"

	// Vendors
	ISC       = "ISC"
	MARA      = "MaraDNS.org" // check
	NLNETLABS = "NLnet Labs"
	MICROSOFT = "Microsoft"
	POWER     = "PowerDNS.com"
	NEUSTAR   = "Neustar"
	VERISIGN  = "Verisign"
	EURID     = "EurID"
)

// probe creates a packet and sends it to the nameserver. It
// returns a fingerprint.
func probe(c *dns.Client, addr string, f *fingerprint) *fingerprint {
	m := f.msg()
	r, err := c.Exchange(m, addr)
	if err != nil {
		return errorToFingerprint(err)
	}
	return toFingerprint(r)
}

// This leads to strings like: "miek.nl.,IN,A,QUERY,NOERROR,qr,aa,tc,RD,ad,cd,z,1,0,0,1,DO,4096,NSID"
type fingerprint struct {
	Query              dns.Question // Question to ask or Question of the reply
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
// This leads to strings like: ".,IN,NS,QUERY,NOERROR,qr,aa,tc,RD,ad,cd,z,1,0,0,1,DO,4096,NSID"
func (f *fingerprint) String() string {
	if f == nil {
		return "<nil>"
	}
	// Use the same order as in Perl's fpdns. But use much more flags.
	var s string
	// The Question.
	if len(f.Query.Name) == 0 {
		s = "."
	} else {
		s = f.Query.Name
	}
	if _, ok := dns.Class_str[f.Query.Qclass]; ok {
		s += "," + dns.Class_str[f.Query.Qclass]
	} else {
		s += "," + "CLASS" + strconv.Itoa(int(f.Query.Qclass))
	}

	if _, ok := dns.Rr_str[f.Query.Qtype]; ok {
		s += "," + dns.Rr_str[f.Query.Qtype]
	} else {
		s += "," + "TYPE" + strconv.Itoa(int(f.Query.Qtype))
	}

	if op, ok := dns.Opcode_str[f.Opcode]; ok {
		s += "," + op
	} else { // number
		s += "," + valueOfInt(f.Opcode)
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
// without the sections' count and the EDNS0 stuff and the query
func (f *fingerprint) StringNoSections() string {
	s := strings.SplitN(f.String(), ",", 14)
	return strings.Join(s[2:13], ",")
}

// Return a new fingerprint, set from string
func newFingerprint(s string) *fingerprint {
        f := new(fingerprint)
        f.setString(s)
        return f
}

// SetString sets the strings str to the fingerprint *f.
func (f *fingerprint) setString(str string) {
	for i, s := range strings.Split(str, ",") {
		switch i {
		case 0: // question section domain name
			f.Query.Name = s
		case 1: // Qclass
			f.Query.Qclass = 0
			if c, ok := dns.Str_class[s]; ok {
				f.Query.Qclass = c
			}
		case 2: // Qtype
			f.Query.Qtype = 0
			if c, ok := dns.Str_rr[s]; ok {
				f.Query.Qtype = c
			}
		case 3:
			if op, ok := dns.Str_opcode[s]; ok {
				f.Opcode = op
			} else { // number
				f.Opcode = valueOfString(s)
			}
		case 4:
			if op, ok := dns.Str_rcode[s]; ok {
				f.Rcode = op
			} else { // number
				f.Rcode = valueOfString(s)
			}
		case 5:
			f.Response = s == strings.ToUpper("qr")
		case 6:
			f.Authoritative = s == strings.ToUpper("aa")
		case 7:
			f.Truncated = s == strings.ToUpper("tc")
		case 8:
			f.RecursionDesired = s == strings.ToUpper("rd")
		case 9:
			f.RecursionAvailable = s == strings.ToUpper("ra")
		case 10:
			f.AuthenticatedData = s == strings.ToUpper("ad")
		case 11:
			f.CheckingDisabled = s == strings.ToUpper("cd")
		case 12:
			f.Zero = s == strings.ToUpper("z")
		case 13, 14, 15, 16:
			// Can not set lenght of the section in the message
		case 17:
			f.Do = s == strings.ToUpper("do")
		case 18:
			f.UDPSize = valueOfString(s)
		case 19:
			f.Nsid = s == strings.ToUpper("nsid")
		default:
			panic("unhandled fingerprint field")
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

// Convert a Msg to a fingerprint
func toFingerprint(m *dns.Msg) *fingerprint {
	if m == nil {
		return nil
	}
	h := m.MsgHdr
	f := new(fingerprint)

	if len(m.Question) > 0 {
		f.Query.Name = m.Question[0].Name
		f.Query.Qtype = m.Question[0].Qtype
		f.Query.Qclass = m.Question[0].Qclass
	}

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
// .,IN,NS,QUERY,NOERROR,qr,aa,tc,RD,ad,ad,z,1,0,0,1,DO,4096,nsid
func (f *fingerprint) msg() *dns.Msg {
	m := new(dns.Msg)
	m.MsgHdr.Id = dns.Id()
	m.Question = make([]dns.Question, 1)
	m.Question[0] = dns.Question{f.Query.Name, f.Query.Qtype, f.Query.Qclass}
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

// Compare two fingerprints, it returns the number of differences.
func (f *fingerprint) compare(f1 *fingerprint) (diff int) {
	if f.Query.Name != f1.Query.Name {
		diff++
	}
	if f.Query.Qtype != f1.Query.Qtype {
		diff++
	}
	if f.Query.Qclass != f1.Query.Qclass {
		diff++
	}
	if f.Opcode != f1.Opcode {
		diff++
	}
	if f.Rcode != f1.Rcode {
		diff++
	}
	if f.Response != f1.Response {
		diff++
	}
	if f.Authoritative != f1.Authoritative {
		diff++
	}
	if f.Truncated != f1.Truncated {
		diff++
	}
	if f.RecursionDesired != f1.RecursionDesired {
		diff++
	}
	if f.RecursionAvailable != f1.RecursionAvailable {
		diff++
	}
	if f.AuthenticatedData != f1.AuthenticatedData {
		diff++
	}
	if f.CheckingDisabled != f1.CheckingDisabled {
		diff++
	}
	if f.Zero != f1.Zero {
		diff++
	}
	if f.Question != f1.Question {
		diff++
	}
	if f.Answer != f1.Answer {
		diff++
	}
	if f.Ns != f1.Ns {
		diff++
	}
	if f.Extra != f1.Extra {
		diff++
	}
	if f.Do != f1.Do {
		diff++
	}
	if f.UDPSize != f1.UDPSize {
		diff++
	}
	if f.Nsid != f1.Nsid {
		diff++
	}
	return
}

// Read the finger prints from the file. Lines starting with 
// # are comments. Each line should contain one fingerprint in string format.
func fingerPrintFromFile(f string) ([]*fingerprint, error) {
	r, e := os.Open(f)
	if e != nil {
		return nil, e
	}
	b := bufio.NewReader(r)
	l, p, e := b.ReadLine()
        i := 1
        prints := make([]*fingerprint, 0)
	for e == nil {
                if p {
                        return nil, nil
                }
                if l[0] != '#' {
                        prints = append(prints, newFingerprint(string(l)))
                }
		l, p, e = b.ReadLine()
                i++
	}
        return prints, nil
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
