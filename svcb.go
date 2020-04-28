package dns

import (
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"strings"
)

// Everything valid for SVCB is applicable to HTTPSSVC too
// except that for HTTPS, HTTPSSVC must be used
// and HTTPSSVC signifies that connections can be made over HTTPS

// Keys defined in draft-ietf-dnsop-svcb-httpssvc-02 Section 11.1.2
const (
	SVCKEY0            = 0 // RESERVED
	SVCALPN            = 1
	SVCNO_DEFAULT_ALPN = 2
	SVCPORT            = 3
	SVCIPV4HINT        = 4
	SVCESNICONFIG      = 5
	SVCIPV6HINT        = 6
	SVCKEY65535        = (1 << 16) - 1 // RESERVED
)

// Keys in this inclusive range are recommended
// for private use. Their names are in the format
// of keyNNNNN, for example 65283 is named key65283
const (
	SVC_PRIVATE_LOWER = 65280
	SVC_PRIVATE_UPPER = 65534
)

var svcKeyToString = map[uint16]string{
	SVCALPN:            "alpn",
	SVCNO_DEFAULT_ALPN: "no-default-alpn",
	SVCPORT:            "port",
	SVCIPV4HINT:        "ipv4hint",
	SVCESNICONFIG:      "esniconfig",
	SVCIPV6HINT:        "ipv6hint",
}

var svcStringToKey = map[string]uint16{
	"alpn":            SVCALPN,
	"no-default-alpn": SVCNO_DEFAULT_ALPN,
	"port":            SVCPORT,
	"ipv4hint":        SVCIPV4HINT,
	"esniconfig":      SVCESNICONFIG,
	"ipv6hint":        SVCIPV6HINT,
}

// SvcKeyToString serializes keys in presentation format.
// Returns empty string for reserved keys.
func SvcKeyToString(svcKey uint16) string {
	x := svcKeyToString[svcKey]
	if len(x) != 0 {
		return x
	}
	if svcKey == 0 || svcKey == 65535 {
		return ""
	}
	return "key" + strconv.FormatInt(int64(svcKey), 10)
}

// svcStringToKey returns SvcValueKey numerically.
// Accepts keyNNN... unless N == 0 or 65535.
func SvcStringToKey(str string) uint16 {
	if strings.HasPrefix(str, "key") {
		a, err := strconv.ParseUint(str[3:], 10, 16)
		// no leading zeros
		if err != nil || a == 65535 || str[4] == '0' {
			return 0
		}
		return uint16(a)
	}
	return svcStringToKey[str]
}

func (rr *SVCB) parse(c *zlexer, o string) *ParseError {
	l, _ := c.Next()
	i, e := strconv.ParseUint(l.token, 10, 16)
	if e != nil || l.err {
		return &ParseError{"", "bad svc Priority", l}
	}
	rr.Priority = uint16(i)

	c.Next()        // zBlank
	l, _ = c.Next() // zString
	rr.Target = l.token

	name, nameOk := toAbsoluteName(l.token, o)
	if l.err || !nameOk {
		return &ParseError{"", "bad svc Target", l}
	}
	rr.Target = name

	// Values (if any)
	l, _ = c.Next()
	var xs []SvcKeyValue
	for l.value != zNewline && l.value != zEOF {
		switch l.value {
		// This consumes at least, including up to the first equality sign
		case zString:
			// In key=value pairs, value doesn't have to be quoted
			// unless value contains whitespace.
			// And keys don't need include values.
			// Keys with equality sign after them
			// don't need values either.
			z := l.token

			idx := strings.IndexByte(z, '=')
			key := ""
			val := ""
			var key_value SvcKeyValue
			// Key with no value and no equality sign
			if idx == -1 {
				key = z
				key_value = makeSvcKeyValue(SvcStringToKey(key))
				if key_value == nil {
					return &ParseError{"", "svc invalid key", l}
				}
			} else {
				if idx == 0 {
					return &ParseError{"", "no valid svc key found", l}
				}
				val = z[idx+1:]
				key = z[0:idx]

				key_value = makeSvcKeyValue(SvcStringToKey(key))
				if key_value == nil {
					return &ParseError{"", "svc invalid key", l}
				}

				if len(val) == 0 {
					// We have a key and an equality sign
					// Maybe we have nothing after "="
					// or we have a double quote
					l, _ = c.Next()
					if l.value == zQuote {
						l, _ = c.Next()
						switch l.value {
						case zString:
							// We have a value in double quotes
							val = l.token
							l, _ = c.Next()
							if l.value != zQuote {
								return &ParseError{"", "svc unterminated value", l}
							}
						case zQuote:
							// There's nothing in double quotes
						default:
							return &ParseError{"", "svc invalid value", l}
						}
					}
				}
			}
			if err := key_value.Read(val); err != nil {
				return &ParseError{"", err.Error(), l}
			}
			xs = append(xs, key_value)
		case zQuote:
			return &ParseError{"", "svc key can't contain double quotes", l}
		case zBlank:
		default:
			return &ParseError{"", "bad svc Values", l}
		}
		l, _ = c.Next()
	}
	rr.Value = xs
	if rr.Priority == 0 && len(xs) > 0 {
		return &ParseError{"", "svc aliasform can't have values", l}
	}
	return nil
}

// makeSvcKeyValue returns a SvcKeyValue with the key
// or nil if a reserved key is used.
func makeSvcKeyValue(code uint16) SvcKeyValue {
	switch code {
	case SVCALPN:
		return new(SVC_ALPN)
	case SVCNO_DEFAULT_ALPN:
		return new(SVC_NO_DEFAULT_ALPN)
	case SVCPORT:
		return new(SVC_PORT)
	case SVCIPV4HINT:
		return new(SVC_IPV4HINT)
	case SVCESNICONFIG:
		return new(SVC_ESNICONFIG)
	case SVCIPV6HINT:
		return new(SVC_IPV6HINT)
	default:
		if code == 0 || code == 65535 {
			return nil
		}
		e := new(SVC_LOCAL)
		e.Code = code
		return e
	}
}

// SVCB RR. TODO See RFC xxxx (https://tools.ietf.org/html/draft-ietf-dnsop-svcb-httpssvc-02)
// The one with smallest priority SHOULD be given preference.
// Of those with equal priority, a random one SHOULD be preferred for load balancing.
type SVCB struct {
	Hdr      RR_Header
	Priority uint16
	Target   string        `dns:"domain-name"`
	Value    []SvcKeyValue `dns:"svc"` // if priority == 0 this is empty
}

// HTTPSSVCB RR. See the beginning of this file
type HTTPSSVC struct {
	SVCB
}

func (rr *HTTPSSVC) String() string {
	return rr.SVCB.String()
}

func (rr *HTTPSSVC) parse(c *zlexer, o string) *ParseError {
	return rr.SVCB.parse(c, o)
}

func (r1 *HTTPSSVC) isDuplicate(r2 RR) bool {
	return (*r1).SVCB.isDuplicate(r2)
}

// SvcKeyValue defines a key=value pair for SvcFieldValue.
// A SVCB RR can have multiple SvcKeyValues appended to it.
type SvcKeyValue interface {
	// Key returns the key code of the pair.
	Key() uint16
	// pack returns the bytes of the value data.
	pack() ([]byte, error)
	// unpack sets the data as found in the value. Is also sets
	// the length of the slice as the length of the value.
	unpack([]byte) error
	// String returns the string representation of the value.
	String() string
	// Read sets the data the string representation of the value.
	Read(string) error
	// copy returns a deep-copy of the pair.
	copy() SvcKeyValue
	// len returns the length of value in the wire format.
	len() uint16
}

// SVC_ALPN pair is used to list supported connection protocols.
// Protocol ids can be found at:
// https://www.iana.org/assignments/tls-extensiontype-values/
// tls-extensiontype-values.xhtml#alpn-protocol-ids
// Basic use pattern for creating an alpn option:
//
//	o := new(dns.HTTPSSVC)
//	o.Hdr.Name = "."
//	o.Hdr.Rrtype = dns.TypeHTTPSSVC
//	e := new(dns.SVC_ALPN)
//	e.Code = dns.SVCALPN
//	e.Alpn = []string{"h2", "http/1.1"}
//	o.Value = append(o.Value, e)
type SVC_ALPN struct {
	Code uint16   // Always SVCALPN
	Alpn []string // Must not be of zero length
}

func (s *SVC_ALPN) Key() uint16       { return SVCALPN }
func (s *SVC_ALPN) copy() SvcKeyValue { return &SVC_ALPN{s.Code, s.Alpn} }
func (s *SVC_ALPN) String() string    { return strings.Join(s.Alpn[:], ",") }

// TODO The spec requires the alpn keys that include \ and , are separated.
// In practice, no standard key including those exists.
// Do we need to handle that case at cost of visible complexity?

func (s *SVC_ALPN) pack() ([]byte, error) {
	// TODO Estimate
	b := make([]byte, 0, 10*len(s.Alpn))
	for _, e := range s.Alpn {
		//x := []byte(strings.ReplaceAll(strings.ReplaceAll(e, "\\", "\\\\"), ",", "\\,"))
		x := []byte(e)
		if len(x) == 0 {
			return nil, errors.New("dns: empty alpn-id")
		}
		if len(x) > 255 {
			return nil, errors.New("dns: alpn-id too long")
		}
		b = append(b, byte(len(x)))
		b = append(b, x...)
	}
	return b[:], nil
}

func (s *SVC_ALPN) unpack(b []byte) error {
	i := 0
	// TODO estimate
	alpn := make([]string, 0, len(b)/10)
	for i < len(b) {
		length := int(b[i])
		i++
		if i+length > len(b) {
			return errors.New("dns: alpn array malformed")
		}
		alpn = append(alpn, string(b[i:i+length]))
		i += length
	}
	s.Alpn = alpn
	return nil
}

func (s *SVC_ALPN) Read(b string) error {
	// TODO Standard requires len > 0 only for presentation format?
	// TODO maybe check if length = 0 or length = 255 for all of them
	// or if they contain disallowed characters?
	s.Alpn = strings.Split(b, ",")
	return nil
}

func (s *SVC_ALPN) len() uint16 {
	l := len(s.Alpn)
	for _, e := range s.Alpn {
		l += len(e)
	}
	return uint16(l)
}

// SVC_NO_DEFAULT_ALPN pair signifies no support
// for default connection protocols.
// Basic use pattern for creating a no_default_alpn option:
//
//	o := new(dns.SVCB)
//	o.Hdr.Name = "."
//	o.Hdr.Rrtype = dns.SVCB
//	e := new(dns.SVC_NO_DEFAULT_ALPN)
//	e.Code = dns.SVCNO_DEFAULT_ALPN
//	o.Value = append(o.Value, e)
type SVC_NO_DEFAULT_ALPN struct {
	Code uint16 // Always SVCNO_DEFAULT_ALPN
}

func (s *SVC_NO_DEFAULT_ALPN) Key() uint16           { return SVCNO_DEFAULT_ALPN }
func (s *SVC_NO_DEFAULT_ALPN) copy() SvcKeyValue     { return &SVC_NO_DEFAULT_ALPN{s.Code} }
func (s *SVC_NO_DEFAULT_ALPN) pack() ([]byte, error) { return []byte{}, nil }
func (s *SVC_NO_DEFAULT_ALPN) String() string        { return "" }
func (s *SVC_NO_DEFAULT_ALPN) len() uint16           { return 0 }

func (s *SVC_NO_DEFAULT_ALPN) unpack(b []byte) error {
	if len(b) != 0 {
		return errors.New("dns: no_default_alpn should have no value")
	}
	return nil
}

func (s *SVC_NO_DEFAULT_ALPN) Read(b string) error {
	if len(b) != 0 {
		return errors.New("dns: no_default_alpn should have no value")
	}
	return nil
}

// SVC_PORT pair defines the port for connection.
// Basic use pattern for creating a port option:
//
//	o := new(dns.SVCB)
//	o.Hdr.Name = "."
//	o.Hdr.Rrtype = dns.SVCB
//	e := new(dns.SVC_PORT)
//	e.Code = dns.SVCPORT
//	e.Port = 80
//	o.Value = append(o.Value, e)
type SVC_PORT struct {
	Code uint16 // Always SVCPORT
	Port uint16
}

func (s *SVC_PORT) Key() uint16       { return SVCPORT }
func (s *SVC_PORT) String() string    { return strconv.FormatUint(uint64(s.Port), 10) }
func (s *SVC_PORT) copy() SvcKeyValue { return &SVC_PORT{s.Code, s.Port} }
func (s *SVC_PORT) len() uint16       { return 2 }

func (s *SVC_PORT) unpack(b []byte) error {
	if len(b) != 2 {
		return errors.New("dns: bad port")
	}
	s.Port = binary.BigEndian.Uint16(b[0:])
	return nil
}

func (s *SVC_PORT) pack() ([]byte, error) {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b[0:], s.Port)
	return b, nil
}

func (s *SVC_PORT) Read(b string) error {
	port, err := strconv.ParseUint(b, 10, 16)
	if err != nil {
		return errors.New("dns: bad port")
	}
	s.Port = uint16(port)
	return nil
}

// SVC_IPV4HINT pair suggests an IPv4 address
// which may be used to open connections if A and AAAA record
// responses for SVCB's Target domain haven't been received.
// In that case, optionally, A and AAAA requests can be made,
// after which the connection to the hinted IP address may be
// terminated and a new connection may be opened.
// Basic use pattern for creating an ipv4hint option:
//
//	o := new(dns.HTTPSSVC)
//	o.Hdr.Name = "."
//	o.Hdr.Rrtype = dns.HTTPSSVC
//	e := new(dns.SVC_IPV4HINT)
//	e.Code = dns.SVCIPV4HINT
//	e.Hint = []net.IP{net.IPv4(1,1,1,1).To4()}
//  // or
//	e.Hint = []net.IP{net.ParseIP("1.1.1.1").To4()}
//	o.Value = append(o.Value, e)
type SVC_IPV4HINT struct {
	Code uint16   // Always SVCIPV4HINT
	Hint []net.IP // Always IPv4
}

func (s *SVC_IPV4HINT) Key() uint16       { return SVCIPV4HINT }
func (s *SVC_IPV4HINT) copy() SvcKeyValue { return &SVC_IPV4HINT{s.Code, s.Hint} }
func (s *SVC_IPV4HINT) len() uint16       { return 4 * uint16(len(s.Hint)) }

func (s *SVC_IPV4HINT) pack() ([]byte, error) {
	b := make([]byte, 4*len(s.Hint))
	for i, e := range s.Hint {
		x := e.To4()
		if x == nil {
			return nil, errors.New("dns: not IPv4")
		}
		copy(b[4*i:], x)
	}
	return b, nil
}

func (s *SVC_IPV4HINT) unpack(b []byte) error {
	if len(b) == 0 || len(b)%4 != 0 {
		return errors.New("dns: invalid IPv4 array")
	}
	i := 0
	x := make([]net.IP, 0, len(b)/4)
	for i < len(b) {
		x = append(x, append(make(net.IP, 0, net.IPv4len), b[i:i+4]...))
		i += 4
	}
	s.Hint = x
	return nil
}

func (s *SVC_IPV4HINT) String() string {
	var str strings.Builder
	for _, e := range s.Hint {
		x := e.To4()
		if x == nil {
			return "<nil>"
		}
		str.WriteRune(',')
		str.WriteString(e.String())
	}
	return str.String()[1:]
}

func (s *SVC_IPV4HINT) Read(b string) error {
	str := strings.Split(b, ",")
	dst := make([]net.IP, 0, len(str))
	for _, e := range str {
		ip := net.ParseIP(e)
		if ip == nil {
			return errors.New("dns: bad IP")
		}
		if ip.To4() == nil {
			return errors.New("dns: not IPv4")
		}
		dst = append(dst, ip.To4())
	}
	s.Hint = dst
	return nil
}

// TODO ECHOConfig
// SVC_ESNICONFIG pair contains the ESNIConfig structure
// defined in draft-ietf-tls-esni [RFC TODO] to encrypt
// the SNI during the client handshake.
// Basic use pattern for creating an esniconfig option:
//
//	o := new(dns.HTTPSSVC)
//	o.Hdr.Name = "."
//	o.Hdr.Rrtype = dns.HTTPSSVC
//	e := new(dns.SVC_ESNICONFIG)
//	e.Code = dns.SVCESNICONFIG
//	e.ESNI = "/wH...="
//	o.Value = append(o.Value, e)
type SVC_ESNICONFIG struct {
	Code uint16 // Always SVCESNICONFIG
	ESNI string // This string needs to be base64 encoded
}

// TODO actually []byte would be more useful?
// because to interpret it one has to decode it

func (s *SVC_ESNICONFIG) Key() uint16           { return SVCESNICONFIG }
func (s *SVC_ESNICONFIG) copy() SvcKeyValue     { return &SVC_ESNICONFIG{s.Code, s.ESNI} }
func (s *SVC_ESNICONFIG) pack() ([]byte, error) { return []byte(s.ESNI), nil }
func (s *SVC_ESNICONFIG) unpack(b []byte) error { s.ESNI = string(b); return nil }
func (s *SVC_ESNICONFIG) String() string        { return s.ESNI }
func (s *SVC_ESNICONFIG) Read(b string) error   { s.ESNI = b; return nil }
func (s *SVC_ESNICONFIG) len() uint16           { return uint16(len(s.ESNI)) }

// SVC_IPV6HINT pair suggests an IPv6 address
// which may be used to open connections if A and AAAA record
// responses for SVCB's Target domain haven't been received.
// In that case, optionally, A and AAAA requests can be made,
// after which the connection to the hinted IP address may be
// terminated and a new connection may be opened.
// Basic use pattern for creating an ipv6hint option:
//
//	o := new(dns.HTTPSSVC)
//	o.Hdr.Name = "."
//	o.Hdr.Rrtype = dns.HTTPSSVC
//	e := new(dns.SVC_IPV6HINT)
//	e.Code = dns.SVCIPV6HINT
//	e.Hint = []net.IP{net.ParseIP("2001:db8::1")}
//	o.Value = append(o.Value, e)
type SVC_IPV6HINT struct {
	Code uint16   // Always SVCIPV6HINT
	Hint []net.IP // Always IPv6
}

func (s *SVC_IPV6HINT) Key() uint16       { return SVCIPV6HINT }
func (s *SVC_IPV6HINT) copy() SvcKeyValue { return &SVC_IPV6HINT{s.Code, s.Hint} }
func (s *SVC_IPV6HINT) len() uint16       { return 16 * uint16(len(s.Hint)) }

func (s *SVC_IPV6HINT) pack() ([]byte, error) {
	b := make([]byte, 16*len(s.Hint))
	for i, e := range s.Hint {
		if len(e) != net.IPv6len {
			return nil, errors.New("dns: not IPv6")
		}
		copy(b[16*i:], e)
	}
	return b, nil
}

func (s *SVC_IPV6HINT) unpack(b []byte) error {
	if len(b) == 0 || len(b)%16 != 0 {
		return errors.New("dns: invalid IPv6 array")
	}
	i := 0
	x := make([]net.IP, 0, len(b)/16)
	for i < len(b) {
		x = append(x, append(make(net.IP, 0, net.IPv6len), b[i:i+16]...))
		i += 16
	}
	s.Hint = x
	return nil
}

func (s *SVC_IPV6HINT) String() string {
	var str strings.Builder
	for _, e := range s.Hint {
		if len(e) != net.IPv6len {
			return "<nil>"
		}
		str.WriteRune(',')
		str.WriteString(e.String())
	}
	return str.String()[1:]
}

func (s *SVC_IPV6HINT) Read(b string) error {
	str := strings.Split(b, ",")
	dst := make([]net.IP, 0, len(str))
	for _, e := range str {
		ip := net.ParseIP(e)
		if ip == nil {
			return errors.New("dns: bad IP")
		}
		if len(ip) != net.IPv6len {
			return errors.New("dns: not IPv6")
		}
		dst = append(dst, ip)
	}
	s.Hint = dst
	return nil
}

// SVC_LOCAL pair is intended for experimental/private use.
// The key is recommended to be in the range
// [SVC_PRIVATE_LOWER, SVC_PRIVATE_UPPER].
// Basic use pattern for creating an keyNNNNN option:
//
//	o := new(dns.HTTPSSVC)
//	o.Hdr.Name = "."
//	o.Hdr.Rrtype = dns.HTTPSSVC
//	e := new(dns.SVC_LOCAL)
//	e.Code = 65400
//	e.Data = []byte("abc")
//	o.Value = append(o.Value, e)
type SVC_LOCAL struct {
	Code uint16 // Never 0, 65535 or any assigned keys
	Data []byte // All byte sequences are allowed
	// For the string representation, See draft-ietf-dnsop-svcb-httpssvc
	// (TODO RFC XXXX)
	// "2.1.1.  Presentation format for SvcFieldValue key=value pairs"
	// for a full list of allowed characters. Otherwise escape codes
	// e.g. \000 for NUL and \127 for DEL are used.
}

func (s *SVC_LOCAL) Key() uint16           { return s.Code }
func (s *SVC_LOCAL) copy() SvcKeyValue     { return &SVC_LOCAL{s.Code, s.Data} }
func (s *SVC_LOCAL) pack() ([]byte, error) { return s.Data, nil }
func (s *SVC_LOCAL) unpack(b []byte) error { s.Data = b; return nil }
func (s *SVC_LOCAL) len() uint16           { return uint16(len(s.Data)) }

// Assumes that the resultant string, in DNS presentation format,
// will be enclosed in double quotes ". Therefore it doesn't
// expect whitespace to be escaped.
func (s *SVC_LOCAL) String() string {
	return string(s.Data)
	// TODO No idea how to escape escape
}

// Assumes that the input string was enclosed in double quotes.
func (s *SVC_LOCAL) Read(b string) error {
	// Allocation for the worst case
	/*	bytes := make([]byte, 0, len(b))
			str := []byte(b)
			backslash := false
			for _, e := range str {
				if e > 0x20 && e < 0x7f {
		      if e == "\"" || e == "\\" || e =
					bytes = append(bytes, e)
				}
				if e == 0x20 || e == 0x09 {
		      bytes = append(bytes, e)
				}
		  }
			return nil*/
	// No idea how it'd escape
	s.Data = []byte(b)
	return nil
}

// TODO standard seems to allow duplicate keys
// in the presentation format.
func (rr *SVCB) String() string {
	s := rr.Hdr.String() +
		strconv.Itoa(int(rr.Priority)) + " " +
		sprintName(rr.Target)
	for _, element := range rr.Value {
		s += " " + SvcKeyToString(element.Key()) +
			"=\"" + element.String() + "\""
	}
	return s
}
