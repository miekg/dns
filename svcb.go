package dns

import (
	"encoding/binary"
	"errors"
	"net"
	"sort"
	"strconv"
	"strings"
)

// Keys defined in draft-ietf-dnsop-svcb-httpssvc-02 Section 11.1.2
const (
	SVC_KEY0            = 0 // RESERVED
	SVC_ALPN            = 1
	SVC_NO_DEFAULT_ALPN = 2
	SVC_PORT            = 3
	SVC_IPV4HINT        = 4
	SVC_ECHOCONFIG      = 5
	SVC_IPV6HINT        = 6
	SVC_KEY65535        = 65535 // RESERVED
)

// Keys in this inclusive range are recommended
// for private use. Their names are in the format
// of keyNNNNN, for example 65283 is named key65283
const (
	SVC_PRIVATE_LOWER = 65280
	SVC_PRIVATE_UPPER = 65534
)

var svcKeyToString = map[uint16]string{
	SVC_ALPN:            "alpn",
	SVC_NO_DEFAULT_ALPN: "no-default-alpn",
	SVC_PORT:            "port",
	SVC_IPV4HINT:        "ipv4hint",
	SVC_ECHOCONFIG:      "echoconfig",
	SVC_IPV6HINT:        "ipv6hint",
}

var svcStringToKey = map[string]uint16{
	"alpn":            SVC_ALPN,
	"no-default-alpn": SVC_NO_DEFAULT_ALPN,
	"port":            SVC_PORT,
	"ipv4hint":        SVC_IPV4HINT,
	"echoconfig":      SVC_ECHOCONFIG,
	"ipv6hint":        SVC_IPV6HINT,
}

// SvcKeyToString takes the numerical code of an SVC key and returns its name.
// Returns an empty string for reserved keys.
// Accepts unassigned keys as well as experimental/private keys.
func SvcKeyToString(svcKey uint16) string {
	x := svcKeyToString[svcKey]
	if x != "" {
		return x
	}
	if svcKey == 0 || svcKey == 65535 {
		return ""
	}
	return "key" + strconv.FormatUint(uint64(svcKey), 10)
}

// SvcStringToKey returns the numerical code of an SVC key.
// Returns zero for reserved/invalid keys.
// Accepts unassigned keys as well as experimental/private keys.
func SvcStringToKey(str string) uint16 {
	if strings.HasPrefix(str, "key") {
		a, err := strconv.ParseUint(str[3:], 10, 16)
		// no leading zeros
		// key shouldn't be registered
		if err != nil || a == 65535 || str[3] == '0' || svcKeyToString[uint16(a)] != "" {
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
			// And keys don't need to include values.
			// Keys with an equality sign after them
			// don't need values either.
			z := l.token

			idx := strings.IndexByte(z, '=')
			key := ""
			val := ""
			var key_value SvcKeyValue
			if idx == -1 {
				// Key with no value and no equality sign
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
			if err := key_value.read(val); err != nil {
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

// makeSvcKeyValue returns an SvcKeyValue struct with the key
// or nil for reserved keys.
func makeSvcKeyValue(key uint16) SvcKeyValue {
	switch key {
	case SVC_ALPN:
		return new(SvcAlpn)
	case SVC_NO_DEFAULT_ALPN:
		return new(SvcNoDefaultAlpn)
	case SVC_PORT:
		return new(SvcPort)
	case SVC_IPV4HINT:
		return new(SvcIPv4Hint)
	case SVC_ECHOCONFIG:
		return new(SvcECHOConfig)
	case SVC_IPV6HINT:
		return new(SvcIPv6Hint)
	default:
		if key == 0 || key == 65535 {
			return nil
		}
		e := new(SvcLocal)
		e.KeyCode = key
		return e
	}
}

// SVCB RR. TODO See RFC xxxx (https://tools.ietf.org/html/draft-ietf-dnsop-svcb-httpssvc-02)
// The one with smallest priority should be given preference.
// Of those with equal priority, a random one should be preferred for load balancing.
type SVCB struct {
	Hdr      RR_Header
	Priority uint16
	Target   string        `dns:"domain-name"`
	Value    []SvcKeyValue `dns:"svc"` // if priority == 0 this is empty
}

// HTTPSSVC RR. Everything valid for SVCB applies to HTTPSSVC as well
// except that for HTTPS, HTTPSSVC must be used
// and HTTPSSVC signifies that connections can be made over HTTPS.
type HTTPSSVC struct {
	SVCB
}

func (rr *HTTPSSVC) String() string {
	return rr.SVCB.String()
}

func (rr *HTTPSSVC) parse(c *zlexer, o string) *ParseError {
	return rr.SVCB.parse(c, o)
}

// SvcKeyValue defines a key=value pair for the SVCB RR type.
// An SVCB RR can have multiple SvcKeyValues appended to it.
type SvcKeyValue interface {
	// Key returns the numerical key code.
	Key() uint16
	// pack returns the encoded value.
	pack() ([]byte, error)
	// unpack sets the value.
	unpack([]byte) error
	// String returns the string representation of the value.
	String() string
	// read sets the value to the given string representation of the value.
	read(string) error
	// copy returns a deep-copy of the pair.
	copy() SvcKeyValue
	// len returns the length of value in the wire format.
	len() uint16
}

// SvcAlpn pair is used to list supported connection protocols.
// Protocol ids can be found at:
// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
// Basic use pattern for creating an alpn option:
//
//	o := new(dns.HTTPSSVC)
//	o.Hdr.Name = "."
//	o.Hdr.Rrtype = dns.TypeHTTPSSVC
//	e := new(dns.SvcAlpn)
//	e.Alpn = []string{"h2", "http/1.1"}
//	o.Value = append(o.Value, e)
type SvcAlpn struct {
	Alpn []string // Must not be of zero length
}

func (s *SvcAlpn) Key() uint16    { return SVC_ALPN }
func (s *SvcAlpn) String() string { return strings.Join(s.Alpn[:], ",") }

// The spec requires the alpn keys including \ or , to be escaped.
// In practice, no standard key including those exists.
// Therefore those characters are not escaped.

func (s *SvcAlpn) pack() ([]byte, error) {
	// Estimate
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

func (s *SvcAlpn) unpack(b []byte) error {
	i := 0
	// Estimate
	alpn := make([]string, 0, len(b)/4)
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

func (s *SvcAlpn) read(b string) error {
	s.Alpn = strings.Split(b, ",")
	return nil
}

func (s *SvcAlpn) len() uint16 {
	l := len(s.Alpn)
	for _, e := range s.Alpn {
		l += len(e)
	}
	return uint16(l)
}

func (s *SvcAlpn) copy() SvcKeyValue {
	return &SvcAlpn{
		append(make([]string, 0, len(s.Alpn)), s.Alpn...),
	}
}

// SvcNoDefaultAlpn pair signifies no support
// for default connection protocols.
// Basic use pattern for creating a no-default-alpn option:
//
//	o := new(dns.SVCB)
//	o.Hdr.Name = "."
//	o.Hdr.Rrtype = dns.SVCB
//	e := new(dns.SvcNoDefaultAlpn)
//	o.Value = append(o.Value, e)
type SvcNoDefaultAlpn struct {
	// Empty
}

func (s *SvcNoDefaultAlpn) Key() uint16           { return SVC_NO_DEFAULT_ALPN }
func (s *SvcNoDefaultAlpn) copy() SvcKeyValue     { return &SvcNoDefaultAlpn{} }
func (s *SvcNoDefaultAlpn) pack() ([]byte, error) { return []byte{}, nil }
func (s *SvcNoDefaultAlpn) String() string        { return "" }
func (s *SvcNoDefaultAlpn) len() uint16           { return 0 }

func (s *SvcNoDefaultAlpn) unpack(b []byte) error {
	if len(b) != 0 {
		return errors.New("dns: no_default_alpn should have no value")
	}
	return nil
}

func (s *SvcNoDefaultAlpn) read(b string) error {
	if len(b) != 0 {
		return errors.New("dns: no_default_alpn should have no value")
	}
	return nil
}

// SvcPort pair defines the port for connection.
// Basic use pattern for creating a port option:
//
//	o := new(dns.SVCB)
//	o.Hdr.Name = "."
//	o.Hdr.Rrtype = dns.SVCB
//	e := new(dns.SvcPort)
//	e.Port = 80
//	o.Value = append(o.Value, e)
type SvcPort struct {
	Port uint16
}

func (s *SvcPort) Key() uint16       { return SVC_PORT }
func (s *SvcPort) String() string    { return strconv.FormatUint(uint64(s.Port), 10) }
func (s *SvcPort) copy() SvcKeyValue { return &SvcPort{s.Port} }
func (s *SvcPort) len() uint16       { return 2 }

func (s *SvcPort) unpack(b []byte) error {
	if len(b) != 2 {
		return errors.New("dns: bad port")
	}
	s.Port = binary.BigEndian.Uint16(b[0:])
	return nil
}

func (s *SvcPort) pack() ([]byte, error) {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b[0:], s.Port)
	return b, nil
}

func (s *SvcPort) read(b string) error {
	port, err := strconv.ParseUint(b, 10, 16)
	if err != nil {
		return errors.New("dns: bad port")
	}
	s.Port = uint16(port)
	return nil
}

// SvcIPv4Hint pair suggests an IPv4 address
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
//	e := new(dns.SvcIPv4Hint)
//	e.Hint = []net.IP{net.IPv4(1,1,1,1).To4()}
//  // or
//	e.Hint = []net.IP{net.ParseIP("1.1.1.1").To4()}
//	o.Value = append(o.Value, e)
type SvcIPv4Hint struct {
	Hint []net.IP // Always IPv4
}

func (s *SvcIPv4Hint) Key() uint16 { return SVC_IPV4HINT }
func (s *SvcIPv4Hint) len() uint16 { return 4 * uint16(len(s.Hint)) }

func (s *SvcIPv4Hint) pack() ([]byte, error) {
	b := make([]byte, 0, 4*len(s.Hint))
	for _, e := range s.Hint {
		x := e.To4()
		if x == nil {
			return nil, errors.New("dns: not IPv4")
		}
		b = append(b, x...)
	}
	return b, nil
}

func (s *SvcIPv4Hint) unpack(b []byte) error {
	if len(b) == 0 || len(b)%4 != 0 {
		return errors.New("dns: invalid IPv4 array")
	}
	i := 0
	x := make([]net.IP, 0, len(b)/4)
	for i < len(b) {
		x = append(x, net.IP(b[i:i+4]))
		i += 4
	}
	s.Hint = x
	return nil
}

// String returns "<nil>" if an invalid IPv4 address was encountered.
// TODO DOC Do I need full definition for doc?
func (s *SvcIPv4Hint) String() string {
	var str strings.Builder
	str.Grow(16 * len(s.Hint))
	for _, e := range s.Hint {
		x := e.To4()
		if x == nil {
			return "<nil>"
		}
		str.WriteByte(',')
		str.WriteString(x.String())
	}
	return str.String()[1:]
}

func (s *SvcIPv4Hint) read(b string) error {
	if strings.ContainsRune(b, ':') {
		return errors.New("dns: not IPv4")
	}
	str := strings.Split(b, ",")
	dst := make([]net.IP, 0, len(str))
	for _, e := range str {
		ip := net.ParseIP(e)
		if ip == nil {
			return errors.New("dns: bad IP")
		}
		dst = append(dst, ip.To4())
	}
	s.Hint = dst
	return nil
}

func (s *SvcIPv4Hint) copy() SvcKeyValue {
	return &SvcIPv4Hint{
		append(make([]net.IP, 0, len(s.Hint)), s.Hint...),
	}
}

// SvcECHOConfig pair contains the ECHOConfig structure
// defined in draft-ietf-tls-esni [RFC TODO] to encrypt TODO
// the SNI during the client handshake.
// Basic use pattern for creating an echoconfig option:
//
//	o := new(dns.HTTPSSVC)
//	o.Hdr.Name = "."
//	o.Hdr.Rrtype = dns.HTTPSSVC
//	e := new(dns.SvcECHOConfig)
//	e.ECHO = "/wH...="
//	o.Value = append(o.Value, e)
type SvcECHOConfig struct {
	ECHO string // This string needs to be base64 encoded
}

func (s *SvcECHOConfig) Key() uint16           { return SVC_ECHOCONFIG }
func (s *SvcECHOConfig) copy() SvcKeyValue     { return &SvcECHOConfig{s.ECHO} }
func (s *SvcECHOConfig) pack() ([]byte, error) { return []byte(s.ECHO), nil }
func (s *SvcECHOConfig) unpack(b []byte) error { s.ECHO = string(b); return nil }
func (s *SvcECHOConfig) String() string        { return s.ECHO }
func (s *SvcECHOConfig) read(b string) error   { s.ECHO = b; return nil }
func (s *SvcECHOConfig) len() uint16           { return uint16(len(s.ECHO)) }

// SvcIPv6Hint pair suggests an IPv6 address
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
//	e := new(dns.SvcIPv6Hint)
//	e.Hint = []net.IP{net.ParseIP("2001:db8::1")}
//	o.Value = append(o.Value, e)
type SvcIPv6Hint struct {
	Hint []net.IP // Always IPv6
}

func (s *SvcIPv6Hint) Key() uint16 { return SVC_IPV6HINT }
func (s *SvcIPv6Hint) len() uint16 { return 16 * uint16(len(s.Hint)) }

func (s *SvcIPv6Hint) pack() ([]byte, error) {
	b := make([]byte, 0, 16*len(s.Hint))
	for _, e := range s.Hint {
		if len(e) != net.IPv6len || e.To4() != nil {
			return nil, errors.New("dns: not IPv6")
		}
		b = append(b, e...)
	}
	return b, nil
}

func (s *SvcIPv6Hint) unpack(b []byte) error {
	if len(b) == 0 || len(b)%16 != 0 {
		return errors.New("dns: invalid IPv6 array")
	}
	i := 0
	x := make([]net.IP, 0, len(b)/16)
	for i < len(b) {
		x = append(x, net.IP(b[i:i+16]))
		i += 16
	}
	s.Hint = x
	return nil
}

// String returns "<nil>" if an invalid IPv6 address was encountered.
// TODO DOC Do I need full definition for doc?
func (s *SvcIPv6Hint) String() string {
	var str strings.Builder
	str.Grow(40 * len(s.Hint))
	for _, e := range s.Hint {
		if e.To4() != nil {
			return "<nil>"
		}
		str.WriteByte(',')
		str.WriteString(e.String())
	}
	return str.String()[1:]
}

func (s *SvcIPv6Hint) read(b string) error {
	if strings.ContainsRune(b, '.') {
		return errors.New("dns: not IPv6")
	}
	str := strings.Split(b, ",")
	dst := make([]net.IP, 0, len(str))
	for _, e := range str {
		ip := net.ParseIP(e)
		if ip == nil {
			return errors.New("dns: bad IP")
		}
		dst = append(dst, ip)
	}
	s.Hint = dst
	return nil
}

func (s *SvcIPv6Hint) copy() SvcKeyValue {
	return &SvcIPv6Hint{
		append(make([]net.IP, 0, len(s.Hint)), s.Hint...),
	}
}

// SvcLocal pair is intended for experimental/private use.
// The key is recommended to be in the range
// [SVC_PRIVATE_LOWER, SVC_PRIVATE_UPPER].
// Basic use pattern for creating a keyNNNNN option:
//
//	o := new(dns.HTTPSSVC)
//	o.Hdr.Name = "."
//	o.Hdr.Rrtype = dns.HTTPSSVC
//	e := new(dns.SvcLocal)
//	e.KeyCode = 65400
//	e.Data = []byte("abc")
//	o.Value = append(o.Value, e)
type SvcLocal struct {
	KeyCode uint16 // Never 0, 65535 or any assigned keys
	Data    []byte // All byte sequences are allowed
	// For the string representation, See draft-ietf-dnsop-svcb-httpssvc
	// (TODO RFC XXXX)
	// "2.1.1.  Presentation format for SvcFieldValue key=value pairs"
	// for a full list of allowed characters. Otherwise escape codes
	// e.g. \000 for NUL and \127 for DEL are used.
}

func (s *SvcLocal) Key() uint16           { return s.KeyCode }
func (s *SvcLocal) pack() ([]byte, error) { return s.Data, nil }
func (s *SvcLocal) unpack(b []byte) error { s.Data = b; return nil }
func (s *SvcLocal) len() uint16           { return uint16(len(s.Data)) }

// String escapes whitespaces too, which is not required when
// the result would be enclosed in double quotes. TODO Is this doc fine?
// do i need definition
func (s *SvcLocal) String() string {
	var str strings.Builder
	str.Grow(4 * len(s.Data))
	for _, e := range s.Data {
		if (0x1f < e && e < 0x7f) || e == 0x09 {
			switch e {
			case '"':
				fallthrough
			case ';':
				fallthrough
			// As promised, optionally handle space
			case ' ':
				fallthrough
			// Tab
			case 0x09:
				fallthrough
			case '\\':
				str.WriteByte('\\')
				fallthrough
			default:
				str.WriteByte(e)
			}
		} else {
			str.WriteByte('\\')
			a := strconv.FormatUint(uint64(e), 10)
			switch len(a) {
			case 1:
				str.WriteByte('0')
				fallthrough
			case 2:
				str.WriteByte('0')
				fallthrough
			default:
				str.WriteString(a)
			}
		}
	}
	return str.String()
}

func (s *SvcLocal) read(b string) error {
	bytes := make([]byte, 0, len(b))
	i := 0
	for i < len(b) {
		if b[i] == '\\' {
			if i+1 == len(b) {
				return errors.New("dns: svc private/experimental key" +
					" escape unterminated")
			}
			if isDigit(b[i+1]) {
				if i+3 < len(b) && isDigit(b[i+2]) && isDigit(b[i+3]) {
					a, err := strconv.ParseUint(b[i+1:i+4], 10, 8)
					if err == nil {
						i += 4
						bytes = append(bytes, byte(a))
						continue
					}
				}
				return errors.New("dns: svc private/experimental key" +
					" invalid escaped octet")
			} else {
				bytes = append(bytes, b[i+1])
				i += 2
			}
		} else {
			bytes = append(bytes, b[i])
			i++
		}
	}
	s.Data = bytes
	return nil
}

func (s *SvcLocal) copy() SvcKeyValue {
	return &SvcLocal{s.KeyCode,
		append(make([]byte, 0, len(s.Data)), s.Data...),
	}
}

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

// areSvcPairArraysEqual checks if SvcKeyValue arrays are equal
// after sorting them. arrA and arrB have equal lengths,
// otherwise zduplicate.go wouldn't call this function.
func areSvcPairArraysEqual(arrA []SvcKeyValue, arrB []SvcKeyValue) bool {
	a := append(make([]SvcKeyValue, 0, len(arrA)), arrA...)
	b := append(make([]SvcKeyValue, 0, len(arrB)), arrB...)
	sort.Slice(a, func(i, j int) bool {
		return a[i].Key() < a[j].Key()
	})
	sort.Slice(b, func(i, j int) bool {
		return b[i].Key() < b[j].Key()
	})
	for i, e := range a {
		if e.Key() != b[i].Key() {
			return false
		}
		b1, err1 := e.pack()
		b2, err2 := b[i].pack()
		if err1 != nil || err2 != nil || len(b1) != len(b2) {
			return false
		}
		for bi, x := range b1 {
			if x != b2[bi] {
				return false
			}
		}
	}
	return true
}
