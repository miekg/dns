package dns

import (
	"encoding/binary"
	"errors"
	"net"
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
	SVC_ESNICONFIG      = 5
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
	SVC_ESNICONFIG:      "esniconfig",
	SVC_IPV6HINT:        "ipv6hint",
}

var svcStringToKey = map[string]uint16{
	"alpn":            SVC_ALPN,
	"no-default-alpn": SVC_NO_DEFAULT_ALPN,
	"port":            SVC_PORT,
	"ipv4hint":        SVC_IPV4HINT,
	"esniconfig":      SVC_ESNICONFIG,
	"ipv6hint":        SVC_IPV6HINT,
}

// SvcKeyToString serializes keys in presentation format.
// Returns empty string for reserved keys.
// Accepts unassigned keys as well as experimental/private keys.
func SvcKeyToString(svcKey uint16) string {
	x := svcKeyToString[svcKey]
	if x != "" {
		return x
	}
	if svcKey == 0 || svcKey == 65535 {
		return ""
	}
	return "key" + strconv.FormatInt(int64(svcKey), 10)
}

// SvcStringToKey returns SvcValueKey numerically.
// Accepts keyNNN... unless N == 0 or 65535.
// NNN... must not be padded with zeros.
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

// makeSvcKeyValue returns a SvcKeyValue with the key
// or nil if a reserved key is used.
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
	case SVC_ESNICONFIG:
		return new(SvcESNIConfig)
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
// The one with smallest priority SHOULD be given preference.
// Of those with equal priority, a random one SHOULD be preferred for load balancing.
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
	// read sets the data the string representation of the value.
	read(string) error
	// copy returns a deep-copy of the pair.
	copy() SvcKeyValue
	// len returns the length of value in the wire format.
	len() uint16
}

// SvcAlpn pair is used to list supported connection protocols.
// Protocol ids can be found at:
// https://www.iana.org/assignments/tls-extensiontype-values/
// tls-extensiontype-values.xhtml#alpn-protocol-ids
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
// Basic use pattern for creating a no_default_alpn option:
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
		x = append(x, append(make(net.IP, 0, net.IPv4len), b[i:i+4]...))
		i += 4
	}
	s.Hint = x
	return nil
}

func (s *SvcIPv4Hint) String() string {
	var str strings.Builder
	for _, e := range s.Hint {
		x := e.To4()
		if x == nil {
			return "<nil>"
		}
		str.WriteByte(',')
		str.WriteString(e.String())
	}
	return str.String()[1:]
}

func (s *SvcIPv4Hint) read(b string) error {
	str := strings.Split(b, ",")
	dst := make([]net.IP, 0, len(str))
	for _, e := range str {
		ip := net.ParseIP(e)
		if ip == nil {
			return errors.New("dns: bad IP")
		}
		if ip.To4() == nil || strings.ContainsRune(e, ':') {
			return errors.New("dns: not IPv4")
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

// TODO ECHOConfig
// SvcESNIConfig pair contains the ESNIConfig structure
// defined in draft-ietf-tls-esni [RFC TODO] to encrypt
// the SNI during the client handshake.
// Basic use pattern for creating an esniconfig option:
//
//	o := new(dns.HTTPSSVC)
//	o.Hdr.Name = "."
//	o.Hdr.Rrtype = dns.HTTPSSVC
//	e := new(dns.SvcESNIConfig)
//	e.ESNI = "/wH...="
//	o.Value = append(o.Value, e)
type SvcESNIConfig struct {
	ESNI string // This string needs to be base64 encoded
}

// TODO actually []byte would be more useful?
// because to interpret it one has to decode it

func (s *SvcESNIConfig) Key() uint16           { return SVC_ESNICONFIG }
func (s *SvcESNIConfig) copy() SvcKeyValue     { return &SvcESNIConfig{s.ESNI} }
func (s *SvcESNIConfig) pack() ([]byte, error) { return []byte(s.ESNI), nil }
func (s *SvcESNIConfig) unpack(b []byte) error { s.ESNI = string(b); return nil }
func (s *SvcESNIConfig) String() string        { return s.ESNI }
func (s *SvcESNIConfig) read(b string) error   { s.ESNI = b; return nil }
func (s *SvcESNIConfig) len() uint16           { return uint16(len(s.ESNI)) }

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
	b := make([]byte, 16*len(s.Hint))
	for _, e := range s.Hint {
		if len(e) != net.IPv6len {
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
		x = append(x, append(make(net.IP, 0, net.IPv6len), b[i:i+16]...))
		i += 16
	}
	s.Hint = x
	return nil
}

func (s *SvcIPv6Hint) String() string {
	var str strings.Builder
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
	str := strings.Split(b, ",")
	dst := make([]net.IP, 0, len(str))
	for _, e := range str {
		if strings.ContainsRune(e, '.') {
			return errors.New("dns: not IPv6")
		}
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

// TODO do we really need to escape space??
// Escapes whitespaces too, which is only optional when
// the result would be enclosed in double quotes.
func (s *SvcLocal) String() string {
	var str strings.Builder
	str.Grow(4 * len(s.Data))
	for _, e := range s.Data {
		if (0x19 < e && e < 0x7f) || e == 0x09 {
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
			a := strconv.FormatInt(int64(e), 10)
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

// Not checked, but duplicates aren't allowed.
// Also assumes that all keys are valid.
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

func (s *SvcLocal) copy() SvcKeyValue {
	return &SvcLocal{s.KeyCode,
		append(make([]byte, 0, len(s.Data)), s.Data...),
	}
}
