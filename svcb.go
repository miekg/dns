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
	SVCB_KEY0            = 0 // RESERVED
	SVCB_ALPN            = 1
	SVCB_NO_DEFAULT_ALPN = 2
	SVCB_PORT            = 3
	SVCB_IPV4HINT        = 4
	SVCB_ECHCONFIG       = 5
	SVCB_IPV6HINT        = 6
	SVCB_KEY65535        = 65535 // RESERVED
)

// Keys in this inclusive range are recommended
// for private use. Their names are in the format
// of keyNNNNN, for example 65283 is named key65283
const (
	SVCB_PRIVATE_LOWER = 65280
	SVCB_PRIVATE_UPPER = 65534
)

var svcbKeyToString = map[uint16]string{
	SVCB_ALPN:            "alpn",
	SVCB_NO_DEFAULT_ALPN: "no-default-alpn",
	SVCB_PORT:            "port",
	SVCB_IPV4HINT:        "ipv4hint",
	SVCB_ECHCONFIG:       "echconfig",
	SVCB_IPV6HINT:        "ipv6hint",
}

var svcbStringToKey = map[string]uint16{
	"alpn":            SVCB_ALPN,
	"no-default-alpn": SVCB_NO_DEFAULT_ALPN,
	"port":            SVCB_PORT,
	"ipv4hint":        SVCB_IPV4HINT,
	"echconfig":       SVCB_ECHCONFIG,
	"ipv6hint":        SVCB_IPV6HINT,
}

// SVCBKeyToString takes the numerical code of an SVCB key and returns its name.
// Returns an empty string for reserved keys.
// Accepts unassigned keys as well as experimental/private keys.
func SVCBKeyToString(svcbKey uint16) string {
	x := svcbKeyToString[svcbKey]
	if x != "" {
		return x
	}
	if svcbKey == 0 || svcbKey == 65535 {
		return ""
	}
	return "key" + strconv.FormatUint(uint64(svcbKey), 10)
}

// SVCBStringToKey returns the numerical code of an SVCB key.
// Returns zero for reserved/invalid keys.
// Accepts unassigned keys as well as experimental/private keys.
func SVCBStringToKey(str string) uint16 {
	if strings.HasPrefix(str, "key") {
		a, err := strconv.ParseUint(str[3:], 10, 16)
		// no leading zeros
		// key shouldn't be registered
		if err != nil || a == 65535 || str[3] == '0' || svcbKeyToString[uint16(a)] != "" {
			return 0
		}
		return uint16(a)
	}
	return svcbStringToKey[str]
}

func (rr *SVCB) parse(c *zlexer, o string) *ParseError {
	l, _ := c.Next()
	i, e := strconv.ParseUint(l.token, 10, 16)
	if e != nil || l.err {
		return &ParseError{"", "bad svb Priority", l}
	}
	rr.Priority = uint16(i)

	c.Next()        // zBlank
	l, _ = c.Next() // zString
	rr.Target = l.token

	name, nameOk := toAbsoluteName(l.token, o)
	if l.err || !nameOk {
		return &ParseError{"", "bad svcb Target", l}
	}
	rr.Target = name

	// Values (if any)
	l, _ = c.Next()
	var xs []SVCBKeyValue
	// Helps require whitespace between pairs.
	// Prevents key1000="a"key1001=...
	canHaveNextKey := true
	for l.value != zNewline && l.value != zEOF {
		switch l.value {
		case zString:
			if !canHaveNextKey {
				// The key we can now read was probably meant to be
				// a part of the last value.
				return &ParseError{"", "svcb invalid value quotation", l}
			}

			// In key=value pairs, value doesn't have to be quoted
			// unless value contains whitespace.
			// And keys don't need to include values.
			// Similarly, keys with an equality signs
			// after them don't need values.
			z := l.token

			// z includes at least up to the first equality sign
			idx := strings.IndexByte(z, '=')
			key := ""
			val := ""
			var key_value SVCBKeyValue
			if idx == -1 {
				// Key with no value and no equality sign
				key = z
			} else if idx == 0 {
				return &ParseError{"", "no valid svcb key found", l}
			} else {
				key = z[0:idx]
				val = z[idx+1:]

				if len(val) == 0 {
					// We have a key and an equality sign
					// Maybe we have nothing after "="
					// or we have a double quote
					l, _ = c.Next()
					if l.value == zQuote {
						// Only needed when value ends with double quotes
						// Any value starting with zQuote ends with it
						canHaveNextKey = false

						l, _ = c.Next()
						switch l.value {
						case zString:
							// We have a value in double quotes
							val = l.token
							l, _ = c.Next()
							if l.value != zQuote {
								return &ParseError{"", "svcb unterminated value", l}
							}
						case zQuote:
							// There's nothing in double quotes
						default:
							return &ParseError{"", "svcb invalid value", l}
						}
					}
				}
			}
			key_value = makeSVCBKeyValue(SVCBStringToKey(key))
			if key_value == nil {
				return &ParseError{"", "svcb invalid key", l}
			}
			if err := key_value.read(val); err != nil {
				return &ParseError{"", err.Error(), l}
			}
			xs = append(xs, key_value)
		case zQuote:
			return &ParseError{"", "svcb key can't contain double quotes", l}
		case zBlank:
			canHaveNextKey = true
		default:
			return &ParseError{"", "bad svcb Values", l}
		}
		l, _ = c.Next()
	}
	rr.Value = xs
	if rr.Priority == 0 && len(xs) > 0 {
		return &ParseError{"", "svcb aliasform can't have values", l}
	}
	return nil
}

// makeSVCBKeyValue returns an SVCBKeyValue struct with the key
// or nil for reserved keys.
func makeSVCBKeyValue(key uint16) SVCBKeyValue {
	switch key {
	case SVCB_ALPN:
		return new(SVCBAlpn)
	case SVCB_NO_DEFAULT_ALPN:
		return new(SVCBNoDefaultAlpn)
	case SVCB_PORT:
		return new(SVCBPort)
	case SVCB_IPV4HINT:
		return new(SVCBIPv4Hint)
	case SVCB_ECHCONFIG:
		return new(SVCBECHConfig)
	case SVCB_IPV6HINT:
		return new(SVCBIPv6Hint)
	default:
		if key == 0 || key == 65535 {
			return nil
		}
		e := new(SVCBLocal)
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
	Target   string         `dns:"domain-name"`
	Value    []SVCBKeyValue `dns:"svcb-pairs"` // if priority == 0 this is empty
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

// SVCBKeyValue defines a key=value pair for the SVCB RR type.
// An SVCB RR can have multiple SVCBKeyValues appended to it.
type SVCBKeyValue interface {
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
	copy() SVCBKeyValue
	// len returns the length of value in the wire format.
	len() uint16
}

// SVCBAlpn pair is used to list supported connection protocols.
// Protocol ids can be found at:
// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
// Basic use pattern for creating an alpn option:
//
//	o := new(dns.HTTPSSVC)
//	o.Hdr.Name = "."
//	o.Hdr.Rrtype = dns.TypeHTTPSSVC
//	e := new(dns.SVCBAlpn)
//	e.Alpn = []string{"h2", "http/1.1"}
//	o.Value = append(o.Value, e)
type SVCBAlpn struct {
	Alpn []string // Must not be of zero length
}

func (s *SVCBAlpn) Key() uint16    { return SVCB_ALPN }
func (s *SVCBAlpn) String() string { return strings.Join(s.Alpn[:], ",") }

// The spec requires the alpn keys including \ or , to be escaped.
// In practice, no standard key including those exists.
// Therefore those characters are not escaped.

func (s *SVCBAlpn) pack() ([]byte, error) {
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

func (s *SVCBAlpn) unpack(b []byte) error {
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

func (s *SVCBAlpn) read(b string) error {
	s.Alpn = strings.Split(b, ",")
	return nil
}

func (s *SVCBAlpn) len() uint16 {
	l := len(s.Alpn)
	for _, e := range s.Alpn {
		l += len(e)
	}
	return uint16(l)
}

func (s *SVCBAlpn) copy() SVCBKeyValue {
	return &SVCBAlpn{
		append(make([]string, 0, len(s.Alpn)), s.Alpn...),
	}
}

// SVCBNoDefaultAlpn pair signifies no support
// for default connection protocols.
// Basic use pattern for creating a no-default-alpn option:
//
//	o := new(dns.SVCB)
//	o.Hdr.Name = "."
//	o.Hdr.Rrtype = dns.SVCB
//	e := new(dns.SVCBNoDefaultAlpn)
//	o.Value = append(o.Value, e)
type SVCBNoDefaultAlpn struct {
	// Empty
}

func (s *SVCBNoDefaultAlpn) Key() uint16           { return SVCB_NO_DEFAULT_ALPN }
func (s *SVCBNoDefaultAlpn) copy() SVCBKeyValue    { return &SVCBNoDefaultAlpn{} }
func (s *SVCBNoDefaultAlpn) pack() ([]byte, error) { return []byte{}, nil }
func (s *SVCBNoDefaultAlpn) String() string        { return "" }
func (s *SVCBNoDefaultAlpn) len() uint16           { return 0 }

func (s *SVCBNoDefaultAlpn) unpack(b []byte) error {
	if len(b) != 0 {
		return errors.New("dns: no_default_alpn should have no value")
	}
	return nil
}

func (s *SVCBNoDefaultAlpn) read(b string) error {
	if len(b) != 0 {
		return errors.New("dns: no_default_alpn should have no value")
	}
	return nil
}

// SVCBPort pair defines the port for connection.
// Basic use pattern for creating a port option:
//
//	o := new(dns.SVCB)
//	o.Hdr.Name = "."
//	o.Hdr.Rrtype = dns.SVCB
//	e := new(dns.SVCBPort)
//	e.Port = 80
//	o.Value = append(o.Value, e)
type SVCBPort struct {
	Port uint16
}

func (s *SVCBPort) Key() uint16        { return SVCB_PORT }
func (s *SVCBPort) String() string     { return strconv.FormatUint(uint64(s.Port), 10) }
func (s *SVCBPort) copy() SVCBKeyValue { return &SVCBPort{s.Port} }
func (s *SVCBPort) len() uint16        { return 2 }

func (s *SVCBPort) unpack(b []byte) error {
	if len(b) != 2 {
		return errors.New("dns: bad port")
	}
	s.Port = binary.BigEndian.Uint16(b[0:])
	return nil
}

func (s *SVCBPort) pack() ([]byte, error) {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b[0:], s.Port)
	return b, nil
}

func (s *SVCBPort) read(b string) error {
	port, err := strconv.ParseUint(b, 10, 16)
	if err != nil {
		return errors.New("dns: bad port")
	}
	s.Port = uint16(port)
	return nil
}

// SVCBIPv4Hint pair suggests an IPv4 address
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
//	e := new(dns.SVCBIPv4Hint)
//	e.Hint = []net.IP{net.IPv4(1,1,1,1).To4()}
//  // or
//	e.Hint = []net.IP{net.ParseIP("1.1.1.1").To4()}
//	o.Value = append(o.Value, e)
type SVCBIPv4Hint struct {
	Hint []net.IP // Always IPv4
}

func (s *SVCBIPv4Hint) Key() uint16 { return SVCB_IPV4HINT }
func (s *SVCBIPv4Hint) len() uint16 { return 4 * uint16(len(s.Hint)) }

func (s *SVCBIPv4Hint) pack() ([]byte, error) {
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

func (s *SVCBIPv4Hint) unpack(b []byte) error {
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
func (s *SVCBIPv4Hint) String() string {
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

func (s *SVCBIPv4Hint) read(b string) error {
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

func (s *SVCBIPv4Hint) copy() SVCBKeyValue {
	return &SVCBIPv4Hint{
		append(make([]net.IP, 0, len(s.Hint)), s.Hint...),
	}
}

// SVCBECHConfig pair contains the ECHConfig structure
// defined in draft-ietf-tls-esni [RFC TODO] to encrypt TODO
// the SNI during the client handshake.
// Basic use pattern for creating an echconfig option:
//
//	o := new(dns.HTTPSSVC)
//	o.Hdr.Name = "."
//	o.Hdr.Rrtype = dns.HTTPSSVC
//	e := new(dns.SVCBECHConfig)
//	e.ECH = "/wH...="
//	o.Value = append(o.Value, e)
type SVCBECHConfig struct {
	ECH string // This string needs to be base64 encoded
}

func (s *SVCBECHConfig) Key() uint16           { return SVCB_ECHCONFIG }
func (s *SVCBECHConfig) copy() SVCBKeyValue    { return &SVCBECHConfig{s.ECH} }
func (s *SVCBECHConfig) pack() ([]byte, error) { return []byte(s.ECH), nil }
func (s *SVCBECHConfig) unpack(b []byte) error { s.ECH = string(b); return nil }
func (s *SVCBECHConfig) String() string        { return s.ECH }
func (s *SVCBECHConfig) read(b string) error   { s.ECH = b; return nil }
func (s *SVCBECHConfig) len() uint16           { return uint16(len(s.ECH)) }

// SVCBIPv6Hint pair suggests an IPv6 address
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
//	e := new(dns.SVCBIPv6Hint)
//	e.Hint = []net.IP{net.ParseIP("2001:db8::1")}
//	o.Value = append(o.Value, e)
type SVCBIPv6Hint struct {
	Hint []net.IP // Always IPv6
}

func (s *SVCBIPv6Hint) Key() uint16 { return SVCB_IPV6HINT }
func (s *SVCBIPv6Hint) len() uint16 { return 16 * uint16(len(s.Hint)) }

func (s *SVCBIPv6Hint) pack() ([]byte, error) {
	b := make([]byte, 0, 16*len(s.Hint))
	for _, e := range s.Hint {
		if len(e) != net.IPv6len || e.To4() != nil {
			return nil, errors.New("dns: not IPv6")
		}
		b = append(b, e...)
	}
	return b, nil
}

func (s *SVCBIPv6Hint) unpack(b []byte) error {
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
func (s *SVCBIPv6Hint) String() string {
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

func (s *SVCBIPv6Hint) read(b string) error {
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

func (s *SVCBIPv6Hint) copy() SVCBKeyValue {
	return &SVCBIPv6Hint{
		append(make([]net.IP, 0, len(s.Hint)), s.Hint...),
	}
}

// SVCBLocal pair is intended for experimental/private use.
// The key is recommended to be in the range
// [SVCB_PRIVATE_LOWER, SVCB_PRIVATE_UPPER].
// Basic use pattern for creating a keyNNNNN option:
//
//	o := new(dns.HTTPSSVC)
//	o.Hdr.Name = "."
//	o.Hdr.Rrtype = dns.HTTPSSVC
//	e := new(dns.SVCBLocal)
//	e.KeyCode = 65400
//	e.Data = []byte("abc")
//	o.Value = append(o.Value, e)
type SVCBLocal struct {
	KeyCode uint16 // Never 0, 65535 or any assigned keys
	Data    []byte // All byte sequences are allowed
	// For the string representation, See draft-ietf-dnsop-svcb-httpssvc
	// (TODO RFC XXXX)
	// "2.1.1.  Presentation format for SVCBFieldValue key=value pairs"
	// for a full list of allowed characters. Otherwise escape codes
	// e.g. \000 for NUL and \127 for DEL are used.
}

func (s *SVCBLocal) Key() uint16           { return s.KeyCode }
func (s *SVCBLocal) pack() ([]byte, error) { return s.Data, nil }
func (s *SVCBLocal) unpack(b []byte) error { s.Data = b; return nil }
func (s *SVCBLocal) len() uint16           { return uint16(len(s.Data)) }

// String escapes whitespaces too, which is not required when
// the result would be enclosed in double quotes. TODO Is this doc fine?
// do i need definition
func (s *SVCBLocal) String() string {
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
			str.WriteString(escapeByte(e))
		}
	}
	return str.String()
}

func (s *SVCBLocal) read(b string) error {
	bytes := make([]byte, 0, len(b))
	i := 0
	for i < len(b) {
		if b[i] == '\\' {
			if i+1 == len(b) {
				return errors.New("dns: svcb private/experimental key" +
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
				return errors.New("dns: svcb private/experimental key" +
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

func (s *SVCBLocal) copy() SVCBKeyValue {
	return &SVCBLocal{s.KeyCode,
		append(make([]byte, 0, len(s.Data)), s.Data...),
	}
}

func (rr *SVCB) String() string {
	s := rr.Hdr.String() +
		strconv.Itoa(int(rr.Priority)) + " " +
		sprintName(rr.Target)
	for _, element := range rr.Value {
		s += " " + SVCBKeyToString(element.Key()) +
			"=\"" + element.String() + "\""
	}
	return s
}

// areSVCBPairArraysEqual checks if SVCBKeyValue arrays are equal
// after sorting their copies. arrA and arrB have equal lengths,
// otherwise zduplicate.go wouldn't call this function.
func areSVCBPairArraysEqual(arrA []SVCBKeyValue, arrB []SVCBKeyValue) bool {
	a := append(make([]SVCBKeyValue, 0, len(arrA)), arrA...)
	b := append(make([]SVCBKeyValue, 0, len(arrB)), arrB...)
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
