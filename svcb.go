package dns

import (
	"encoding/binary"
	"errors"
	"net"
	"sort"
	"strconv"
	"strings"
)

type SVCBKey uint16

// Keys defined in draft-ietf-dnsop-svcb-https-02 Section 11.1.2
const (
	SVCB_MANDATORY       SVCBKey = 0
	SVCB_ALPN            SVCBKey = 1
	SVCB_NO_DEFAULT_ALPN SVCBKey = 2
	SVCB_PORT            SVCBKey = 3
	SVCB_IPV4HINT        SVCBKey = 4
	SVCB_ECHCONFIG       SVCBKey = 5
	SVCB_IPV6HINT        SVCBKey = 6
	svcb_RESERVED        SVCBKey = 65535
)

var svcbKeyToStringMap = map[SVCBKey]string{
	SVCB_ALPN:            "alpn",
	SVCB_NO_DEFAULT_ALPN: "no-default-alpn",
	SVCB_PORT:            "port",
	SVCB_IPV4HINT:        "ipv4hint",
	SVCB_ECHCONFIG:       "echconfig",
	SVCB_IPV6HINT:        "ipv6hint",
}

var svcbStringToKeyMap = reverseSVCBKeyMap(svcbKeyToStringMap)

func reverseSVCBKeyMap(m map[SVCBKey]string) map[string]SVCBKey {
	n := make(map[string]SVCBKey, len(m))
	for u, s := range m {
		n[s] = u
	}
	return n
}

// svcbKeyToString takes the numerical code of an SVCB key and returns its name.
// Returns an empty string for reserved keys.
// Accepts unassigned keys as well as experimental/private keys.
func svcbKeyToString(svcbKey SVCBKey) string {
	x := svcbKeyToStringMap[svcbKey]
	if x != "" {
		return x
	}
	if svcbKey == svcb_RESERVED {
		return ""
	}
	return "key" + strconv.FormatUint(uint64(svcbKey), 10)
}

// svcbStringToKey returns the numerical code of an SVCB key.
// Returns svcb_RESERVED for reserved/invalid keys.
// Accepts unassigned keys as well as experimental/private keys.
func svcbStringToKey(str string) SVCBKey {
	if strings.HasPrefix(str, "key") {
		a, err := strconv.ParseUint(str[3:], 10, 16)
		// no leading zeros
		// key shouldn't be registered
		if err != nil || a == 65535 || str[3] == '0' || svcbKeyToStringMap[SVCBKey(a)] != "" {
			return svcb_RESERVED
		}
		return SVCBKey(a)
	}
	return svcbStringToKeyMap[str]
}

func (rr *SVCB) parse(c *zlexer, o string) *ParseError {
	l, _ := c.Next()
	i, e := strconv.ParseUint(l.token, 10, 16)
	if e != nil || l.err {
		return &ParseError{l.token, "bad SVCB priority", l}
	}
	rr.Priority = uint16(i)

	c.Next()        // zBlank
	l, _ = c.Next() // zString
	rr.Target = l.token

	name, nameOk := toAbsoluteName(l.token, o)
	if l.err || !nameOk {
		return &ParseError{l.token, "bad SVCB Target", l}
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
				return &ParseError{l.token, "bad SVCB value quotation", l}
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
			if idx == -1 {
				// Key with no value and no equality sign
				key = z
			} else if idx == 0 {
				return &ParseError{l.token, "bad SVCB key", l}
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
								return &ParseError{l.token, "SVCB unterminated value", l}
							}
						case zQuote:
							// There's nothing in double quotes
						default:
							return &ParseError{l.token, "bad SVCB value", l}
						}
					}
				}
			}
			keyValue := makeSVCBKeyValue(svcbStringToKey(key))
			if keyValue == nil {
				return &ParseError{l.token, "bad SVCB key", l}
			}
			if err := keyValue.parse(val); err != nil {
				return &ParseError{l.token, err.Error(), l}
			}
			xs = append(xs, keyValue)
		case zQuote:
			return &ParseError{l.token, "SVCB key can't contain double quotes", l}
		case zBlank:
			canHaveNextKey = true
		default:
			return &ParseError{l.token, "bad SVCB values", l}
		}
		l, _ = c.Next()
	}
	rr.Value = xs
	if rr.Priority == 0 && len(xs) > 0 {
		return &ParseError{l.token, "SVCB aliasform can't have values", l}
	}
	return nil
}

// makeSVCBKeyValue returns an SVCBKeyValue struct with the key
// or nil for reserved keys.
func makeSVCBKeyValue(key SVCBKey) SVCBKeyValue {
	switch key {
	case SVCB_MANDATORY:
		return new(SVCBMandatory)
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
		if key == svcb_RESERVED {
			return nil
		}
		e := new(SVCBLocal)
		e.KeyCode = key
		return e
	}
}

// SVCB RR. TODO See RFC xxxx (https://tools.ietf.org/html/draft-ietf-dnsop-svcb-https-02)
// The one with smallest priority should be given preference.
// Of those with equal priority, a random one should be preferred for load balancing.
type SVCB struct {
	Hdr      RR_Header
	Priority uint16
	Target   string         `dns:"domain-name"`
	Value    []SVCBKeyValue `dns:"pairs"` // if priority == 0 this is empty
}

// HTTPS RR. Everything valid for SVCB applies to HTTPS as well
// except that for HTTPS, HTTPS must be used
// and HTTPS signifies that connections can be made over HTTPS.
type HTTPS struct {
	SVCB
}

func (rr *HTTPS) String() string {
	return rr.SVCB.String()
}

func (rr *HTTPS) parse(c *zlexer, o string) *ParseError {
	return rr.SVCB.parse(c, o)
}

// SVCBKeyValue defines a key=value pair for the SVCB RR type.
// An SVCB RR can have multiple SVCBKeyValues appended to it.
type SVCBKeyValue interface {
	// Key returns the numerical key code.
	Key() SVCBKey
	// pack returns the encoded value.
	pack() ([]byte, error)
	// unpack sets the value.
	unpack([]byte) error
	// String returns the string representation of the value.
	String() string
	// parse sets the value to the given string representation of the value.
	parse(string) error
	// copy returns a deep-copy of the pair.
	copy() SVCBKeyValue
	// len returns the length of value in the wire format.
	len() uint16
}

// SVCBMandatory pair adds to required keys that must be
// interpreted for the RR to be functional.
// Basic use pattern for creating a mandatory option:
//
//	o := new(dns.SVCB)
//	o.Hdr.Name = "."
//	o.Hdr.Rrtype = dns.TypeSVCB
//	e := new(dns.SVCBMandatory)
//	e.Code = []uint16{65403}
//	o.Value = append(o.Value, e)
//  // Then add key-value pair for key65403
type SVCBMandatory struct {
	Code []SVCBKey // Must not include mandatory
}

func (s *SVCBMandatory) Key() SVCBKey { return SVCB_MANDATORY }
func (s *SVCBMandatory) String() string {
	str := make([]string, 0, len(s.Code))
	for _, e := range s.Code {
		str = append(str, svcbKeyToString(e))
	}
	return strings.Join(str, ",")
}

func (s *SVCBMandatory) pack() ([]byte, error) {
	codes := append(make([]SVCBKey, 0, len(s.Code)), s.Code...)
	sort.Slice(codes, func(i, j int) bool {
		return codes[i] < codes[j]
	})
	b := make([]byte, 2*len(s.Code))
	for i, e := range s.Code {
		binary.BigEndian.PutUint16(b[2*i:], uint16(e))
	}
	return b, nil
}

func (s *SVCBMandatory) unpack(b []byte) error {
	if len(b)%2 != 0 {
		return errors.New("dns: bad mandatory value")
	}
	codes := make([]SVCBKey, 0, len(b)/2)
	i := 0
	for i < len(b) {
		// We assume strictly increasing order
		codes = append(codes, SVCBKey(binary.BigEndian.Uint16(b[i:])))
		i += 2
	}
	s.Code = codes
	return nil
}

func (s *SVCBMandatory) parse(b string) error {
	str := strings.Split(b, ",")
	codes := make([]SVCBKey, 0, len(str))
	for _, e := range str {
		codes = append(codes, svcbStringToKey(e))
	}
	s.Code = codes
	return nil
}

func (s *SVCBMandatory) len() uint16 {
	return uint16(2 * len(s.Code))
}

func (s *SVCBMandatory) copy() SVCBKeyValue {
	return &SVCBMandatory{
		append(make([]SVCBKey, 0, len(s.Code)), s.Code...),
	}
}

// SVCBAlpn pair is used to list supported connection protocols.
// Protocol ids can be found at:
// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
// Basic use pattern for creating an alpn option:
//
//	o := new(dns.HTTPS)
//	o.Hdr.Name = "."
//	o.Hdr.Rrtype = dns.TypeHTTPS
//	e := new(dns.SVCBAlpn)
//	e.Alpn = []string{"h2", "http/1.1"}
//	o.Value = append(o.Value, e)
type SVCBAlpn struct {
	Alpn []string
}

func (s *SVCBAlpn) Key() SVCBKey   { return SVCB_ALPN }
func (s *SVCBAlpn) String() string { return strings.Join(s.Alpn, ",") }

// The spec requires the alpn keys including \ or , to be escaped.
// In practice, no standard key including those exists.
// Therefore those characters are not escaped.

func (s *SVCBAlpn) pack() ([]byte, error) {
	// Estimate
	b := make([]byte, 0, 10*len(s.Alpn))
	for _, e := range s.Alpn {
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
	return b, nil
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

func (s *SVCBAlpn) parse(b string) error {
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

func (s *SVCBNoDefaultAlpn) Key() SVCBKey          { return SVCB_NO_DEFAULT_ALPN }
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

func (s *SVCBNoDefaultAlpn) parse(b string) error {
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

func (s *SVCBPort) Key() SVCBKey       { return SVCB_PORT }
func (s *SVCBPort) String() string     { return strconv.FormatUint(uint64(s.Port), 10) }
func (s *SVCBPort) copy() SVCBKeyValue { return &SVCBPort{s.Port} }
func (s *SVCBPort) len() uint16        { return 2 }

func (s *SVCBPort) unpack(b []byte) error {
	if len(b) != 2 {
		return errors.New("dns: bad port")
	}
	s.Port = binary.BigEndian.Uint16(b)
	return nil
}

func (s *SVCBPort) pack() ([]byte, error) {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, s.Port)
	return b, nil
}

func (s *SVCBPort) parse(b string) error {
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
//	o := new(dns.HTTPS)
//	o.Hdr.Name = "."
//	o.Hdr.Rrtype = dns.HTTPS
//	e := new(dns.SVCBIPv4Hint)
//	e.Hint = []net.IP{net.IPv4(1,1,1,1).To4()}
//  // or
//	e.Hint = []net.IP{net.ParseIP("1.1.1.1").To4()}
//	o.Value = append(o.Value, e)
type SVCBIPv4Hint struct {
	Hint []net.IP // Always IPv4
}

func (s *SVCBIPv4Hint) Key() SVCBKey { return SVCB_IPV4HINT }
func (s *SVCBIPv4Hint) len() uint16  { return uint16(4 * len(s.Hint)) }

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
		return errors.New("dns: bad array of IPv4 addresses")
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

func (s *SVCBIPv4Hint) parse(b string) error {
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
//	o := new(dns.HTTPS)
//	o.Hdr.Name = "."
//	o.Hdr.Rrtype = dns.HTTPS
//	e := new(dns.SVCBECHConfig)
//	e.ECH = "/wH...="
//	o.Value = append(o.Value, e)
type SVCBECHConfig struct {
	ECH string // This string needs to be base64 encoded
}

func (s *SVCBECHConfig) Key() SVCBKey          { return SVCB_ECHCONFIG }
func (s *SVCBECHConfig) copy() SVCBKeyValue    { return &SVCBECHConfig{s.ECH} }
func (s *SVCBECHConfig) pack() ([]byte, error) { return []byte(s.ECH), nil }
func (s *SVCBECHConfig) unpack(b []byte) error { s.ECH = string(b); return nil }
func (s *SVCBECHConfig) String() string        { return s.ECH }
func (s *SVCBECHConfig) parse(b string) error  { s.ECH = b; return nil }
func (s *SVCBECHConfig) len() uint16           { return uint16(len(s.ECH)) }

// SVCBIPv6Hint pair suggests an IPv6 address
// which may be used to open connections if A and AAAA record
// responses for SVCB's Target domain haven't been received.
// In that case, optionally, A and AAAA requests can be made,
// after which the connection to the hinted IP address may be
// terminated and a new connection may be opened.
// Basic use pattern for creating an ipv6hint option:
//
//	o := new(dns.HTTPS)
//	o.Hdr.Name = "."
//	o.Hdr.Rrtype = dns.HTTPS
//	e := new(dns.SVCBIPv6Hint)
//	e.Hint = []net.IP{net.ParseIP("2001:db8::1")}
//	o.Value = append(o.Value, e)
type SVCBIPv6Hint struct {
	Hint []net.IP // Always IPv6
}

func (s *SVCBIPv6Hint) Key() SVCBKey { return SVCB_IPV6HINT }
func (s *SVCBIPv6Hint) len() uint16  { return uint16(16 * len(s.Hint)) }

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
		return errors.New("dns: bad array of IPv6 addresses")
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

func (s *SVCBIPv6Hint) parse(b string) error {
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
//	o := new(dns.HTTPS)
//	o.Hdr.Name = "."
//	o.Hdr.Rrtype = dns.HTTPS
//	e := new(dns.SVCBLocal)
//	e.KeyCode = 65400
//	e.Data = []byte("abc")
//	o.Value = append(o.Value, e)
type SVCBLocal struct {
	KeyCode SVCBKey // Never 65535 or any assigned keys
	Data    []byte  // All byte sequences are allowed
	// For the string representation, See draft-ietf-dnsop-svcb-https
	// (TODO RFC XXXX)
	// "2.1.1.  Presentation format for SVCBFieldValue key=value pairs"
	// for a full list of allowed characters. Otherwise escape codes
	// e.g. \000 for NUL and \127 for DEL are used.
}

func (s *SVCBLocal) Key() SVCBKey          { return s.KeyCode }
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

func (s *SVCBLocal) parse(b string) error {
	bytes := make([]byte, 0, len(b))
	i := 0
	for i < len(b) {
		if b[i] == '\\' {
			if i+1 == len(b) {
				return errors.New("dns: SVCB private/experimental key" +
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
				return errors.New("dns: SVCB private/experimental key" +
					" bad escaped octet")
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
		s += " " + svcbKeyToString(element.Key()) +
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
