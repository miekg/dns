package dns

import (
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
	if svcKey == 0 || svcKey == 65536 {
		return ""
	}
	return "key" + strconv.FormatInt(int64(svcKey), 10)
}

// svcStringToKey returns SvcValueKey numerically.
// Accepts keyNNN... unless N == 0 or 65535.
func SvcStringToKey(str string) uint16 {
	if strings.HasPrefix(str, "key") {
		a, err := strconv.ParseUint(str[3:], 10, 16)
		if err != nil || a == 65536 {
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
		return &ParseError{"", "bad SVCB Priority", l}
	}
	rr.Priority = uint16(i)

	c.Next()        // zBlank
	l, _ = c.Next() // zString
	rr.Target = l.token

	name, nameOk := toAbsoluteName(l.token, o)
	if l.err || !nameOk {
		return &ParseError{"", "bad SVCB Target", l}
	}
	rr.Target = name

	// Values (if any)
	l, _ = c.Next()
	var xs []SvcKeyValue
	xi := 0
	// If possibly the last value is delayed
	lastHasNoValue := false
	quoteCount := 0
	for l.value != zNewline && l.value != zEOF {
		switch l.value {
		// This consumes at least, including up to the first equality sign
		case zString:
			// In key=value pairs, value doesn't have to be quoted
			// Unless value contains whitespace
			// And keys don't need include values
			// Keys with equality sign after them
			// don't need values either
			z := l.token
			if quoteCount == 1 {
				if !lastHasNoValue {
					return &ParseError{"", "corrupted key=value pairs", l}
				}
				xs[xi-1].SvcParamValue = z
				lastHasNoValue = false
			} else {
				idx := strings.IndexByte(z, '=')
				key := ""
				val := ""
				if idx == -1 {
					lastHasNoValue = false
					key = z
				} else {
					if idx == 0 {
						return &ParseError{"", "no valid key found", l}
					}
					val = z[idx+1:]
					key = z[0:idx]
					if len(val) == 0 {
						lastHasNoValue = true
					}
				}
				code := SvcStringToKey(key)
				switch code {
				case SVCALPN:
					e := new(SVC_ALPN)
					if err := e.Read(val); err != nil {
						return nil, len(msg), err
					}
					xs = append(xs, e)
				case SVCNO_DEFAULT_ALPN:
					e := new(SVC_NO_DEFAULT_ALPN)
					if err := e.Read(val); err != nil {
						return nil, len(msg), err
					}
					xs = append(xs, e)
				case SVCPORT:
					e := new(SVC_PORT)
					if err := e.Read(val); err != nil {
						return nil, len(msg), err
					}
					xs = append(xs, e)
				case SVCIPV4HINT:
					e := new(SVC_IPV4HINT)
					if err := e.Read(val); err != nil {
						return nil, len(msg), err
					}
					xs = append(xs, e)
				case SVCESNICONFIG:
					e := new(SVC_ESNICONFIG)
					if err := e.Read(val); err != nil {
						return nil, len(msg), err
					}
					xs = append(xs, e)
				case SVCIPV6HINT:
					e := new(SVC_IPV6HINT)
					if err := e.Read(val); err != nil {
						return nil, len(msg), err
					}
					xs = append(xs, e)
				default:
					if code == 0 {
						return &ParseError{"", "reserved or unrecognized key used", l}
					}
					e := new(SVC_LOCAL)
					e.Code = code
					if err := e.Read(val); err != nil {
						return nil, len(msg), err
					}
					xs = append(xs, e)
				}
				xi++
			}
		case zQuote:
			quoteCount++
			if quoteCount == 2 {
				lastHasNoValue = false
			} else if quoteCount == 3 {
				return &ParseError{"", "bad value quotation", l}
			}
		case zBlank:
			lastHasNoValue = false
			quoteCount = 0
		default:
			return &ParseError{"", "bad SVCB Values", l}
		}
		l, _ = c.Next()
	}
	rr.Value = xs
	return nil
}

// SVCB RR. See RFC xxxx (https://tools.ietf.org/html/draft-ietf-dnsop-svcb-httpssvc-02)
// TODO Named ESNI and numbered 0xff9f = 65439 according to draft-ietf-tls-esni-05
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
	// " and ; and and \ are escaped TODO MAYBE REMOVE
	String() string
	// Read sets the data the string representation of the value.
	Read(string) error
	// copy returns a deep-copy of the pair.
	copy() SvcKeyValue
}

// SVC_ALPN pair is used to list supported connection protocols.
// Basic use pattern for creating an alpn option:
//
//	o := new(dns.HTTPSSVC)
//	o.Hdr.Name = "."
//	o.Hdr.Rrtype = dns.TypeHTTPSSVC
//	e := new(dns.SVC_ALPN)
//	e.Code = dns.SVCALPN
//	e.Nsid = "AA" TODO
//	o.Value = append(o.Value, e)
type SVC_ALPN struct {
	Code uint16 // Always SVCALPN
	Alpn string // TODO
} // TODO ALPN format

// TODO BIG ALPN format needs
// https://www.iana.org/assignments/tls-extensiontype-values/
// tls-extensiontype-values.xhtml#alpn-protocol-ids

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
	Alpn string // Always empty
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
//	e.Hint = net.IPv4(1.1.1.1)
//	o.Value = append(o.Value, e)
type SVC_IPV4HINT struct {
	Code uint16    // Always SVCIPV4HINT
	Hint net.IPNet // Always IPv4
}

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
	ESNI string // This string needs to be hex encoded
}

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
//	e.Hint = net.ParseIP("2001:db8::1")
//	o.Value = append(o.Value, e)
type SVC_IPV6HINT struct {
	Code uint16    // Always SVCIPV6HINT
	Hint net.IPNet // Always IPv6
}

// SVC_LOCAL pair is intended for experimental/private use.
// The key is recommended to be in the range
// [SVC_PRIVATE_LOWER, SVC_PRIVATE_UPPER].
// Its value in presentation format
// Basic use pattern for creating an keyNNNNN option:
//
//	o := new(dns.HTTPSSVC)
//	o.Hdr.Name = "."
//	o.Hdr.Rrtype = dns.HTTPSSVC
//	e := new(dns.SVC_LOCAL)
//	e.Code = 65400
//	e.Data = "abc"
//	o.Value = append(o.Value, e)
type SVC_LOCAL struct {
	Code uint16 // Never 0, 65535 or any assigned keys
	Data string // Can contain everything a byte array can
	// TODO: Or a byte array?
	// TODO How are ", ;, \ encoded? Are they escaped
}

func (rr *SVCB) String() string {
	s := rr.Hdr.String() +
		strconv.Itoa(int(rr.Priority)) + " " +
		sprintName(rr.Target)
	for _, element := range rr.Value {
		s += " " + SvcKeyToString[element.Key()] +
			"=\"" + element.String() + "\""
	}
	return s
}
