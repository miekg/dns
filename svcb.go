package dns

import (
	"sort"
	"strconv"
	"strings"
)

// Various constants used in the SVCB RR, See draft-ietf-dnsop-svcb-httpssvc-02
// Section 11.1.2
const (
	SVC_KEY0            = 0 // RESERVED
	SVC_ALPN            = 1
	SVC_NO_DEFAULT_ALPN = 2
	SVC_PORT            = 3
	SVC_IPV4HINT        = 4
	SVC_ESNICONFIG      = 5
	SVC_IPV6HINT        = 6
	SVC_KEY65535        = (1 << 16) - 1 // RESERVED
)

// Keys in this inclusive range are for private use
// Their name is keyNNNNN,
// for example 65283 is named key65283
const (
	SVC_PRIVATE_USE_LOWER_RANGE = 65280
	SVC_PRIVATE_USE_UPPER_RANGE = 65534
)

var SvcKeyToString = map[uint16]string{
	SVC_ALPN:            "alpn",
	SVC_NO_DEFAULT_ALPN: "no-default-alpn",
	SVC_PORT:            "port",
	SVC_IPV4HINT:        "ipv4hint",
	SVC_ESNICONFIG:      "esniconfig",
	SVC_IPV6HINT:        "ipv6hint",
}

var SvcStringToKey = map[string]uint16{
	"alpn":            SVC_ALPN,
	"no-default-alpn": SVC_NO_DEFAULT_ALPN,
	"port":            SVC_PORT,
	"ipv4hint":        SVC_IPV4HINT,
	"esniconfig":      SVC_ESNICONFIG,
	"ipv6hint":        SVC_IPV6HINT,
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
				numericalKey := svcStringToKey(key)
				if numericalKey == 0 {
					return &ParseError{"", "reserved key used", l}
				}
				xs = append(xs, SvcKeyValue{SvcParamKey: numericalKey,
					SvcParamValue: val})
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
	// No keys are repeated so stable sort not needed
	sort.Slice(xs, func(i, j int) bool {
		return xs[i].SvcParamKey < xs[j].SvcParamKey
	})
	rr.Value = xs
	return nil
}

// SVCB RR. See RFC xxxx (https://tools.ietf.org/html/draft-ietf-dnsop-svcb-httpssvc-02)
// Named ESNI and numbered 0xff9f = 65439 according to draft-ietf-tls-esni-05
type SVCB struct {
	Hdr      RR_Header
	Priority uint16
	Target   string        `dns:"domain-name"`
	Value    []SvcKeyValue `dns:"svc"` // if priority == 0 this is empty
}

// Those must be ordered by increasing key
// but only in wire format
type SvcKeyValue struct {
	SvcParamKey   uint16
	SvcParamValue string // DQUOTE, ";", and "\"  are escaped
} // TODO IMPORTANT Maybe we shouldn't escape them in this string?

// TODO should we de-escape?
func (rr *SVCB) String() string {
	s := rr.Hdr.String() +
		strconv.Itoa(int(rr.Priority)) + " " +
		sprintName(rr.Target)
		// TODO SvcParamKeys SHALL appear in increasing numeric order.
	for _, element := range rr.Value {
		s += " " + lenientSvcKeyToString(element.SvcParamKey) +
			"=\"" + element.SvcParamValue + "\""
	}
	return s
}

// svcKeyToString serializes SVCB key values
// return empty string if reserved/undefined
func svcKeyToString(svcKey uint16) string {
	if svcKey >= SVC_PRIVATE_USE_LOWER_RANGE && svcKey <= SVC_PRIVATE_USE_UPPER_RANGE {
		return "key" + strconv.FormatInt(int64(svcKey), 10)
	}
	// Numbers currently not defined cause the same
	// empty string return as reserved ones

	/* TODO:
	  ???
		In presentation format, values of unrecognized keys
		   SHALL be represented in wire format, using decimal escape codes (e.g.
		   \255) when necessary.
	*/

	return SvcKeyToString[svcKey]
}

// Non-conformant: attempts to serialize what can't be
// serialized as keyNNN...
func lenientSvcKeyToString(svcKey uint16) string {
	x := svcKeyToString(svcKey)
	if len(x) != 0 {
		return x
	}
	return "key" + strconv.FormatInt(int64(svcKey), 10)
}

// svcStringToKey returns SvcValueKey numerically
// Accepts keyNNN... unless N == 0 or 65535
func svcStringToKey(str string) uint16 {
	if strings.HasPrefix(str, "key") {
		a, err := strconv.ParseUint(str[3:], 10, 16)
		if err != nil || a == 65536 {
			return 0
		}
		return uint16(a)
	}
	return SvcStringToKey[str]
}
