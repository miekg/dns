// line 1 "zparse.rl"
package dns

// Parse RRs
// With the thankful help of gdnsd and the Go examples for Ragel.

import (
	"io"
	//	"net"
	"time"
	"strings"
	"strconv"
)

const _IOBUF = MaxMsgSize

// A Parser represents a DNS parser for a 
// particular input stream. 
type Parser struct {
	// nothing here yet
	buf []byte
}

type ParseError struct {
	Err  string
	name string
	line int
}

func (e *ParseError) Error() string {
	s := e.Err + ": \"" + e.name + "\" at line: " + strconv.Itoa(e.line)
	return s
}

// First will return the first RR found when parsing.
func (zp *Parser) First() (RR, error) {
	// defer close something
	return nil, nil
}

// NewParser creates a new DNS file parser from r.
func NewParser(r io.Reader) *Parser {
	buf := make([]byte, _IOBUF)
	n, err := r.Read(buf)
	if err != nil {
		return nil
	}
	if buf[n-1] != '\n' {
		buf[n] = '\n'
		n++
	}
	buf = buf[:n]
	p := new(Parser)
	p.buf = buf
	return p
}

// Translate the RRSIG's incep. and expir. times from 
// string values ("20110403154150") to an integer.
// Taking into account serial arithmetic (RFC 1982)
func dateToTime(s string) (uint32, error) {
	_, e := time.Parse("20060102150405", s)
	if e != nil {
		return 0, e
	}
        return 0, nil
        /*
	mod := t.Seconds() / Year68
	ti := uint32(t.Seconds() - (mod * Year68))
	return ti, nil
        */
}

// Return the rdata fields as a string slice. 
// All starting whitespace is deleted.
// If i is 0 no spaces are deleted from the final rdfs.
func fields(s string, i int) (rdf []string) {
	rdf = strings.Fields(s)
	for i, _ := range rdf {
		rdf[i] = strings.TrimSpace(rdf[i])
	}
	if i > 0 && len(rdf) > i {
		// The last rdf contained embedded spaces, glue it back together.
		for j := i; j < len(rdf); j++ {
			rdf[i-1] += rdf[j]
		}
	}
	return
}

// line 86 "zparse.go"
var z_start int = 141
var z_first_final int = 141
var z_error int = 0

var z_en_main int = 141

// line 85 "zparse.rl"

// Zone parses an DNS master zone file.
func (zp *Parser) Zone() (err error) {
	/*
		z = NewZone()
		data := string(zp.buf)
		cs, p, pe := 0, 0, len(data)
		eof := len(data)

		//        brace := false
		l := 1 // or... 0?
		mark := 0
		var hdr RR_Header

		// line 119 "zparse.go"
		cs = z_start

		// line 122 "zparse.go"
		{
			if p == pe {
				goto _test_eof
			}
			switch cs {
			case -666: // i am a hack D:
			tr33:
				// line 3 "types.rl"
				{
					rdf := fields(data[mark:p], 1)
					rr := new(RR_A)
					rr.Hdr = hdr
					rr.Hdr.Rrtype = TypeA
					rr.A = net.ParseIP(rdf[0])
					if rr.A == nil {
						return z, &ParseError{Error: "bad A", name: rdf[0], line: l}
					}
					z.PushRR(rr)
				}
				// line 112 "zparse.rl"
				{
					l++
				}
				goto st141
			tr40:
				// line 15 "types.rl"
				{
					rdf := fields(data[mark:p], 1)
					rr := new(RR_AAAA)
					rr.Hdr = hdr
					rr.Hdr.Rrtype = TypeAAAA
					rr.AAAA = net.ParseIP(rdf[0])
					if rr.AAAA == nil {
						return z, &ParseError{Error: "bad AAAA", name: rdf[0], line: l}
					}
					z.PushRR(rr)
				}
				// line 112 "zparse.rl"
				{
					l++
				}
				goto st141
			tr50:
				// line 342 "types.rl"
				{
				}
				// line 112 "zparse.rl"
				{
					l++
				}
				goto st141
			tr61:
				// line 53 "types.rl"
				{
					rdf := fields(data[mark:p], 1)
					rr := new(RR_CNAME)
					rr.Hdr = hdr
					rr.Hdr.Rrtype = TypeCNAME
					rr.Cname = rdf[0]
					if !IsDomainName(rdf[0]) {
						return z, &ParseError{Error: "bad CNAME", name: rdf[0], line: l}
					}
					z.PushRR(rr)
				}
				// line 112 "zparse.rl"
				{
					l++
				}
				goto st141
			tr70:
				// line 122 "types.rl"
				{
					var (
						i uint
						e os.Error
					)
					rdf := fields(data[mark:p], 4)
					rr := new(RR_DLV)
					rr.Hdr = hdr
					rr.Hdr.Rrtype = TypeDLV
					if i, e = strconv.Atoui(rdf[0]); e != nil {
						return z, &ParseError{Error: "bad DS", name: rdf[0], line: l}
					}
					rr.KeyTag = uint16(i)
					if i, e = strconv.Atoui(rdf[1]); e != nil {
						return z, &ParseError{Error: "bad DS", name: rdf[1], line: l}
					}
					rr.Algorithm = uint8(i)
					if i, e = strconv.Atoui(rdf[2]); e != nil {
						return z, &ParseError{Error: "bad DS", name: rdf[2], line: l}
					}
					rr.DigestType = uint8(i)
					rr.Digest = rdf[3]
					z.PushRR(rr)
				}
				// line 112 "zparse.rl"
				{
					l++
				}
				goto st141
			tr79:
				// line 348 "types.rl"
				{
				}
				// line 112 "zparse.rl"
				{
					l++
				}
				goto st141
			tr87:
				// line 172 "types.rl"
				{
					var (
						i uint
						e os.Error
					)
					rdf := fields(data[mark:p], 4)
					rr := new(RR_DNSKEY)
					rr.Hdr = hdr
					rr.Hdr.Rrtype = TypeDNSKEY

					if i, e = strconv.Atoui(rdf[0]); e != nil {
						return z, &ParseError{Error: "bad DNSKEY", name: rdf[0], line: l}
					}
					rr.Flags = uint16(i)
					if i, e = strconv.Atoui(rdf[1]); e != nil {
						return z, &ParseError{Error: "bad DNSKEY", name: rdf[1], line: l}
					}
					rr.Protocol = uint8(i)
					if i, e = strconv.Atoui(rdf[2]); e != nil {
						return z, &ParseError{Error: "bad DNSKEY", name: rdf[2], line: l}
					}
					rr.Algorithm = uint8(i)
					rr.PublicKey = rdf[3]
					z.PushRR(rr)
				}
				// line 112 "zparse.rl"
				{
					l++
				}
				goto st141
			tr92:
				// line 97 "types.rl"
				{
					var (
						i uint
						e os.Error
					)
					rdf := fields(data[mark:p], 4)
					rr := new(RR_DS)
					rr.Hdr = hdr
					rr.Hdr.Rrtype = TypeDS
					if i, e = strconv.Atoui(rdf[0]); e != nil {
						return z, &ParseError{Error: "bad DS", name: rdf[0], line: l}
					}
					rr.KeyTag = uint16(i)
					if i, e = strconv.Atoui(rdf[1]); e != nil {
						return z, &ParseError{Error: "bad DS", name: rdf[1], line: l}
					}
					rr.Algorithm = uint8(i)
					if i, e = strconv.Atoui(rdf[2]); e != nil {
						return z, &ParseError{Error: "bad DS", name: rdf[2], line: l}
					}
					rr.DigestType = uint8(i)
					rr.Digest = rdf[3]
					z.PushRR(rr)
				}
				// line 112 "zparse.rl"
				{
					l++
				}
				goto st141
			tr98:
				// line 39 "types.rl"
				{
					rdf := fields(data[mark:p], 2)
					rr := new(RR_MX)
					rr.Hdr = hdr
					rr.Hdr.Rrtype = TypeMX
					i, err := strconv.Atoui(rdf[0])
					rr.Pref = uint16(i)
					rr.Mx = rdf[1]
					if err != nil {
						return z, &ParseError{Error: "bad MX", name: rdf[0], line: l}
					}
					z.PushRR(rr)
				}
				// line 112 "zparse.rl"
				{
					l++
				}
				goto st141
			tr108:
				// line 351 "types.rl"
				{
				}
				// line 112 "zparse.rl"
				{
					l++
				}
				goto st141
			tr114:
				// line 27 "types.rl"
				{
					rdf := fields(data[mark:p], 1)
					rr := new(RR_NS)
					rr.Hdr = hdr
					rr.Hdr.Rrtype = TypeNS
					rr.Ns = rdf[0]
					if !IsDomainName(rdf[0]) {
						return z, &ParseError{Error: "bad NS", name: rdf[0], line: l}
					}
					z.PushRR(rr)
				}
				// line 112 "zparse.rl"
				{
					l++
				}
				goto st141
			tr121:
				// line 250 "types.rl"
				{
					rdf := fields(data[mark:p], 0)
					rr := new(RR_NSEC)
					rr.Hdr = hdr
					rr.Hdr.Rrtype = TypeNSEC
					rr.NextDomain = rdf[0]
					rr.TypeBitMap = make([]uint16, len(rdf)-1)
					// Fill the Type Bit Map
					for i := 1; i < len(rdf); i++ {
						// Check if its there in the map TODO
						rr.TypeBitMap[i-1] = str_rr[strings.ToUpper(rdf[i])]
					}
					z.PushRR(rr)
				}
				// line 112 "zparse.rl"
				{
					l++
				}
				goto st141
			tr127:
				// line 265 "types.rl"
				{
					var (
						i uint
						e os.Error
					)
					rdf := fields(data[mark:p], 0)
					rr := new(RR_NSEC3)
					rr.Hdr = hdr
					rr.Hdr.Rrtype = TypeNSEC3

					if i, e = strconv.Atoui(rdf[0]); e != nil {
						return z, &ParseError{Error: "bad NSEC3", name: rdf[0], line: l}
					}
					rr.Hash = uint8(i)
					if i, e = strconv.Atoui(rdf[1]); e != nil {
						return z, &ParseError{Error: "bad NSEC3", name: rdf[1], line: l}
					}
					rr.Flags = uint8(i)
					if i, e = strconv.Atoui(rdf[2]); e != nil {
						return z, &ParseError{Error: "bad NSEC3", name: rdf[2], line: l}
					}
					rr.Iterations = uint16(i)
					rr.SaltLength = uint8(len(rdf[3]))
					rr.Salt = rdf[3]

					rr.HashLength = uint8(len(rdf[4]))
					rr.NextDomain = rdf[4]
					rr.TypeBitMap = make([]uint16, len(rdf)-5)
					// Fill the Type Bit Map
					for i := 5; i < len(rdf); i++ {
						// Check if its there in the map TODO
						rr.TypeBitMap[i-5] = str_rr[strings.ToUpper(rdf[i])]
					}
					z.PushRR(rr)
				}
				// line 112 "zparse.rl"
				{
					l++
				}
				goto st141
			tr136:
				// line 301 "types.rl"
				{
					var (
						i int
						e os.Error
					)
					rdf := fields(data[mark:p], 4)
					rr := new(RR_NSEC3PARAM)
					rr.Hdr = hdr
					rr.Hdr.Rrtype = TypeNSEC3PARAM
					if i, e = strconv.Atoi(rdf[0]); e != nil {
						return z, &ParseError{Error: "bad NSEC3PARAM", name: rdf[0], line: l}
					}
					rr.Hash = uint8(i)
					if i, e = strconv.Atoi(rdf[1]); e != nil {
						return z, &ParseError{Error: "bad NSEC3PARAM", name: rdf[1], line: l}
					}
					rr.Flags = uint8(i)
					if i, e = strconv.Atoi(rdf[2]); e != nil {
						return z, &ParseError{Error: "bad NSEC3PARAM", name: rdf[2], line: l}
					}
					rr.Iterations = uint16(i)
					rr.Salt = rdf[3]
					rr.SaltLength = uint8(len(rr.Salt))
					z.PushRR(rr)
				}
				// line 112 "zparse.rl"
				{
					l++
				}
				goto st141
			tr143:
				// line 345 "types.rl"
				{
				}
				// line 112 "zparse.rl"
				{
					l++
				}
				goto st141
			tr152:
				// line 198 "types.rl"
				{
					var (
						i   uint
						j   uint32
						err os.Error
					)
					rdf := fields(data[mark:p], 9)
					rr := new(RR_RRSIG)
					rr.Hdr = hdr
					rr.Hdr.Rrtype = TypeRRSIG

					if _, ok := str_rr[strings.ToUpper(rdf[0])]; !ok {
						return z, &ParseError{Error: "bad RRSIG", name: rdf[0], line: l}
					}
					rr.TypeCovered = str_rr[strings.ToUpper(rdf[0])]

					if i, err = strconv.Atoui(rdf[1]); err != nil {
						return z, &ParseError{Error: "bad RRSIG", name: rdf[1], line: l}
					}
					rr.Algorithm = uint8(i)
					if i, err = strconv.Atoui(rdf[2]); err != nil {
						return z, &ParseError{Error: "bad RRSIG", name: rdf[2], line: l}
					}
					rr.Labels = uint8(i)
					if i, err = strconv.Atoui(rdf[3]); err != nil {
						return z, &ParseError{Error: "bad RRSIG", name: rdf[3], line: l}
					}
					rr.OrigTtl = uint32(i)

					if j, err = dateToTime(rdf[4]); err != nil {
						return z, &ParseError{Error: "bad RRSIG", name: rdf[4], line: l}
					}
					rr.Expiration = j
					if j, err = dateToTime(rdf[5]); err != nil {
						return z, &ParseError{Error: "bad RRSIG", name: rdf[5], line: l}
					}
					rr.Inception = j

					if i, err = strconv.Atoui(rdf[6]); err != nil {
						return z, &ParseError{Error: "bad RRSIG", name: rdf[3], line: l}
					}
					rr.KeyTag = uint16(i)

					rr.SignerName = rdf[7]
					if !IsDomainName(rdf[7]) {
						return z, &ParseError{Error: "bad RRSIG", name: rdf[7], line: l}
					}
					// Check base64 TODO
					rr.Signature = rdf[8]
					z.PushRR(rr)
				}
				// line 112 "zparse.rl"
				{
					l++
				}
				goto st141
			tr161:
				// line 65 "types.rl"
				{
					var (
						i   uint
						err os.Error
					)
					rdf := fields(data[mark:p], 7)
					rr := new(RR_SOA)
					rr.Hdr = hdr
					rr.Hdr.Rrtype = TypeSOA
					rr.Ns = rdf[0]
					rr.Mbox = rdf[1]
					if !IsDomainName(rdf[0]) {
						return z, &ParseError{Error: "bad SOA", name: rdf[0], line: l}
					}
					if !IsDomainName(rdf[1]) {
						return z, &ParseError{Error: "bad SOA", name: rdf[1], line: l}
					}
					for j, s := range rdf[2:7] {
						if i, err = strconv.Atoui(s); err != nil {
							return z, &ParseError{Error: "bad SOA", name: s, line: l}
						}
						switch j {
						case 0:
							rr.Serial = uint32(i)
						case 1:
							rr.Refresh = uint32(i)
						case 2:
							rr.Retry = uint32(i)
						case 3:
							rr.Expire = uint32(i)
						case 4:
							rr.Minttl = uint32(i)
						}
					}
					z.PushRR(rr)
				}
				// line 112 "zparse.rl"
				{
					l++
				}
				goto st141
			tr167:
				// line 339 "types.rl"
				{
				}
				// line 112 "zparse.rl"
				{
					l++
				}
				goto st141
			tr175:
				// line 354 "types.rl"
				{
					var (
						i int
						e os.Error
					)
					rdf := fields(data[mark:p], 3)
					rr := new(RR_SSHFP)
					rr.Hdr = hdr
					rr.Hdr.Rrtype = TypeSSHFP
					if i, e = strconv.Atoi(rdf[0]); e != nil {
						return z, &ParseError{Error: "bad SSHFP", name: rdf[0], line: l}
					}
					rr.Algorithm = uint8(i)
					if i, e = strconv.Atoi(rdf[1]); e != nil {
						return z, &ParseError{Error: "bad SSHFP", name: rdf[1], line: l}
					}
					rr.Type = uint8(i)
					rr.FingerPrint = rdf[2]
					z.PushRR(rr)
				}
				// line 112 "zparse.rl"
				{
					l++
				}
				goto st141
			tr182:
				// line 147 "types.rl"
				{
					var (
						i uint
						e os.Error
					)
					rdf := fields(data[mark:p], 4)
					rr := new(RR_TA)
					rr.Hdr = hdr
					rr.Hdr.Rrtype = TypeTA
					if i, e = strconv.Atoui(rdf[0]); e != nil {
						return z, &ParseError{Error: "bad DS", name: rdf[0], line: l}
					}
					rr.KeyTag = uint16(i)
					if i, e = strconv.Atoui(rdf[1]); e != nil {
						return z, &ParseError{Error: "bad DS", name: rdf[1], line: l}
					}
					rr.Algorithm = uint8(i)
					if i, e = strconv.Atoui(rdf[2]); e != nil {
						return z, &ParseError{Error: "bad DS", name: rdf[2], line: l}
					}
					rr.DigestType = uint8(i)
					rr.Digest = rdf[3]
					z.PushRR(rr)
				}
				// line 112 "zparse.rl"
				{
					l++
				}
				goto st141
			tr188:
				// line 330 "types.rl"
				{
					rdf := fields(data[mark:p], 1)
					rr := new(RR_TXT)
					rr.Hdr = hdr
					rr.Hdr.Rrtype = TypeTXT
					rr.Txt = rdf[0]
					z.PushRR(rr)
				}
				// line 112 "zparse.rl"
				{
					l++
				}
				goto st141
			tr198:
				// line 112 "zparse.rl"
				{
					l++
				}
				goto st141
			st141:
				p++
				if p == pe {
					goto _test_eof141
				}
				fallthrough
			case 141:
				// line 589 "zparse.go"
				switch data[p] {
				case 9:
					goto st1
				case 10:
					goto tr198
				case 32:
					goto st1
				case 42:
					goto tr199
				case 59:
					goto st140
				case 95:
					goto tr199
				}
				if data[p] < 48 {
					if 45 <= data[p] && data[p] <= 46 {
						goto tr199
					}
				} else if data[p] > 57 {
					if data[p] > 90 {
						if 97 <= data[p] && data[p] <= 122 {
							goto tr199
						}
					} else if data[p] >= 65 {
						goto tr199
					}
				} else {
					goto tr199
				}
				goto st0
			st0:
				cs = 0
				goto _out
			tr195:
				// line 113 "zparse.rl"
				{
					if !IsDomainName(data[mark:p]) {
						return z, &ParseError{Error: "bad qname: " + data[mark:p], line: l}
					}
					hdr.Name = data[mark:p]
				}
				goto st1
			st1:
				p++
				if p == pe {
					goto _test_eof1
				}
				fallthrough
			case 1:
				// line 626 "zparse.go"
				switch data[p] {
				case 9:
					goto st1
				case 32:
					goto st1
				case 65:
					goto tr3
				case 67:
					goto tr4
				case 68:
					goto tr5
				case 72:
					goto tr6
				case 73:
					goto tr7
				case 77:
					goto tr8
				case 78:
					goto tr9
				case 80:
					goto tr10
				case 82:
					goto tr11
				case 83:
					goto tr12
				case 84:
					goto tr13
				case 97:
					goto tr3
				case 99:
					goto tr4
				case 100:
					goto tr5
				case 104:
					goto tr6
				case 105:
					goto tr7
				case 109:
					goto tr8
				case 110:
					goto tr9
				case 112:
					goto tr10
				case 114:
					goto tr11
				case 115:
					goto tr12
				case 116:
					goto tr13
				}
				if 48 <= data[p] && data[p] <= 57 {
					goto tr2
				}
				goto st0
			tr2:
				// line 120 "zparse.rl"
				{ // ... 
				}
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st2
			st2:
				p++
				if p == pe {
					goto _test_eof2
				}
				fallthrough
			case 2:
				// line 666 "zparse.go"
				switch data[p] {
				case 9:
					goto tr14
				case 32:
					goto tr14
				}
				if 48 <= data[p] && data[p] <= 57 {
					goto st2
				}
				goto st0
			tr14:
				// line 122 "zparse.rl"
				{
					i, _ := strconv.Atoui(data[mark:p])
					hdr.Ttl = uint32(i)
				}
				goto st3
			st3:
				p++
				if p == pe {
					goto _test_eof3
				}
				fallthrough
			case 3:
				// line 682 "zparse.go"
				switch data[p] {
				case 9:
					goto st3
				case 32:
					goto st3
				case 65:
					goto st4
				case 67:
					goto tr18
				case 68:
					goto st31
				case 72:
					goto tr20
				case 73:
					goto tr21
				case 77:
					goto st55
				case 78:
					goto st60
				case 80:
					goto st89
				case 82:
					goto st95
				case 83:
					goto st103
				case 84:
					goto st121
				case 97:
					goto st4
				case 99:
					goto tr18
				case 100:
					goto st31
				case 104:
					goto tr20
				case 105:
					goto tr21
				case 109:
					goto st55
				case 110:
					goto st60
				case 112:
					goto st89
				case 114:
					goto st95
				case 115:
					goto st103
				case 116:
					goto st121
				}
				goto st0
			tr3:
				// line 120 "zparse.rl"
				{ // ... 
				}
				goto st4
			st4:
				p++
				if p == pe {
					goto _test_eof4
				}
				fallthrough
			case 4:
				// line 719 "zparse.go"
				switch data[p] {
				case 9:
					goto st5
				case 32:
					goto st5
				case 65:
					goto st8
				case 97:
					goto st8
				}
				goto st0
			st5:
				p++
				if p == pe {
					goto _test_eof5
				}
				fallthrough
			case 5:
				switch data[p] {
				case 9:
					goto tr31
				case 10:
					goto st0
				case 32:
					goto tr31
				}
				goto tr30
			tr30:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st6
			st6:
				p++
				if p == pe {
					goto _test_eof6
				}
				fallthrough
			case 6:
				// line 747 "zparse.go"
				if data[p] == 10 {
					goto tr33
				}
				goto st6
			tr31:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st7
			st7:
				p++
				if p == pe {
					goto _test_eof7
				}
				fallthrough
			case 7:
				// line 759 "zparse.go"
				switch data[p] {
				case 9:
					goto tr31
				case 10:
					goto tr33
				case 32:
					goto tr31
				}
				goto tr30
			st8:
				p++
				if p == pe {
					goto _test_eof8
				}
				fallthrough
			case 8:
				switch data[p] {
				case 65:
					goto st9
				case 97:
					goto st9
				}
				goto st0
			st9:
				p++
				if p == pe {
					goto _test_eof9
				}
				fallthrough
			case 9:
				switch data[p] {
				case 65:
					goto st10
				case 97:
					goto st10
				}
				goto st0
			st10:
				p++
				if p == pe {
					goto _test_eof10
				}
				fallthrough
			case 10:
				switch data[p] {
				case 9:
					goto st11
				case 32:
					goto st11
				}
				goto st0
			st11:
				p++
				if p == pe {
					goto _test_eof11
				}
				fallthrough
			case 11:
				switch data[p] {
				case 9:
					goto tr38
				case 10:
					goto st0
				case 32:
					goto tr38
				}
				goto tr37
			tr37:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st12
			st12:
				p++
				if p == pe {
					goto _test_eof12
				}
				fallthrough
			case 12:
				// line 816 "zparse.go"
				if data[p] == 10 {
					goto tr40
				}
				goto st12
			tr38:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st13
			st13:
				p++
				if p == pe {
					goto _test_eof13
				}
				fallthrough
			case 13:
				// line 828 "zparse.go"
				switch data[p] {
				case 9:
					goto tr38
				case 10:
					goto tr40
				case 32:
					goto tr38
				}
				goto tr37
			tr18:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st14
			st14:
				p++
				if p == pe {
					goto _test_eof14
				}
				fallthrough
			case 14:
				// line 844 "zparse.go"
				switch data[p] {
				case 69:
					goto st15
				case 72:
					goto st21
				case 78:
					goto st24
				case 101:
					goto st15
				case 104:
					goto st21
				case 110:
					goto st24
				}
				goto st0
			st15:
				p++
				if p == pe {
					goto _test_eof15
				}
				fallthrough
			case 15:
				switch data[p] {
				case 82:
					goto st16
				case 114:
					goto st16
				}
				goto st0
			st16:
				p++
				if p == pe {
					goto _test_eof16
				}
				fallthrough
			case 16:
				switch data[p] {
				case 84:
					goto st17
				case 116:
					goto st17
				}
				goto st0
			st17:
				p++
				if p == pe {
					goto _test_eof17
				}
				fallthrough
			case 17:
				switch data[p] {
				case 9:
					goto st18
				case 32:
					goto st18
				}
				goto st0
			st18:
				p++
				if p == pe {
					goto _test_eof18
				}
				fallthrough
			case 18:
				switch data[p] {
				case 9:
					goto tr48
				case 10:
					goto st0
				case 32:
					goto tr48
				}
				goto tr47
			tr47:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st19
			st19:
				p++
				if p == pe {
					goto _test_eof19
				}
				fallthrough
			case 19:
				// line 904 "zparse.go"
				if data[p] == 10 {
					goto tr50
				}
				goto st19
			tr48:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st20
			st20:
				p++
				if p == pe {
					goto _test_eof20
				}
				fallthrough
			case 20:
				// line 916 "zparse.go"
				switch data[p] {
				case 9:
					goto tr48
				case 10:
					goto tr50
				case 32:
					goto tr48
				}
				goto tr47
			st21:
				p++
				if p == pe {
					goto _test_eof21
				}
				fallthrough
			case 21:
				switch data[p] {
				case 9:
					goto tr51
				case 32:
					goto tr51
				}
				goto st0
			tr193:
				// line 122 "zparse.rl"
				{
					i, _ := strconv.Atoui(data[mark:p])
					hdr.Ttl = uint32(i)
				}
				goto st22
			tr51:
				// line 119 "zparse.rl"
				{
					hdr.Class = str_class[data[mark:p]]
				}
				goto st22
			st22:
				p++
				if p == pe {
					goto _test_eof22
				}
				fallthrough
			case 22:
				// line 946 "zparse.go"
				switch data[p] {
				case 9:
					goto st22
				case 32:
					goto st22
				case 65:
					goto st4
				case 67:
					goto st23
				case 68:
					goto st31
				case 77:
					goto st55
				case 78:
					goto st60
				case 80:
					goto st89
				case 82:
					goto st95
				case 83:
					goto st103
				case 84:
					goto st121
				case 97:
					goto st4
				case 99:
					goto st23
				case 100:
					goto st31
				case 109:
					goto st55
				case 110:
					goto st60
				case 112:
					goto st89
				case 114:
					goto st95
				case 115:
					goto st103
				case 116:
					goto st121
				}
				goto st0
			st23:
				p++
				if p == pe {
					goto _test_eof23
				}
				fallthrough
			case 23:
				switch data[p] {
				case 69:
					goto st15
				case 78:
					goto st24
				case 101:
					goto st15
				case 110:
					goto st24
				}
				goto st0
			st24:
				p++
				if p == pe {
					goto _test_eof24
				}
				fallthrough
			case 24:
				switch data[p] {
				case 65:
					goto st25
				case 97:
					goto st25
				}
				goto st0
			st25:
				p++
				if p == pe {
					goto _test_eof25
				}
				fallthrough
			case 25:
				switch data[p] {
				case 77:
					goto st26
				case 109:
					goto st26
				}
				goto st0
			st26:
				p++
				if p == pe {
					goto _test_eof26
				}
				fallthrough
			case 26:
				switch data[p] {
				case 69:
					goto st27
				case 101:
					goto st27
				}
				goto st0
			st27:
				p++
				if p == pe {
					goto _test_eof27
				}
				fallthrough
			case 27:
				switch data[p] {
				case 9:
					goto st28
				case 32:
					goto st28
				}
				goto st0
			st28:
				p++
				if p == pe {
					goto _test_eof28
				}
				fallthrough
			case 28:
				switch data[p] {
				case 9:
					goto tr59
				case 10:
					goto st0
				case 32:
					goto tr59
				}
				goto tr58
			tr58:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st29
			st29:
				p++
				if p == pe {
					goto _test_eof29
				}
				fallthrough
			case 29:
				// line 1042 "zparse.go"
				if data[p] == 10 {
					goto tr61
				}
				goto st29
			tr59:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st30
			st30:
				p++
				if p == pe {
					goto _test_eof30
				}
				fallthrough
			case 30:
				// line 1054 "zparse.go"
				switch data[p] {
				case 9:
					goto tr59
				case 10:
					goto tr61
				case 32:
					goto tr59
				}
				goto tr58
			tr5:
				// line 120 "zparse.rl"
				{ // ...
				}
				goto st31
			st31:
				p++
				if p == pe {
					goto _test_eof31
				}
				fallthrough
			case 31:
				// line 1070 "zparse.go"
				switch data[p] {
				case 76:
					goto st32
				case 78:
					goto st37
				case 83:
					goto st51
				case 108:
					goto st32
				case 110:
					goto st37
				case 115:
					goto st51
				}
				goto st0
			st32:
				p++
				if p == pe {
					goto _test_eof32
				}
				fallthrough
			case 32:
				switch data[p] {
				case 86:
					goto st33
				case 118:
					goto st33
				}
				goto st0
			st33:
				p++
				if p == pe {
					goto _test_eof33
				}
				fallthrough
			case 33:
				switch data[p] {
				case 9:
					goto st34
				case 32:
					goto st34
				}
				goto st0
			st34:
				p++
				if p == pe {
					goto _test_eof34
				}
				fallthrough
			case 34:
				switch data[p] {
				case 9:
					goto tr68
				case 10:
					goto st0
				case 32:
					goto tr68
				}
				goto tr67
			tr67:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st35
			st35:
				p++
				if p == pe {
					goto _test_eof35
				}
				fallthrough
			case 35:
				// line 1120 "zparse.go"
				if data[p] == 10 {
					goto tr70
				}
				goto st35
			tr68:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st36
			st36:
				p++
				if p == pe {
					goto _test_eof36
				}
				fallthrough
			case 36:
				// line 1132 "zparse.go"
				switch data[p] {
				case 9:
					goto tr68
				case 10:
					goto tr70
				case 32:
					goto tr68
				}
				goto tr67
			st37:
				p++
				if p == pe {
					goto _test_eof37
				}
				fallthrough
			case 37:
				switch data[p] {
				case 65:
					goto st38
				case 83:
					goto st44
				case 97:
					goto st38
				case 115:
					goto st44
				}
				goto st0
			st38:
				p++
				if p == pe {
					goto _test_eof38
				}
				fallthrough
			case 38:
				switch data[p] {
				case 77:
					goto st39
				case 109:
					goto st39
				}
				goto st0
			st39:
				p++
				if p == pe {
					goto _test_eof39
				}
				fallthrough
			case 39:
				switch data[p] {
				case 69:
					goto st40
				case 101:
					goto st40
				}
				goto st0
			st40:
				p++
				if p == pe {
					goto _test_eof40
				}
				fallthrough
			case 40:
				switch data[p] {
				case 9:
					goto st41
				case 32:
					goto st41
				}
				goto st0
			st41:
				p++
				if p == pe {
					goto _test_eof41
				}
				fallthrough
			case 41:
				switch data[p] {
				case 9:
					goto tr77
				case 10:
					goto st0
				case 32:
					goto tr77
				}
				goto tr76
			tr76:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st42
			st42:
				p++
				if p == pe {
					goto _test_eof42
				}
				fallthrough
			case 42:
				// line 1201 "zparse.go"
				if data[p] == 10 {
					goto tr79
				}
				goto st42
			tr77:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st43
			st43:
				p++
				if p == pe {
					goto _test_eof43
				}
				fallthrough
			case 43:
				// line 1213 "zparse.go"
				switch data[p] {
				case 9:
					goto tr77
				case 10:
					goto tr79
				case 32:
					goto tr77
				}
				goto tr76
			st44:
				p++
				if p == pe {
					goto _test_eof44
				}
				fallthrough
			case 44:
				switch data[p] {
				case 75:
					goto st45
				case 107:
					goto st45
				}
				goto st0
			st45:
				p++
				if p == pe {
					goto _test_eof45
				}
				fallthrough
			case 45:
				switch data[p] {
				case 69:
					goto st46
				case 101:
					goto st46
				}
				goto st0
			st46:
				p++
				if p == pe {
					goto _test_eof46
				}
				fallthrough
			case 46:
				switch data[p] {
				case 89:
					goto st47
				case 121:
					goto st47
				}
				goto st0
			st47:
				p++
				if p == pe {
					goto _test_eof47
				}
				fallthrough
			case 47:
				switch data[p] {
				case 9:
					goto st48
				case 32:
					goto st48
				}
				goto st0
			st48:
				p++
				if p == pe {
					goto _test_eof48
				}
				fallthrough
			case 48:
				switch data[p] {
				case 9:
					goto tr85
				case 10:
					goto st0
				case 32:
					goto tr85
				}
				goto tr84
			tr84:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st49
			st49:
				p++
				if p == pe {
					goto _test_eof49
				}
				fallthrough
			case 49:
				// line 1280 "zparse.go"
				if data[p] == 10 {
					goto tr87
				}
				goto st49
			tr85:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st50
			st50:
				p++
				if p == pe {
					goto _test_eof50
				}
				fallthrough
			case 50:
				// line 1292 "zparse.go"
				switch data[p] {
				case 9:
					goto tr85
				case 10:
					goto tr87
				case 32:
					goto tr85
				}
				goto tr84
			st51:
				p++
				if p == pe {
					goto _test_eof51
				}
				fallthrough
			case 51:
				switch data[p] {
				case 9:
					goto st52
				case 32:
					goto st52
				}
				goto st0
			st52:
				p++
				if p == pe {
					goto _test_eof52
				}
				fallthrough
			case 52:
				switch data[p] {
				case 9:
					goto tr90
				case 10:
					goto st0
				case 32:
					goto tr90
				}
				goto tr89
			tr89:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st53
			st53:
				p++
				if p == pe {
					goto _test_eof53
				}
				fallthrough
			case 53:
				// line 1329 "zparse.go"
				if data[p] == 10 {
					goto tr92
				}
				goto st53
			tr90:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st54
			st54:
				p++
				if p == pe {
					goto _test_eof54
				}
				fallthrough
			case 54:
				// line 1341 "zparse.go"
				switch data[p] {
				case 9:
					goto tr90
				case 10:
					goto tr92
				case 32:
					goto tr90
				}
				goto tr89
			tr8:
				// line 120 "zparse.rl"
				{ // ...
				}
				goto st55
			st55:
				p++
				if p == pe {
					goto _test_eof55
				}
				fallthrough
			case 55:
				// line 1357 "zparse.go"
				switch data[p] {
				case 88:
					goto st56
				case 120:
					goto st56
				}
				goto st0
			st56:
				p++
				if p == pe {
					goto _test_eof56
				}
				fallthrough
			case 56:
				switch data[p] {
				case 9:
					goto st57
				case 32:
					goto st57
				}
				goto st0
			st57:
				p++
				if p == pe {
					goto _test_eof57
				}
				fallthrough
			case 57:
				switch data[p] {
				case 9:
					goto tr96
				case 10:
					goto st0
				case 32:
					goto tr96
				}
				goto tr95
			tr95:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st58
			st58:
				p++
				if p == pe {
					goto _test_eof58
				}
				fallthrough
			case 58:
				// line 1393 "zparse.go"
				if data[p] == 10 {
					goto tr98
				}
				goto st58
			tr96:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st59
			st59:
				p++
				if p == pe {
					goto _test_eof59
				}
				fallthrough
			case 59:
				// line 1405 "zparse.go"
				switch data[p] {
				case 9:
					goto tr96
				case 10:
					goto tr98
				case 32:
					goto tr96
				}
				goto tr95
			tr9:
				// line 120 "zparse.rl"
				{ // ... 
				}
				goto st60
			st60:
				p++
				if p == pe {
					goto _test_eof60
				}
				fallthrough
			case 60:
				// line 1421 "zparse.go"
				switch data[p] {
				case 65:
					goto st61
				case 83:
					goto st68
				case 97:
					goto st61
				case 115:
					goto st68
				}
				goto st0
			st61:
				p++
				if p == pe {
					goto _test_eof61
				}
				fallthrough
			case 61:
				switch data[p] {
				case 80:
					goto st62
				case 112:
					goto st62
				}
				goto st0
			st62:
				p++
				if p == pe {
					goto _test_eof62
				}
				fallthrough
			case 62:
				switch data[p] {
				case 84:
					goto st63
				case 116:
					goto st63
				}
				goto st0
			st63:
				p++
				if p == pe {
					goto _test_eof63
				}
				fallthrough
			case 63:
				switch data[p] {
				case 82:
					goto st64
				case 114:
					goto st64
				}
				goto st0
			st64:
				p++
				if p == pe {
					goto _test_eof64
				}
				fallthrough
			case 64:
				switch data[p] {
				case 9:
					goto st65
				case 32:
					goto st65
				}
				goto st0
			st65:
				p++
				if p == pe {
					goto _test_eof65
				}
				fallthrough
			case 65:
				switch data[p] {
				case 9:
					goto tr106
				case 10:
					goto st0
				case 32:
					goto tr106
				}
				goto tr105
			tr105:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st66
			st66:
				p++
				if p == pe {
					goto _test_eof66
				}
				fallthrough
			case 66:
				// line 1489 "zparse.go"
				if data[p] == 10 {
					goto tr108
				}
				goto st66
			tr106:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st67
			st67:
				p++
				if p == pe {
					goto _test_eof67
				}
				fallthrough
			case 67:
				// line 1501 "zparse.go"
				switch data[p] {
				case 9:
					goto tr106
				case 10:
					goto tr108
				case 32:
					goto tr106
				}
				goto tr105
			st68:
				p++
				if p == pe {
					goto _test_eof68
				}
				fallthrough
			case 68:
				switch data[p] {
				case 9:
					goto st69
				case 32:
					goto st69
				case 69:
					goto st72
				case 101:
					goto st72
				}
				goto st0
			st69:
				p++
				if p == pe {
					goto _test_eof69
				}
				fallthrough
			case 69:
				switch data[p] {
				case 9:
					goto tr112
				case 10:
					goto st0
				case 32:
					goto tr112
				}
				goto tr111
			tr111:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st70
			st70:
				p++
				if p == pe {
					goto _test_eof70
				}
				fallthrough
			case 70:
				// line 1540 "zparse.go"
				if data[p] == 10 {
					goto tr114
				}
				goto st70
			tr112:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st71
			st71:
				p++
				if p == pe {
					goto _test_eof71
				}
				fallthrough
			case 71:
				// line 1552 "zparse.go"
				switch data[p] {
				case 9:
					goto tr112
				case 10:
					goto tr114
				case 32:
					goto tr112
				}
				goto tr111
			st72:
				p++
				if p == pe {
					goto _test_eof72
				}
				fallthrough
			case 72:
				switch data[p] {
				case 67:
					goto st73
				case 99:
					goto st73
				}
				goto st0
			st73:
				p++
				if p == pe {
					goto _test_eof73
				}
				fallthrough
			case 73:
				switch data[p] {
				case 9:
					goto st74
				case 32:
					goto st74
				case 51:
					goto st77
				}
				goto st0
			st74:
				p++
				if p == pe {
					goto _test_eof74
				}
				fallthrough
			case 74:
				switch data[p] {
				case 9:
					goto tr119
				case 10:
					goto st0
				case 32:
					goto tr119
				}
				goto tr118
			tr118:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st75
			st75:
				p++
				if p == pe {
					goto _test_eof75
				}
				fallthrough
			case 75:
				// line 1600 "zparse.go"
				if data[p] == 10 {
					goto tr121
				}
				goto st75
			tr119:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st76
			st76:
				p++
				if p == pe {
					goto _test_eof76
				}
				fallthrough
			case 76:
				// line 1612 "zparse.go"
				switch data[p] {
				case 9:
					goto tr119
				case 10:
					goto tr121
				case 32:
					goto tr119
				}
				goto tr118
			st77:
				p++
				if p == pe {
					goto _test_eof77
				}
				fallthrough
			case 77:
				switch data[p] {
				case 9:
					goto st78
				case 32:
					goto st78
				case 80:
					goto st81
				case 112:
					goto st81
				}
				goto st0
			st78:
				p++
				if p == pe {
					goto _test_eof78
				}
				fallthrough
			case 78:
				switch data[p] {
				case 9:
					goto tr125
				case 10:
					goto st0
				case 32:
					goto tr125
				}
				goto tr124
			tr124:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st79
			st79:
				p++
				if p == pe {
					goto _test_eof79
				}
				fallthrough
			case 79:
				// line 1651 "zparse.go"
				if data[p] == 10 {
					goto tr127
				}
				goto st79
			tr125:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st80
			st80:
				p++
				if p == pe {
					goto _test_eof80
				}
				fallthrough
			case 80:
				// line 1663 "zparse.go"
				switch data[p] {
				case 9:
					goto tr125
				case 10:
					goto tr127
				case 32:
					goto tr125
				}
				goto tr124
			st81:
				p++
				if p == pe {
					goto _test_eof81
				}
				fallthrough
			case 81:
				switch data[p] {
				case 65:
					goto st82
				case 97:
					goto st82
				}
				goto st0
			st82:
				p++
				if p == pe {
					goto _test_eof82
				}
				fallthrough
			case 82:
				switch data[p] {
				case 82:
					goto st83
				case 114:
					goto st83
				}
				goto st0
			st83:
				p++
				if p == pe {
					goto _test_eof83
				}
				fallthrough
			case 83:
				switch data[p] {
				case 65:
					goto st84
				case 97:
					goto st84
				}
				goto st0
			st84:
				p++
				if p == pe {
					goto _test_eof84
				}
				fallthrough
			case 84:
				switch data[p] {
				case 77:
					goto st85
				case 109:
					goto st85
				}
				goto st0
			st85:
				p++
				if p == pe {
					goto _test_eof85
				}
				fallthrough
			case 85:
				switch data[p] {
				case 9:
					goto st86
				case 32:
					goto st86
				}
				goto st0
			st86:
				p++
				if p == pe {
					goto _test_eof86
				}
				fallthrough
			case 86:
				switch data[p] {
				case 9:
					goto tr134
				case 10:
					goto st0
				case 32:
					goto tr134
				}
				goto tr133
			tr133:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st87
			st87:
				p++
				if p == pe {
					goto _test_eof87
				}
				fallthrough
			case 87:
				// line 1740 "zparse.go"
				if data[p] == 10 {
					goto tr136
				}
				goto st87
			tr134:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st88
			st88:
				p++
				if p == pe {
					goto _test_eof88
				}
				fallthrough
			case 88:
				// line 1752 "zparse.go"
				switch data[p] {
				case 9:
					goto tr134
				case 10:
					goto tr136
				case 32:
					goto tr134
				}
				goto tr133
			tr10:
				// line 120 "zparse.rl"
				{ // ... 
				}
				goto st89
			st89:
				p++
				if p == pe {
					goto _test_eof89
				}
				fallthrough
			case 89:
				// line 1768 "zparse.go"
				switch data[p] {
				case 84:
					goto st90
				case 116:
					goto st90
				}
				goto st0
			st90:
				p++
				if p == pe {
					goto _test_eof90
				}
				fallthrough
			case 90:
				switch data[p] {
				case 82:
					goto st91
				case 114:
					goto st91
				}
				goto st0
			st91:
				p++
				if p == pe {
					goto _test_eof91
				}
				fallthrough
			case 91:
				switch data[p] {
				case 9:
					goto st92
				case 32:
					goto st92
				}
				goto st0
			st92:
				p++
				if p == pe {
					goto _test_eof92
				}
				fallthrough
			case 92:
				switch data[p] {
				case 9:
					goto tr141
				case 10:
					goto st0
				case 32:
					goto tr141
				}
				goto tr140
			tr140:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st93
			st93:
				p++
				if p == pe {
					goto _test_eof93
				}
				fallthrough
			case 93:
				// line 1814 "zparse.go"
				if data[p] == 10 {
					goto tr143
				}
				goto st93
			tr141:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st94
			st94:
				p++
				if p == pe {
					goto _test_eof94
				}
				fallthrough
			case 94:
				// line 1826 "zparse.go"
				switch data[p] {
				case 9:
					goto tr141
				case 10:
					goto tr143
				case 32:
					goto tr141
				}
				goto tr140
			tr11:
				// line 120 "zparse.rl"
				{ // ... 
				}
				goto st95
			st95:
				p++
				if p == pe {
					goto _test_eof95
				}
				fallthrough
			case 95:
				// line 1842 "zparse.go"
				switch data[p] {
				case 82:
					goto st96
				case 114:
					goto st96
				}
				goto st0
			st96:
				p++
				if p == pe {
					goto _test_eof96
				}
				fallthrough
			case 96:
				switch data[p] {
				case 83:
					goto st97
				case 115:
					goto st97
				}
				goto st0
			st97:
				p++
				if p == pe {
					goto _test_eof97
				}
				fallthrough
			case 97:
				switch data[p] {
				case 73:
					goto st98
				case 105:
					goto st98
				}
				goto st0
			st98:
				p++
				if p == pe {
					goto _test_eof98
				}
				fallthrough
			case 98:
				switch data[p] {
				case 71:
					goto st99
				case 103:
					goto st99
				}
				goto st0
			st99:
				p++
				if p == pe {
					goto _test_eof99
				}
				fallthrough
			case 99:
				switch data[p] {
				case 9:
					goto st100
				case 32:
					goto st100
				}
				goto st0
			st100:
				p++
				if p == pe {
					goto _test_eof100
				}
				fallthrough
			case 100:
				switch data[p] {
				case 9:
					goto tr150
				case 10:
					goto st0
				case 32:
					goto tr150
				}
				goto tr149
			tr149:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st101
			st101:
				p++
				if p == pe {
					goto _test_eof101
				}
				fallthrough
			case 101:
				// line 1908 "zparse.go"
				if data[p] == 10 {
					goto tr152
				}
				goto st101
			tr150:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st102
			st102:
				p++
				if p == pe {
					goto _test_eof102
				}
				fallthrough
			case 102:
				// line 1920 "zparse.go"
				switch data[p] {
				case 9:
					goto tr150
				case 10:
					goto tr152
				case 32:
					goto tr150
				}
				goto tr149
			tr12:
				// line 120 "zparse.rl"
				{ // ... 
				}
				goto st103
			st103:
				p++
				if p == pe {
					goto _test_eof103
				}
				fallthrough
			case 103:
				// line 1936 "zparse.go"
				switch data[p] {
				case 79:
					goto st104
				case 82:
					goto st109
				case 83:
					goto st114
				case 111:
					goto st104
				case 114:
					goto st109
				case 115:
					goto st114
				}
				goto st0
			st104:
				p++
				if p == pe {
					goto _test_eof104
				}
				fallthrough
			case 104:
				switch data[p] {
				case 65:
					goto st105
				case 97:
					goto st105
				}
				goto st0
			st105:
				p++
				if p == pe {
					goto _test_eof105
				}
				fallthrough
			case 105:
				switch data[p] {
				case 9:
					goto st106
				case 32:
					goto st106
				}
				goto st0
			st106:
				p++
				if p == pe {
					goto _test_eof106
				}
				fallthrough
			case 106:
				switch data[p] {
				case 9:
					goto tr159
				case 10:
					goto st0
				case 32:
					goto tr159
				}
				goto tr158
			tr158:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st107
			st107:
				p++
				if p == pe {
					goto _test_eof107
				}
				fallthrough
			case 107:
				// line 1986 "zparse.go"
				if data[p] == 10 {
					goto tr161
				}
				goto st107
			tr159:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st108
			st108:
				p++
				if p == pe {
					goto _test_eof108
				}
				fallthrough
			case 108:
				// line 1998 "zparse.go"
				switch data[p] {
				case 9:
					goto tr159
				case 10:
					goto tr161
				case 32:
					goto tr159
				}
				goto tr158
			st109:
				p++
				if p == pe {
					goto _test_eof109
				}
				fallthrough
			case 109:
				switch data[p] {
				case 86:
					goto st110
				case 118:
					goto st110
				}
				goto st0
			st110:
				p++
				if p == pe {
					goto _test_eof110
				}
				fallthrough
			case 110:
				switch data[p] {
				case 9:
					goto st111
				case 32:
					goto st111
				}
				goto st0
			st111:
				p++
				if p == pe {
					goto _test_eof111
				}
				fallthrough
			case 111:
				switch data[p] {
				case 9:
					goto tr165
				case 10:
					goto st0
				case 32:
					goto tr165
				}
				goto tr164
			tr164:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st112
			st112:
				p++
				if p == pe {
					goto _test_eof112
				}
				fallthrough
			case 112:
				// line 2045 "zparse.go"
				if data[p] == 10 {
					goto tr167
				}
				goto st112
			tr165:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st113
			st113:
				p++
				if p == pe {
					goto _test_eof113
				}
				fallthrough
			case 113:
				// line 2057 "zparse.go"
				switch data[p] {
				case 9:
					goto tr165
				case 10:
					goto tr167
				case 32:
					goto tr165
				}
				goto tr164
			st114:
				p++
				if p == pe {
					goto _test_eof114
				}
				fallthrough
			case 114:
				switch data[p] {
				case 72:
					goto st115
				case 104:
					goto st115
				}
				goto st0
			st115:
				p++
				if p == pe {
					goto _test_eof115
				}
				fallthrough
			case 115:
				switch data[p] {
				case 70:
					goto st116
				case 102:
					goto st116
				}
				goto st0
			st116:
				p++
				if p == pe {
					goto _test_eof116
				}
				fallthrough
			case 116:
				switch data[p] {
				case 80:
					goto st117
				case 112:
					goto st117
				}
				goto st0
			st117:
				p++
				if p == pe {
					goto _test_eof117
				}
				fallthrough
			case 117:
				switch data[p] {
				case 9:
					goto st118
				case 32:
					goto st118
				}
				goto st0
			st118:
				p++
				if p == pe {
					goto _test_eof118
				}
				fallthrough
			case 118:
				switch data[p] {
				case 9:
					goto tr173
				case 10:
					goto st0
				case 32:
					goto tr173
				}
				goto tr172
			tr172:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st119
			st119:
				p++
				if p == pe {
					goto _test_eof119
				}
				fallthrough
			case 119:
				// line 2124 "zparse.go"
				if data[p] == 10 {
					goto tr175
				}
				goto st119
			tr173:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st120
			st120:
				p++
				if p == pe {
					goto _test_eof120
				}
				fallthrough
			case 120:
				// line 2136 "zparse.go"
				switch data[p] {
				case 9:
					goto tr173
				case 10:
					goto tr175
				case 32:
					goto tr173
				}
				goto tr172
			tr13:
				// line 120 "zparse.rl"
				{ // ... 
				}
				goto st121
			st121:
				p++
				if p == pe {
					goto _test_eof121
				}
				fallthrough
			case 121:
				// line 2152 "zparse.go"
				switch data[p] {
				case 65:
					goto st122
				case 88:
					goto st126
				case 97:
					goto st122
				case 120:
					goto st126
				}
				goto st0
			st122:
				p++
				if p == pe {
					goto _test_eof122
				}
				fallthrough
			case 122:
				switch data[p] {
				case 9:
					goto st123
				case 32:
					goto st123
				}
				goto st0
			st123:
				p++
				if p == pe {
					goto _test_eof123
				}
				fallthrough
			case 123:
				switch data[p] {
				case 9:
					goto tr180
				case 10:
					goto st0
				case 32:
					goto tr180
				}
				goto tr179
			tr179:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st124
			st124:
				p++
				if p == pe {
					goto _test_eof124
				}
				fallthrough
			case 124:
				// line 2190 "zparse.go"
				if data[p] == 10 {
					goto tr182
				}
				goto st124
			tr180:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st125
			st125:
				p++
				if p == pe {
					goto _test_eof125
				}
				fallthrough
			case 125:
				// line 2202 "zparse.go"
				switch data[p] {
				case 9:
					goto tr180
				case 10:
					goto tr182
				case 32:
					goto tr180
				}
				goto tr179
			st126:
				p++
				if p == pe {
					goto _test_eof126
				}
				fallthrough
			case 126:
				switch data[p] {
				case 84:
					goto st127
				case 116:
					goto st127
				}
				goto st0
			st127:
				p++
				if p == pe {
					goto _test_eof127
				}
				fallthrough
			case 127:
				switch data[p] {
				case 9:
					goto st128
				case 32:
					goto st128
				}
				goto st0
			st128:
				p++
				if p == pe {
					goto _test_eof128
				}
				fallthrough
			case 128:
				switch data[p] {
				case 9:
					goto tr186
				case 10:
					goto st0
				case 32:
					goto tr186
				}
				goto tr185
			tr185:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st129
			st129:
				p++
				if p == pe {
					goto _test_eof129
				}
				fallthrough
			case 129:
				// line 2249 "zparse.go"
				if data[p] == 10 {
					goto tr188
				}
				goto st129
			tr186:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st130
			st130:
				p++
				if p == pe {
					goto _test_eof130
				}
				fallthrough
			case 130:
				// line 2261 "zparse.go"
				switch data[p] {
				case 9:
					goto tr186
				case 10:
					goto tr188
				case 32:
					goto tr186
				}
				goto tr185
			tr20:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st131
			st131:
				p++
				if p == pe {
					goto _test_eof131
				}
				fallthrough
			case 131:
				// line 2277 "zparse.go"
				switch data[p] {
				case 83:
					goto st21
				case 115:
					goto st21
				}
				goto st0
			tr21:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st132
			st132:
				p++
				if p == pe {
					goto _test_eof132
				}
				fallthrough
			case 132:
				// line 2292 "zparse.go"
				switch data[p] {
				case 78:
					goto st21
				case 110:
					goto st21
				}
				goto st0
			tr4:
				// line 120 "zparse.rl"
				{ // ...
				}
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st133
			st133:
				p++
				if p == pe {
					goto _test_eof133
				}
				fallthrough
			case 133:
				// line 2309 "zparse.go"
				switch data[p] {
				case 69:
					goto st15
				case 72:
					goto st134
				case 78:
					goto st24
				case 101:
					goto st15
				case 104:
					goto st134
				case 110:
					goto st24
				}
				goto st0
			st134:
				p++
				if p == pe {
					goto _test_eof134
				}
				fallthrough
			case 134:
				switch data[p] {
				case 9:
					goto tr190
				case 32:
					goto tr190
				}
				goto st0
			tr190:
				// line 119 "zparse.rl"
				{
					hdr.Class = str_class[data[mark:p]]
				}
				goto st135
			st135:
				p++
				if p == pe {
					goto _test_eof135
				}
				fallthrough
			case 135:
				// line 2338 "zparse.go"
				switch data[p] {
				case 9:
					goto st135
				case 32:
					goto st135
				case 65:
					goto st4
				case 67:
					goto st23
				case 68:
					goto st31
				case 77:
					goto st55
				case 78:
					goto st60
				case 80:
					goto st89
				case 82:
					goto st95
				case 83:
					goto st103
				case 84:
					goto st121
				case 97:
					goto st4
				case 99:
					goto st23
				case 100:
					goto st31
				case 109:
					goto st55
				case 110:
					goto st60
				case 112:
					goto st89
				case 114:
					goto st95
				case 115:
					goto st103
				case 116:
					goto st121
				}
				if 48 <= data[p] && data[p] <= 57 {
					goto tr192
				}
				goto st0
			tr192:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st136
			st136:
				p++
				if p == pe {
					goto _test_eof136
				}
				fallthrough
			case 136:
				// line 2372 "zparse.go"
				switch data[p] {
				case 9:
					goto tr193
				case 32:
					goto tr193
				}
				if 48 <= data[p] && data[p] <= 57 {
					goto st136
				}
				goto st0
			tr6:
				// line 120 "zparse.rl"
				{ // ... 
				}
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st137
			st137:
				p++
				if p == pe {
					goto _test_eof137
				}
				fallthrough
			case 137:
				// line 2390 "zparse.go"
				switch data[p] {
				case 83:
					goto st134
				case 115:
					goto st134
				}
				goto st0
			tr7:
				// line 120 "zparse.rl"
				{ // ...
				}
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st138
			st138:
				p++
				if p == pe {
					goto _test_eof138
				}
				fallthrough
			case 138:
				// line 2407 "zparse.go"
				switch data[p] {
				case 78:
					goto st134
				case 110:
					goto st134
				}
				goto st0
			tr199:
				// line 111 "zparse.rl"
				{
					mark = p
				}
				goto st139
			st139:
				p++
				if p == pe {
					goto _test_eof139
				}
				fallthrough
			case 139:
				// line 2422 "zparse.go"
				switch data[p] {
				case 9:
					goto tr195
				case 32:
					goto tr195
				case 42:
					goto st139
				case 95:
					goto st139
				}
				if data[p] < 48 {
					if 45 <= data[p] && data[p] <= 46 {
						goto st139
					}
				} else if data[p] > 57 {
					if data[p] > 90 {
						if 97 <= data[p] && data[p] <= 122 {
							goto st139
						}
					} else if data[p] >= 65 {
						goto st139
					}
				} else {
					goto st139
				}
				goto st0
			st140:
				p++
				if p == pe {
					goto _test_eof140
				}
				fallthrough
			case 140:
				if data[p] == 10 {
					goto tr198
				}
				goto st140
			}
		_test_eof141:
			cs = 141
			goto _test_eof
		_test_eof1:
			cs = 1
			goto _test_eof
		_test_eof2:
			cs = 2
			goto _test_eof
		_test_eof3:
			cs = 3
			goto _test_eof
		_test_eof4:
			cs = 4
			goto _test_eof
		_test_eof5:
			cs = 5
			goto _test_eof
		_test_eof6:
			cs = 6
			goto _test_eof
		_test_eof7:
			cs = 7
			goto _test_eof
		_test_eof8:
			cs = 8
			goto _test_eof
		_test_eof9:
			cs = 9
			goto _test_eof
		_test_eof10:
			cs = 10
			goto _test_eof
		_test_eof11:
			cs = 11
			goto _test_eof
		_test_eof12:
			cs = 12
			goto _test_eof
		_test_eof13:
			cs = 13
			goto _test_eof
		_test_eof14:
			cs = 14
			goto _test_eof
		_test_eof15:
			cs = 15
			goto _test_eof
		_test_eof16:
			cs = 16
			goto _test_eof
		_test_eof17:
			cs = 17
			goto _test_eof
		_test_eof18:
			cs = 18
			goto _test_eof
		_test_eof19:
			cs = 19
			goto _test_eof
		_test_eof20:
			cs = 20
			goto _test_eof
		_test_eof21:
			cs = 21
			goto _test_eof
		_test_eof22:
			cs = 22
			goto _test_eof
		_test_eof23:
			cs = 23
			goto _test_eof
		_test_eof24:
			cs = 24
			goto _test_eof
		_test_eof25:
			cs = 25
			goto _test_eof
		_test_eof26:
			cs = 26
			goto _test_eof
		_test_eof27:
			cs = 27
			goto _test_eof
		_test_eof28:
			cs = 28
			goto _test_eof
		_test_eof29:
			cs = 29
			goto _test_eof
		_test_eof30:
			cs = 30
			goto _test_eof
		_test_eof31:
			cs = 31
			goto _test_eof
		_test_eof32:
			cs = 32
			goto _test_eof
		_test_eof33:
			cs = 33
			goto _test_eof
		_test_eof34:
			cs = 34
			goto _test_eof
		_test_eof35:
			cs = 35
			goto _test_eof
		_test_eof36:
			cs = 36
			goto _test_eof
		_test_eof37:
			cs = 37
			goto _test_eof
		_test_eof38:
			cs = 38
			goto _test_eof
		_test_eof39:
			cs = 39
			goto _test_eof
		_test_eof40:
			cs = 40
			goto _test_eof
		_test_eof41:
			cs = 41
			goto _test_eof
		_test_eof42:
			cs = 42
			goto _test_eof
		_test_eof43:
			cs = 43
			goto _test_eof
		_test_eof44:
			cs = 44
			goto _test_eof
		_test_eof45:
			cs = 45
			goto _test_eof
		_test_eof46:
			cs = 46
			goto _test_eof
		_test_eof47:
			cs = 47
			goto _test_eof
		_test_eof48:
			cs = 48
			goto _test_eof
		_test_eof49:
			cs = 49
			goto _test_eof
		_test_eof50:
			cs = 50
			goto _test_eof
		_test_eof51:
			cs = 51
			goto _test_eof
		_test_eof52:
			cs = 52
			goto _test_eof
		_test_eof53:
			cs = 53
			goto _test_eof
		_test_eof54:
			cs = 54
			goto _test_eof
		_test_eof55:
			cs = 55
			goto _test_eof
		_test_eof56:
			cs = 56
			goto _test_eof
		_test_eof57:
			cs = 57
			goto _test_eof
		_test_eof58:
			cs = 58
			goto _test_eof
		_test_eof59:
			cs = 59
			goto _test_eof
		_test_eof60:
			cs = 60
			goto _test_eof
		_test_eof61:
			cs = 61
			goto _test_eof
		_test_eof62:
			cs = 62
			goto _test_eof
		_test_eof63:
			cs = 63
			goto _test_eof
		_test_eof64:
			cs = 64
			goto _test_eof
		_test_eof65:
			cs = 65
			goto _test_eof
		_test_eof66:
			cs = 66
			goto _test_eof
		_test_eof67:
			cs = 67
			goto _test_eof
		_test_eof68:
			cs = 68
			goto _test_eof
		_test_eof69:
			cs = 69
			goto _test_eof
		_test_eof70:
			cs = 70
			goto _test_eof
		_test_eof71:
			cs = 71
			goto _test_eof
		_test_eof72:
			cs = 72
			goto _test_eof
		_test_eof73:
			cs = 73
			goto _test_eof
		_test_eof74:
			cs = 74
			goto _test_eof
		_test_eof75:
			cs = 75
			goto _test_eof
		_test_eof76:
			cs = 76
			goto _test_eof
		_test_eof77:
			cs = 77
			goto _test_eof
		_test_eof78:
			cs = 78
			goto _test_eof
		_test_eof79:
			cs = 79
			goto _test_eof
		_test_eof80:
			cs = 80
			goto _test_eof
		_test_eof81:
			cs = 81
			goto _test_eof
		_test_eof82:
			cs = 82
			goto _test_eof
		_test_eof83:
			cs = 83
			goto _test_eof
		_test_eof84:
			cs = 84
			goto _test_eof
		_test_eof85:
			cs = 85
			goto _test_eof
		_test_eof86:
			cs = 86
			goto _test_eof
		_test_eof87:
			cs = 87
			goto _test_eof
		_test_eof88:
			cs = 88
			goto _test_eof
		_test_eof89:
			cs = 89
			goto _test_eof
		_test_eof90:
			cs = 90
			goto _test_eof
		_test_eof91:
			cs = 91
			goto _test_eof
		_test_eof92:
			cs = 92
			goto _test_eof
		_test_eof93:
			cs = 93
			goto _test_eof
		_test_eof94:
			cs = 94
			goto _test_eof
		_test_eof95:
			cs = 95
			goto _test_eof
		_test_eof96:
			cs = 96
			goto _test_eof
		_test_eof97:
			cs = 97
			goto _test_eof
		_test_eof98:
			cs = 98
			goto _test_eof
		_test_eof99:
			cs = 99
			goto _test_eof
		_test_eof100:
			cs = 100
			goto _test_eof
		_test_eof101:
			cs = 101
			goto _test_eof
		_test_eof102:
			cs = 102
			goto _test_eof
		_test_eof103:
			cs = 103
			goto _test_eof
		_test_eof104:
			cs = 104
			goto _test_eof
		_test_eof105:
			cs = 105
			goto _test_eof
		_test_eof106:
			cs = 106
			goto _test_eof
		_test_eof107:
			cs = 107
			goto _test_eof
		_test_eof108:
			cs = 108
			goto _test_eof
		_test_eof109:
			cs = 109
			goto _test_eof
		_test_eof110:
			cs = 110
			goto _test_eof
		_test_eof111:
			cs = 111
			goto _test_eof
		_test_eof112:
			cs = 112
			goto _test_eof
		_test_eof113:
			cs = 113
			goto _test_eof
		_test_eof114:
			cs = 114
			goto _test_eof
		_test_eof115:
			cs = 115
			goto _test_eof
		_test_eof116:
			cs = 116
			goto _test_eof
		_test_eof117:
			cs = 117
			goto _test_eof
		_test_eof118:
			cs = 118
			goto _test_eof
		_test_eof119:
			cs = 119
			goto _test_eof
		_test_eof120:
			cs = 120
			goto _test_eof
		_test_eof121:
			cs = 121
			goto _test_eof
		_test_eof122:
			cs = 122
			goto _test_eof
		_test_eof123:
			cs = 123
			goto _test_eof
		_test_eof124:
			cs = 124
			goto _test_eof
		_test_eof125:
			cs = 125
			goto _test_eof
		_test_eof126:
			cs = 126
			goto _test_eof
		_test_eof127:
			cs = 127
			goto _test_eof
		_test_eof128:
			cs = 128
			goto _test_eof
		_test_eof129:
			cs = 129
			goto _test_eof
		_test_eof130:
			cs = 130
			goto _test_eof
		_test_eof131:
			cs = 131
			goto _test_eof
		_test_eof132:
			cs = 132
			goto _test_eof
		_test_eof133:
			cs = 133
			goto _test_eof
		_test_eof134:
			cs = 134
			goto _test_eof
		_test_eof135:
			cs = 135
			goto _test_eof
		_test_eof136:
			cs = 136
			goto _test_eof
		_test_eof137:
			cs = 137
			goto _test_eof
		_test_eof138:
			cs = 138
			goto _test_eof
		_test_eof139:
			cs = 139
			goto _test_eof
		_test_eof140:
			cs = 140
			goto _test_eof

		_test_eof:
			{
			}
		_out:
			{
			}
		}

		// line 178 "zparse.rl"


		if eof > -1 {
			if cs < z_first_final {
				// No clue what I'm doing what so ever
				if p == pe {
					println("p", p, "pe", pe)
					println("cs", cs, "z_first_final", z_first_final)
					println("unexpected eof at line ", l)
					return nil
				} else {
					println("error at position ", p, "\"", data[mark:p], "\" at line ", l)
					return nil
				}
			}
		}
	*/
	return nil
}
