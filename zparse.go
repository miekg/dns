
// line 1 "zparse.rl"
package dns

// Parse RRs
// With the thankful help of gdnsd and the Go examples for Ragel.

import (
    "os"
    "io"
    "net"
    "strings"
    "strconv"
)

// A Parser represents a DNS master zone file parser for a 
// particular input stream.
type Parser struct {
    // nothing here yet
    buf    []byte
}

// NewParser create a new DNS master zone file parser from r.
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

//const _IOBUF = 65365 // See comments in gdnsd
const _IOBUF = 3e7

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

// Wrapper for strconv.Atoi*().
func atoi(s string) uint {
    i, err :=  strconv.Atoui(s)
    if err != nil {
        panic("not a number: " + s + " " + err.String())
    }
    return i
}


// line 71 "zparse.go"
var z_start int = 134
var z_first_final int = 134
var z_error int = 0

var z_en_main int = 134


// line 70 "zparse.rl"


// Token parses a zone file, but only returns the last RR read.
func (zp *Parser) RR() RR {
    z, err := zp.Zone()
    if err != nil {
        return nil
    }
    return z.Pop().(RR)
}

// All the NewReader stuff is expensive...
// only works for short io.Readers as we put the whole thing
// in a string -- needs to be extended for large files (sliding window).
func (zp *Parser) Zone() (z *Zone, err os.Error) {
        z = new(Zone)
        data := string(zp.buf)
        cs, p, pe := 0, 0, len(data)
        eof := len(data)

//        brace := false
        lines := 0
        mark := 0
        hdr := new(RR_Header)

        
// line 106 "zparse.go"
	cs = z_start

// line 109 "zparse.go"
	{
	if p == pe { goto _test_eof }
	switch cs {
	case -666: // i am a hack D:
tr33:
// line 5 "types.rl"
	{
        rdf := fields(data[mark:p], 1)
        rr := new(RR_A)
        rr.Hdr = *hdr
        rr.Hdr.Rrtype = TypeA
        rr.A = net.ParseIP(rdf[0])
        z.Push(rr)
    }
// line 101 "zparse.rl"
	{ lines++ }
	goto st134
tr40:
// line 14 "types.rl"
	{
        rdf := fields(data[mark:p], 1)
        rr := new(RR_AAAA)
        rr.Hdr = *hdr
        rr.Hdr.Rrtype = TypeAAAA
        rr.AAAA = net.ParseIP(rdf[0])
        z.Push(rr)
    }
// line 101 "zparse.rl"
	{ lines++ }
	goto st134
tr50:
// line 179 "types.rl"
	{
    }
// line 101 "zparse.rl"
	{ lines++ }
	goto st134
tr61:
// line 42 "types.rl"
	{
        rdf := fields(data[mark:p], 1)
        rr := new(RR_CNAME)
        rr.Hdr = *hdr
        rr.Hdr.Rrtype = TypeCNAME
        rr.Cname = rdf[0]
        z.Push(rr)
    }
// line 101 "zparse.rl"
	{ lines++ }
	goto st134
tr70:
// line 78 "types.rl"
	{
        rdf := fields(data[mark:p], 4)
        rr := new(RR_DLV)
        rr.Hdr = *hdr
        rr.Hdr.Rrtype = TypeDLV
        rr.KeyTag = uint16(atoi(rdf[0]))
        rr.Algorithm = uint8(atoi(rdf[1]))
        rr.DigestType = uint8(atoi(rdf[2]))
        rr.Digest = rdf[3]
        z.Push(rr)
    }
// line 101 "zparse.rl"
	{ lines++ }
	goto st134
tr79:
// line 185 "types.rl"
	{
    }
// line 101 "zparse.rl"
	{ lines++ }
	goto st134
tr87:
// line 102 "types.rl"
	{
        rdf := fields(data[mark:p], 4)
        rr := new(RR_DNSKEY)
        rr.Hdr = *hdr
        rr.Hdr.Rrtype = TypeDNSKEY
        rr.Flags = uint16(atoi(rdf[0]))
        rr.Protocol = uint8(atoi(rdf[1]))
        rr.Algorithm = uint8(atoi(rdf[2]))
        rr.PublicKey = rdf[3]
        z.Push(rr)
    }
// line 101 "zparse.rl"
	{ lines++ }
	goto st134
tr92:
// line 66 "types.rl"
	{
        rdf := fields(data[mark:p], 4)
        rr := new(RR_DS)
        rr.Hdr = *hdr
        rr.Hdr.Rrtype = TypeDS
        rr.KeyTag = uint16(atoi(rdf[0]))
        rr.Algorithm = uint8(atoi(rdf[1]))
        rr.DigestType = uint8(atoi(rdf[2]))
        rr.Digest = rdf[3]
        z.Push(rr)
    }
// line 101 "zparse.rl"
	{ lines++ }
	goto st134
tr98:
// line 32 "types.rl"
	{
        rdf := fields(data[mark:p], 2)
        rr := new(RR_MX)
        rr.Hdr = *hdr
        rr.Hdr.Rrtype = TypeMX
        rr.Pref = uint16(atoi(rdf[0]))
        rr.Mx = rdf[1]
        z.Push(rr)
    }
// line 101 "zparse.rl"
	{ lines++ }
	goto st134
tr108:
// line 188 "types.rl"
	{
    }
// line 101 "zparse.rl"
	{ lines++ }
	goto st134
tr114:
// line 23 "types.rl"
	{
        rdf := fields(data[mark:p], 1)
        rr := new(RR_NS)
        rr.Hdr = *hdr
        rr.Hdr.Rrtype = TypeNS
        rr.Ns = rdf[0]
        z.Push(rr)
    }
// line 101 "zparse.rl"
	{ lines++ }
	goto st134
tr121:
// line 131 "types.rl"
	{
        rdf := fields(data[mark:p], 0)
        rr := new(RR_NSEC)
        rr.Hdr = *hdr
        rr.Hdr.Rrtype = TypeNSEC
        rr.NextDomain = rdf[0]
        rr.TypeBitMap = make([]uint16, len(rdf)-1)
        // Fill the Type Bit Map
        for i := 1; i < len(rdf); i++ {
            // Check if its there in the map TODO
            rr.TypeBitMap[i-1] = Str_rr[rdf[i]]
        }
        z.Push(rr)
    }
// line 101 "zparse.rl"
	{ lines++ }
	goto st134
tr127:
// line 146 "types.rl"
	{
        rdf := fields(data[mark:p], 0)
        rr := new(RR_NSEC3)
        rr.Hdr = *hdr
        rr.Hdr.Rrtype = TypeNSEC3
        rr.Hash = uint8(atoi(rdf[0]))
        rr.Flags = uint8(atoi(rdf[1]))
        rr.Iterations = uint16(atoi(rdf[2]))
        rr.SaltLength = uint8(atoi(rdf[3]))
        rr.Salt = rdf[4]
        rr.HashLength = uint8(atoi(rdf[4]))
        rr.NextDomain = rdf[5]
        rr.TypeBitMap = make([]uint16, len(rdf)-6)
        // Fill the Type Bit Map
        for i := 6; i < len(rdf); i++ {
            // Check if its there in the map TODO
            rr.TypeBitMap[i-6] = Str_rr[rdf[i]]
        }
        z.Push(rr)
    }
// line 101 "zparse.rl"
	{ lines++ }
	goto st134
tr136:
// line 167 "types.rl"
	{
    }
// line 101 "zparse.rl"
	{ lines++ }
	goto st134
tr143:
// line 182 "types.rl"
	{
    }
// line 101 "zparse.rl"
	{ lines++ }
	goto st134
tr152:
// line 114 "types.rl"
	{
        rdf := fields(data[mark:p], 9)
        rr := new(RR_RRSIG)
        rr.Hdr = *hdr
        rr.Hdr.Rrtype = TypeRRSIG
        rr.TypeCovered = uint16(atoi(rdf[0]))
        rr.Algorithm = uint8(atoi(rdf[1]))
        rr.Labels = uint8(atoi(rdf[2]))
        rr.OrigTtl = uint32(atoi(rdf[3]))
        rr.Expiration = uint32(atoi(rdf[4]))
        rr.Inception = uint32(atoi(rdf[5]))
        rr.KeyTag = uint16(atoi(rdf[6]))
        rr.SignerName = rdf[7]
        rr.Signature = rdf[9]
        z.Push(rr)
    }
// line 101 "zparse.rl"
	{ lines++ }
	goto st134
tr160:
// line 51 "types.rl"
	{
        rdf := fields(data[mark:p], 7)
        rr := new(RR_SOA)
        rr.Hdr = *hdr
        rr.Hdr.Rrtype = TypeSOA
        rr.Ns = rdf[0]
        rr.Mbox = rdf[1]
        rr.Serial = uint32(atoi(rdf[2]))
        rr.Refresh = uint32(atoi(rdf[3]))
        rr.Retry = uint32(atoi(rdf[4]))
        rr.Expire = uint32(atoi(rdf[5]))
        rr.Minttl = uint32(atoi(rdf[6]))
        z.Push(rr)
    }
// line 101 "zparse.rl"
	{ lines++ }
	goto st134
tr166:
// line 176 "types.rl"
	{
    }
// line 101 "zparse.rl"
	{ lines++ }
	goto st134
tr173:
// line 90 "types.rl"
	{
        rdf := fields(data[mark:p], 4)
        rr := new(RR_TA)
        rr.Hdr = *hdr
        rr.Hdr.Rrtype = TypeTA
        rr.KeyTag = uint16(atoi(rdf[0]))
        rr.Algorithm = uint8(atoi(rdf[1]))
        rr.DigestType = uint8(atoi(rdf[2]))
        rr.Digest = rdf[3]
        z.Push(rr)
    }
// line 101 "zparse.rl"
	{ lines++ }
	goto st134
tr179:
// line 173 "types.rl"
	{
    }
// line 101 "zparse.rl"
	{ lines++ }
	goto st134
tr189:
// line 101 "zparse.rl"
	{ lines++ }
	goto st134
st134:
	p++
	if p == pe { goto _test_eof134 }
	fallthrough
case 134:
// line 386 "zparse.go"
	switch data[p] {
		case 9: goto st1
		case 10: goto tr189
		case 32: goto st1
		case 59: goto st133
		case 95: goto tr190
	}
	if data[p] < 48 {
		if 45 <= data[p] && data[p] <= 46 { goto tr190 }
	} else if data[p] > 57 {
		if data[p] > 90 {
			if 97 <= data[p] && data[p] <= 122 { goto tr190 }
		} else if data[p] >= 65 {
			goto tr190
		}
	} else {
		goto tr190
	}
	goto st0
st0:
cs = 0;
	goto _out;
tr186:
// line 97 "zparse.rl"
	{ hdr.Name = data[mark:p] }
	goto st1
st1:
	p++
	if p == pe { goto _test_eof1 }
	fallthrough
case 1:
// line 418 "zparse.go"
	switch data[p] {
		case 9: goto st1
		case 32: goto st1
		case 65: goto tr3
		case 67: goto tr4
		case 68: goto tr5
		case 72: goto tr6
		case 73: goto tr7
		case 77: goto tr8
		case 78: goto tr9
		case 80: goto tr10
		case 82: goto tr11
		case 83: goto tr12
		case 84: goto tr13
		case 97: goto tr3
		case 99: goto tr4
		case 100: goto tr5
		case 104: goto tr6
		case 105: goto tr7
		case 109: goto tr8
		case 110: goto tr9
		case 112: goto tr10
		case 114: goto tr11
		case 115: goto tr12
		case 116: goto tr13
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr2 }
	goto st0
tr2:
// line 99 "zparse.rl"
	{ /* ... */ }
// line 96 "zparse.rl"
	{ mark = p }
	goto st2
st2:
	p++
	if p == pe { goto _test_eof2 }
	fallthrough
case 2:
// line 458 "zparse.go"
	switch data[p] {
		case 9: goto tr14
		case 32: goto tr14
	}
	if 48 <= data[p] && data[p] <= 57 { goto st2 }
	goto st0
tr14:
// line 100 "zparse.rl"
	{ ttl := atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st3
st3:
	p++
	if p == pe { goto _test_eof3 }
	fallthrough
case 3:
// line 474 "zparse.go"
	switch data[p] {
		case 9: goto st3
		case 32: goto st3
		case 65: goto st4
		case 67: goto tr18
		case 68: goto st31
		case 72: goto tr20
		case 73: goto tr21
		case 77: goto st55
		case 78: goto st60
		case 80: goto st89
		case 82: goto st95
		case 83: goto st103
		case 84: goto st114
		case 97: goto st4
		case 99: goto tr18
		case 100: goto st31
		case 104: goto tr20
		case 105: goto tr21
		case 109: goto st55
		case 110: goto st60
		case 112: goto st89
		case 114: goto st95
		case 115: goto st103
		case 116: goto st114
	}
	goto st0
tr3:
// line 99 "zparse.rl"
	{ /* ... */ }
	goto st4
st4:
	p++
	if p == pe { goto _test_eof4 }
	fallthrough
case 4:
// line 511 "zparse.go"
	switch data[p] {
		case 9: goto st5
		case 32: goto st5
		case 65: goto st8
		case 97: goto st8
	}
	goto st0
st5:
	p++
	if p == pe { goto _test_eof5 }
	fallthrough
case 5:
	switch data[p] {
		case 9: goto tr31
		case 10: goto st0
		case 32: goto tr31
	}
	goto tr30
tr30:
// line 96 "zparse.rl"
	{ mark = p }
	goto st6
st6:
	p++
	if p == pe { goto _test_eof6 }
	fallthrough
case 6:
// line 539 "zparse.go"
	if data[p] == 10 { goto tr33 }
	goto st6
tr31:
// line 96 "zparse.rl"
	{ mark = p }
	goto st7
st7:
	p++
	if p == pe { goto _test_eof7 }
	fallthrough
case 7:
// line 551 "zparse.go"
	switch data[p] {
		case 9: goto tr31
		case 10: goto tr33
		case 32: goto tr31
	}
	goto tr30
st8:
	p++
	if p == pe { goto _test_eof8 }
	fallthrough
case 8:
	switch data[p] {
		case 65: goto st9
		case 97: goto st9
	}
	goto st0
st9:
	p++
	if p == pe { goto _test_eof9 }
	fallthrough
case 9:
	switch data[p] {
		case 65: goto st10
		case 97: goto st10
	}
	goto st0
st10:
	p++
	if p == pe { goto _test_eof10 }
	fallthrough
case 10:
	switch data[p] {
		case 9: goto st11
		case 32: goto st11
	}
	goto st0
st11:
	p++
	if p == pe { goto _test_eof11 }
	fallthrough
case 11:
	switch data[p] {
		case 9: goto tr38
		case 10: goto st0
		case 32: goto tr38
	}
	goto tr37
tr37:
// line 96 "zparse.rl"
	{ mark = p }
	goto st12
st12:
	p++
	if p == pe { goto _test_eof12 }
	fallthrough
case 12:
// line 608 "zparse.go"
	if data[p] == 10 { goto tr40 }
	goto st12
tr38:
// line 96 "zparse.rl"
	{ mark = p }
	goto st13
st13:
	p++
	if p == pe { goto _test_eof13 }
	fallthrough
case 13:
// line 620 "zparse.go"
	switch data[p] {
		case 9: goto tr38
		case 10: goto tr40
		case 32: goto tr38
	}
	goto tr37
tr18:
// line 96 "zparse.rl"
	{ mark = p }
	goto st14
st14:
	p++
	if p == pe { goto _test_eof14 }
	fallthrough
case 14:
// line 636 "zparse.go"
	switch data[p] {
		case 69: goto st15
		case 72: goto st21
		case 78: goto st24
		case 101: goto st15
		case 104: goto st21
		case 110: goto st24
	}
	goto st0
st15:
	p++
	if p == pe { goto _test_eof15 }
	fallthrough
case 15:
	switch data[p] {
		case 82: goto st16
		case 114: goto st16
	}
	goto st0
st16:
	p++
	if p == pe { goto _test_eof16 }
	fallthrough
case 16:
	switch data[p] {
		case 84: goto st17
		case 116: goto st17
	}
	goto st0
st17:
	p++
	if p == pe { goto _test_eof17 }
	fallthrough
case 17:
	switch data[p] {
		case 9: goto st18
		case 32: goto st18
	}
	goto st0
st18:
	p++
	if p == pe { goto _test_eof18 }
	fallthrough
case 18:
	switch data[p] {
		case 9: goto tr48
		case 10: goto st0
		case 32: goto tr48
	}
	goto tr47
tr47:
// line 96 "zparse.rl"
	{ mark = p }
	goto st19
st19:
	p++
	if p == pe { goto _test_eof19 }
	fallthrough
case 19:
// line 696 "zparse.go"
	if data[p] == 10 { goto tr50 }
	goto st19
tr48:
// line 96 "zparse.rl"
	{ mark = p }
	goto st20
st20:
	p++
	if p == pe { goto _test_eof20 }
	fallthrough
case 20:
// line 708 "zparse.go"
	switch data[p] {
		case 9: goto tr48
		case 10: goto tr50
		case 32: goto tr48
	}
	goto tr47
st21:
	p++
	if p == pe { goto _test_eof21 }
	fallthrough
case 21:
	switch data[p] {
		case 9: goto tr51
		case 32: goto tr51
	}
	goto st0
tr184:
// line 100 "zparse.rl"
	{ ttl := atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st22
tr51:
// line 98 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st22
st22:
	p++
	if p == pe { goto _test_eof22 }
	fallthrough
case 22:
// line 738 "zparse.go"
	switch data[p] {
		case 9: goto st22
		case 32: goto st22
		case 65: goto st4
		case 67: goto st23
		case 68: goto st31
		case 77: goto st55
		case 78: goto st60
		case 80: goto st89
		case 82: goto st95
		case 83: goto st103
		case 84: goto st114
		case 97: goto st4
		case 99: goto st23
		case 100: goto st31
		case 109: goto st55
		case 110: goto st60
		case 112: goto st89
		case 114: goto st95
		case 115: goto st103
		case 116: goto st114
	}
	goto st0
st23:
	p++
	if p == pe { goto _test_eof23 }
	fallthrough
case 23:
	switch data[p] {
		case 69: goto st15
		case 78: goto st24
		case 101: goto st15
		case 110: goto st24
	}
	goto st0
st24:
	p++
	if p == pe { goto _test_eof24 }
	fallthrough
case 24:
	switch data[p] {
		case 65: goto st25
		case 97: goto st25
	}
	goto st0
st25:
	p++
	if p == pe { goto _test_eof25 }
	fallthrough
case 25:
	switch data[p] {
		case 77: goto st26
		case 109: goto st26
	}
	goto st0
st26:
	p++
	if p == pe { goto _test_eof26 }
	fallthrough
case 26:
	switch data[p] {
		case 69: goto st27
		case 101: goto st27
	}
	goto st0
st27:
	p++
	if p == pe { goto _test_eof27 }
	fallthrough
case 27:
	switch data[p] {
		case 9: goto st28
		case 32: goto st28
	}
	goto st0
st28:
	p++
	if p == pe { goto _test_eof28 }
	fallthrough
case 28:
	switch data[p] {
		case 9: goto tr59
		case 10: goto st0
		case 32: goto tr59
	}
	goto tr58
tr58:
// line 96 "zparse.rl"
	{ mark = p }
	goto st29
st29:
	p++
	if p == pe { goto _test_eof29 }
	fallthrough
case 29:
// line 834 "zparse.go"
	if data[p] == 10 { goto tr61 }
	goto st29
tr59:
// line 96 "zparse.rl"
	{ mark = p }
	goto st30
st30:
	p++
	if p == pe { goto _test_eof30 }
	fallthrough
case 30:
// line 846 "zparse.go"
	switch data[p] {
		case 9: goto tr59
		case 10: goto tr61
		case 32: goto tr59
	}
	goto tr58
tr5:
// line 99 "zparse.rl"
	{ /* ... */ }
	goto st31
st31:
	p++
	if p == pe { goto _test_eof31 }
	fallthrough
case 31:
// line 862 "zparse.go"
	switch data[p] {
		case 76: goto st32
		case 78: goto st37
		case 83: goto st51
		case 108: goto st32
		case 110: goto st37
		case 115: goto st51
	}
	goto st0
st32:
	p++
	if p == pe { goto _test_eof32 }
	fallthrough
case 32:
	switch data[p] {
		case 86: goto st33
		case 118: goto st33
	}
	goto st0
st33:
	p++
	if p == pe { goto _test_eof33 }
	fallthrough
case 33:
	switch data[p] {
		case 9: goto st34
		case 32: goto st34
	}
	goto st0
st34:
	p++
	if p == pe { goto _test_eof34 }
	fallthrough
case 34:
	switch data[p] {
		case 9: goto tr68
		case 10: goto st0
		case 32: goto tr68
	}
	goto tr67
tr67:
// line 96 "zparse.rl"
	{ mark = p }
	goto st35
st35:
	p++
	if p == pe { goto _test_eof35 }
	fallthrough
case 35:
// line 912 "zparse.go"
	if data[p] == 10 { goto tr70 }
	goto st35
tr68:
// line 96 "zparse.rl"
	{ mark = p }
	goto st36
st36:
	p++
	if p == pe { goto _test_eof36 }
	fallthrough
case 36:
// line 924 "zparse.go"
	switch data[p] {
		case 9: goto tr68
		case 10: goto tr70
		case 32: goto tr68
	}
	goto tr67
st37:
	p++
	if p == pe { goto _test_eof37 }
	fallthrough
case 37:
	switch data[p] {
		case 65: goto st38
		case 83: goto st44
		case 97: goto st38
		case 115: goto st44
	}
	goto st0
st38:
	p++
	if p == pe { goto _test_eof38 }
	fallthrough
case 38:
	switch data[p] {
		case 77: goto st39
		case 109: goto st39
	}
	goto st0
st39:
	p++
	if p == pe { goto _test_eof39 }
	fallthrough
case 39:
	switch data[p] {
		case 69: goto st40
		case 101: goto st40
	}
	goto st0
st40:
	p++
	if p == pe { goto _test_eof40 }
	fallthrough
case 40:
	switch data[p] {
		case 9: goto st41
		case 32: goto st41
	}
	goto st0
st41:
	p++
	if p == pe { goto _test_eof41 }
	fallthrough
case 41:
	switch data[p] {
		case 9: goto tr77
		case 10: goto st0
		case 32: goto tr77
	}
	goto tr76
tr76:
// line 96 "zparse.rl"
	{ mark = p }
	goto st42
st42:
	p++
	if p == pe { goto _test_eof42 }
	fallthrough
case 42:
// line 993 "zparse.go"
	if data[p] == 10 { goto tr79 }
	goto st42
tr77:
// line 96 "zparse.rl"
	{ mark = p }
	goto st43
st43:
	p++
	if p == pe { goto _test_eof43 }
	fallthrough
case 43:
// line 1005 "zparse.go"
	switch data[p] {
		case 9: goto tr77
		case 10: goto tr79
		case 32: goto tr77
	}
	goto tr76
st44:
	p++
	if p == pe { goto _test_eof44 }
	fallthrough
case 44:
	switch data[p] {
		case 75: goto st45
		case 107: goto st45
	}
	goto st0
st45:
	p++
	if p == pe { goto _test_eof45 }
	fallthrough
case 45:
	switch data[p] {
		case 69: goto st46
		case 101: goto st46
	}
	goto st0
st46:
	p++
	if p == pe { goto _test_eof46 }
	fallthrough
case 46:
	switch data[p] {
		case 89: goto st47
		case 121: goto st47
	}
	goto st0
st47:
	p++
	if p == pe { goto _test_eof47 }
	fallthrough
case 47:
	switch data[p] {
		case 9: goto st48
		case 32: goto st48
	}
	goto st0
st48:
	p++
	if p == pe { goto _test_eof48 }
	fallthrough
case 48:
	switch data[p] {
		case 9: goto tr85
		case 10: goto st0
		case 32: goto tr85
	}
	goto tr84
tr84:
// line 96 "zparse.rl"
	{ mark = p }
	goto st49
st49:
	p++
	if p == pe { goto _test_eof49 }
	fallthrough
case 49:
// line 1072 "zparse.go"
	if data[p] == 10 { goto tr87 }
	goto st49
tr85:
// line 96 "zparse.rl"
	{ mark = p }
	goto st50
st50:
	p++
	if p == pe { goto _test_eof50 }
	fallthrough
case 50:
// line 1084 "zparse.go"
	switch data[p] {
		case 9: goto tr85
		case 10: goto tr87
		case 32: goto tr85
	}
	goto tr84
st51:
	p++
	if p == pe { goto _test_eof51 }
	fallthrough
case 51:
	switch data[p] {
		case 9: goto st52
		case 32: goto st52
	}
	goto st0
st52:
	p++
	if p == pe { goto _test_eof52 }
	fallthrough
case 52:
	switch data[p] {
		case 9: goto tr90
		case 10: goto st0
		case 32: goto tr90
	}
	goto tr89
tr89:
// line 96 "zparse.rl"
	{ mark = p }
	goto st53
st53:
	p++
	if p == pe { goto _test_eof53 }
	fallthrough
case 53:
// line 1121 "zparse.go"
	if data[p] == 10 { goto tr92 }
	goto st53
tr90:
// line 96 "zparse.rl"
	{ mark = p }
	goto st54
st54:
	p++
	if p == pe { goto _test_eof54 }
	fallthrough
case 54:
// line 1133 "zparse.go"
	switch data[p] {
		case 9: goto tr90
		case 10: goto tr92
		case 32: goto tr90
	}
	goto tr89
tr8:
// line 99 "zparse.rl"
	{ /* ... */ }
	goto st55
st55:
	p++
	if p == pe { goto _test_eof55 }
	fallthrough
case 55:
// line 1149 "zparse.go"
	switch data[p] {
		case 88: goto st56
		case 120: goto st56
	}
	goto st0
st56:
	p++
	if p == pe { goto _test_eof56 }
	fallthrough
case 56:
	switch data[p] {
		case 9: goto st57
		case 32: goto st57
	}
	goto st0
st57:
	p++
	if p == pe { goto _test_eof57 }
	fallthrough
case 57:
	switch data[p] {
		case 9: goto tr96
		case 10: goto st0
		case 32: goto tr96
	}
	goto tr95
tr95:
// line 96 "zparse.rl"
	{ mark = p }
	goto st58
st58:
	p++
	if p == pe { goto _test_eof58 }
	fallthrough
case 58:
// line 1185 "zparse.go"
	if data[p] == 10 { goto tr98 }
	goto st58
tr96:
// line 96 "zparse.rl"
	{ mark = p }
	goto st59
st59:
	p++
	if p == pe { goto _test_eof59 }
	fallthrough
case 59:
// line 1197 "zparse.go"
	switch data[p] {
		case 9: goto tr96
		case 10: goto tr98
		case 32: goto tr96
	}
	goto tr95
tr9:
// line 99 "zparse.rl"
	{ /* ... */ }
	goto st60
st60:
	p++
	if p == pe { goto _test_eof60 }
	fallthrough
case 60:
// line 1213 "zparse.go"
	switch data[p] {
		case 65: goto st61
		case 83: goto st68
		case 97: goto st61
		case 115: goto st68
	}
	goto st0
st61:
	p++
	if p == pe { goto _test_eof61 }
	fallthrough
case 61:
	switch data[p] {
		case 80: goto st62
		case 112: goto st62
	}
	goto st0
st62:
	p++
	if p == pe { goto _test_eof62 }
	fallthrough
case 62:
	switch data[p] {
		case 84: goto st63
		case 116: goto st63
	}
	goto st0
st63:
	p++
	if p == pe { goto _test_eof63 }
	fallthrough
case 63:
	switch data[p] {
		case 82: goto st64
		case 114: goto st64
	}
	goto st0
st64:
	p++
	if p == pe { goto _test_eof64 }
	fallthrough
case 64:
	switch data[p] {
		case 9: goto st65
		case 32: goto st65
	}
	goto st0
st65:
	p++
	if p == pe { goto _test_eof65 }
	fallthrough
case 65:
	switch data[p] {
		case 9: goto tr106
		case 10: goto st0
		case 32: goto tr106
	}
	goto tr105
tr105:
// line 96 "zparse.rl"
	{ mark = p }
	goto st66
st66:
	p++
	if p == pe { goto _test_eof66 }
	fallthrough
case 66:
// line 1281 "zparse.go"
	if data[p] == 10 { goto tr108 }
	goto st66
tr106:
// line 96 "zparse.rl"
	{ mark = p }
	goto st67
st67:
	p++
	if p == pe { goto _test_eof67 }
	fallthrough
case 67:
// line 1293 "zparse.go"
	switch data[p] {
		case 9: goto tr106
		case 10: goto tr108
		case 32: goto tr106
	}
	goto tr105
st68:
	p++
	if p == pe { goto _test_eof68 }
	fallthrough
case 68:
	switch data[p] {
		case 9: goto st69
		case 32: goto st69
		case 69: goto st72
		case 101: goto st72
	}
	goto st0
st69:
	p++
	if p == pe { goto _test_eof69 }
	fallthrough
case 69:
	switch data[p] {
		case 9: goto tr112
		case 10: goto st0
		case 32: goto tr112
	}
	goto tr111
tr111:
// line 96 "zparse.rl"
	{ mark = p }
	goto st70
st70:
	p++
	if p == pe { goto _test_eof70 }
	fallthrough
case 70:
// line 1332 "zparse.go"
	if data[p] == 10 { goto tr114 }
	goto st70
tr112:
// line 96 "zparse.rl"
	{ mark = p }
	goto st71
st71:
	p++
	if p == pe { goto _test_eof71 }
	fallthrough
case 71:
// line 1344 "zparse.go"
	switch data[p] {
		case 9: goto tr112
		case 10: goto tr114
		case 32: goto tr112
	}
	goto tr111
st72:
	p++
	if p == pe { goto _test_eof72 }
	fallthrough
case 72:
	switch data[p] {
		case 67: goto st73
		case 99: goto st73
	}
	goto st0
st73:
	p++
	if p == pe { goto _test_eof73 }
	fallthrough
case 73:
	switch data[p] {
		case 9: goto st74
		case 32: goto st74
		case 51: goto st77
	}
	goto st0
st74:
	p++
	if p == pe { goto _test_eof74 }
	fallthrough
case 74:
	switch data[p] {
		case 9: goto tr119
		case 10: goto st0
		case 32: goto tr119
	}
	goto tr118
tr118:
// line 96 "zparse.rl"
	{ mark = p }
	goto st75
st75:
	p++
	if p == pe { goto _test_eof75 }
	fallthrough
case 75:
// line 1392 "zparse.go"
	if data[p] == 10 { goto tr121 }
	goto st75
tr119:
// line 96 "zparse.rl"
	{ mark = p }
	goto st76
st76:
	p++
	if p == pe { goto _test_eof76 }
	fallthrough
case 76:
// line 1404 "zparse.go"
	switch data[p] {
		case 9: goto tr119
		case 10: goto tr121
		case 32: goto tr119
	}
	goto tr118
st77:
	p++
	if p == pe { goto _test_eof77 }
	fallthrough
case 77:
	switch data[p] {
		case 9: goto st78
		case 32: goto st78
		case 80: goto st81
		case 112: goto st81
	}
	goto st0
st78:
	p++
	if p == pe { goto _test_eof78 }
	fallthrough
case 78:
	switch data[p] {
		case 9: goto tr125
		case 10: goto st0
		case 32: goto tr125
	}
	goto tr124
tr124:
// line 96 "zparse.rl"
	{ mark = p }
	goto st79
st79:
	p++
	if p == pe { goto _test_eof79 }
	fallthrough
case 79:
// line 1443 "zparse.go"
	if data[p] == 10 { goto tr127 }
	goto st79
tr125:
// line 96 "zparse.rl"
	{ mark = p }
	goto st80
st80:
	p++
	if p == pe { goto _test_eof80 }
	fallthrough
case 80:
// line 1455 "zparse.go"
	switch data[p] {
		case 9: goto tr125
		case 10: goto tr127
		case 32: goto tr125
	}
	goto tr124
st81:
	p++
	if p == pe { goto _test_eof81 }
	fallthrough
case 81:
	switch data[p] {
		case 65: goto st82
		case 97: goto st82
	}
	goto st0
st82:
	p++
	if p == pe { goto _test_eof82 }
	fallthrough
case 82:
	switch data[p] {
		case 82: goto st83
		case 114: goto st83
	}
	goto st0
st83:
	p++
	if p == pe { goto _test_eof83 }
	fallthrough
case 83:
	switch data[p] {
		case 65: goto st84
		case 97: goto st84
	}
	goto st0
st84:
	p++
	if p == pe { goto _test_eof84 }
	fallthrough
case 84:
	switch data[p] {
		case 77: goto st85
		case 109: goto st85
	}
	goto st0
st85:
	p++
	if p == pe { goto _test_eof85 }
	fallthrough
case 85:
	switch data[p] {
		case 9: goto st86
		case 32: goto st86
	}
	goto st0
st86:
	p++
	if p == pe { goto _test_eof86 }
	fallthrough
case 86:
	switch data[p] {
		case 9: goto tr134
		case 10: goto st0
		case 32: goto tr134
	}
	goto tr133
tr133:
// line 96 "zparse.rl"
	{ mark = p }
	goto st87
st87:
	p++
	if p == pe { goto _test_eof87 }
	fallthrough
case 87:
// line 1532 "zparse.go"
	if data[p] == 10 { goto tr136 }
	goto st87
tr134:
// line 96 "zparse.rl"
	{ mark = p }
	goto st88
st88:
	p++
	if p == pe { goto _test_eof88 }
	fallthrough
case 88:
// line 1544 "zparse.go"
	switch data[p] {
		case 9: goto tr134
		case 10: goto tr136
		case 32: goto tr134
	}
	goto tr133
tr10:
// line 99 "zparse.rl"
	{ /* ... */ }
	goto st89
st89:
	p++
	if p == pe { goto _test_eof89 }
	fallthrough
case 89:
// line 1560 "zparse.go"
	switch data[p] {
		case 84: goto st90
		case 116: goto st90
	}
	goto st0
st90:
	p++
	if p == pe { goto _test_eof90 }
	fallthrough
case 90:
	switch data[p] {
		case 82: goto st91
		case 114: goto st91
	}
	goto st0
st91:
	p++
	if p == pe { goto _test_eof91 }
	fallthrough
case 91:
	switch data[p] {
		case 9: goto st92
		case 32: goto st92
	}
	goto st0
st92:
	p++
	if p == pe { goto _test_eof92 }
	fallthrough
case 92:
	switch data[p] {
		case 9: goto tr141
		case 10: goto st0
		case 32: goto tr141
	}
	goto tr140
tr140:
// line 96 "zparse.rl"
	{ mark = p }
	goto st93
st93:
	p++
	if p == pe { goto _test_eof93 }
	fallthrough
case 93:
// line 1606 "zparse.go"
	if data[p] == 10 { goto tr143 }
	goto st93
tr141:
// line 96 "zparse.rl"
	{ mark = p }
	goto st94
st94:
	p++
	if p == pe { goto _test_eof94 }
	fallthrough
case 94:
// line 1618 "zparse.go"
	switch data[p] {
		case 9: goto tr141
		case 10: goto tr143
		case 32: goto tr141
	}
	goto tr140
tr11:
// line 99 "zparse.rl"
	{ /* ... */ }
	goto st95
st95:
	p++
	if p == pe { goto _test_eof95 }
	fallthrough
case 95:
// line 1634 "zparse.go"
	switch data[p] {
		case 82: goto st96
		case 114: goto st96
	}
	goto st0
st96:
	p++
	if p == pe { goto _test_eof96 }
	fallthrough
case 96:
	switch data[p] {
		case 83: goto st97
		case 115: goto st97
	}
	goto st0
st97:
	p++
	if p == pe { goto _test_eof97 }
	fallthrough
case 97:
	switch data[p] {
		case 73: goto st98
		case 105: goto st98
	}
	goto st0
st98:
	p++
	if p == pe { goto _test_eof98 }
	fallthrough
case 98:
	switch data[p] {
		case 71: goto st99
		case 103: goto st99
	}
	goto st0
st99:
	p++
	if p == pe { goto _test_eof99 }
	fallthrough
case 99:
	switch data[p] {
		case 9: goto st100
		case 32: goto st100
	}
	goto st0
st100:
	p++
	if p == pe { goto _test_eof100 }
	fallthrough
case 100:
	switch data[p] {
		case 9: goto tr150
		case 10: goto st0
		case 32: goto tr150
	}
	goto tr149
tr149:
// line 96 "zparse.rl"
	{ mark = p }
	goto st101
st101:
	p++
	if p == pe { goto _test_eof101 }
	fallthrough
case 101:
// line 1700 "zparse.go"
	if data[p] == 10 { goto tr152 }
	goto st101
tr150:
// line 96 "zparse.rl"
	{ mark = p }
	goto st102
st102:
	p++
	if p == pe { goto _test_eof102 }
	fallthrough
case 102:
// line 1712 "zparse.go"
	switch data[p] {
		case 9: goto tr150
		case 10: goto tr152
		case 32: goto tr150
	}
	goto tr149
tr12:
// line 99 "zparse.rl"
	{ /* ... */ }
	goto st103
st103:
	p++
	if p == pe { goto _test_eof103 }
	fallthrough
case 103:
// line 1728 "zparse.go"
	switch data[p] {
		case 79: goto st104
		case 82: goto st109
		case 111: goto st104
		case 114: goto st109
	}
	goto st0
st104:
	p++
	if p == pe { goto _test_eof104 }
	fallthrough
case 104:
	switch data[p] {
		case 65: goto st105
		case 97: goto st105
	}
	goto st0
st105:
	p++
	if p == pe { goto _test_eof105 }
	fallthrough
case 105:
	switch data[p] {
		case 9: goto st106
		case 32: goto st106
	}
	goto st0
st106:
	p++
	if p == pe { goto _test_eof106 }
	fallthrough
case 106:
	switch data[p] {
		case 9: goto tr158
		case 10: goto st0
		case 32: goto tr158
	}
	goto tr157
tr157:
// line 96 "zparse.rl"
	{ mark = p }
	goto st107
st107:
	p++
	if p == pe { goto _test_eof107 }
	fallthrough
case 107:
// line 1776 "zparse.go"
	if data[p] == 10 { goto tr160 }
	goto st107
tr158:
// line 96 "zparse.rl"
	{ mark = p }
	goto st108
st108:
	p++
	if p == pe { goto _test_eof108 }
	fallthrough
case 108:
// line 1788 "zparse.go"
	switch data[p] {
		case 9: goto tr158
		case 10: goto tr160
		case 32: goto tr158
	}
	goto tr157
st109:
	p++
	if p == pe { goto _test_eof109 }
	fallthrough
case 109:
	switch data[p] {
		case 86: goto st110
		case 118: goto st110
	}
	goto st0
st110:
	p++
	if p == pe { goto _test_eof110 }
	fallthrough
case 110:
	switch data[p] {
		case 9: goto st111
		case 32: goto st111
	}
	goto st0
st111:
	p++
	if p == pe { goto _test_eof111 }
	fallthrough
case 111:
	switch data[p] {
		case 9: goto tr164
		case 10: goto st0
		case 32: goto tr164
	}
	goto tr163
tr163:
// line 96 "zparse.rl"
	{ mark = p }
	goto st112
st112:
	p++
	if p == pe { goto _test_eof112 }
	fallthrough
case 112:
// line 1835 "zparse.go"
	if data[p] == 10 { goto tr166 }
	goto st112
tr164:
// line 96 "zparse.rl"
	{ mark = p }
	goto st113
st113:
	p++
	if p == pe { goto _test_eof113 }
	fallthrough
case 113:
// line 1847 "zparse.go"
	switch data[p] {
		case 9: goto tr164
		case 10: goto tr166
		case 32: goto tr164
	}
	goto tr163
tr13:
// line 99 "zparse.rl"
	{ /* ... */ }
	goto st114
st114:
	p++
	if p == pe { goto _test_eof114 }
	fallthrough
case 114:
// line 1863 "zparse.go"
	switch data[p] {
		case 65: goto st115
		case 88: goto st119
		case 97: goto st115
		case 120: goto st119
	}
	goto st0
st115:
	p++
	if p == pe { goto _test_eof115 }
	fallthrough
case 115:
	switch data[p] {
		case 9: goto st116
		case 32: goto st116
	}
	goto st0
st116:
	p++
	if p == pe { goto _test_eof116 }
	fallthrough
case 116:
	switch data[p] {
		case 9: goto tr171
		case 10: goto st0
		case 32: goto tr171
	}
	goto tr170
tr170:
// line 96 "zparse.rl"
	{ mark = p }
	goto st117
st117:
	p++
	if p == pe { goto _test_eof117 }
	fallthrough
case 117:
// line 1901 "zparse.go"
	if data[p] == 10 { goto tr173 }
	goto st117
tr171:
// line 96 "zparse.rl"
	{ mark = p }
	goto st118
st118:
	p++
	if p == pe { goto _test_eof118 }
	fallthrough
case 118:
// line 1913 "zparse.go"
	switch data[p] {
		case 9: goto tr171
		case 10: goto tr173
		case 32: goto tr171
	}
	goto tr170
st119:
	p++
	if p == pe { goto _test_eof119 }
	fallthrough
case 119:
	switch data[p] {
		case 84: goto st120
		case 116: goto st120
	}
	goto st0
st120:
	p++
	if p == pe { goto _test_eof120 }
	fallthrough
case 120:
	switch data[p] {
		case 9: goto st121
		case 32: goto st121
	}
	goto st0
st121:
	p++
	if p == pe { goto _test_eof121 }
	fallthrough
case 121:
	switch data[p] {
		case 9: goto tr177
		case 10: goto st0
		case 32: goto tr177
	}
	goto tr176
tr176:
// line 96 "zparse.rl"
	{ mark = p }
	goto st122
st122:
	p++
	if p == pe { goto _test_eof122 }
	fallthrough
case 122:
// line 1960 "zparse.go"
	if data[p] == 10 { goto tr179 }
	goto st122
tr177:
// line 96 "zparse.rl"
	{ mark = p }
	goto st123
st123:
	p++
	if p == pe { goto _test_eof123 }
	fallthrough
case 123:
// line 1972 "zparse.go"
	switch data[p] {
		case 9: goto tr177
		case 10: goto tr179
		case 32: goto tr177
	}
	goto tr176
tr20:
// line 96 "zparse.rl"
	{ mark = p }
	goto st124
st124:
	p++
	if p == pe { goto _test_eof124 }
	fallthrough
case 124:
// line 1988 "zparse.go"
	switch data[p] {
		case 83: goto st21
		case 115: goto st21
	}
	goto st0
tr21:
// line 96 "zparse.rl"
	{ mark = p }
	goto st125
st125:
	p++
	if p == pe { goto _test_eof125 }
	fallthrough
case 125:
// line 2003 "zparse.go"
	switch data[p] {
		case 78: goto st21
		case 110: goto st21
	}
	goto st0
tr4:
// line 99 "zparse.rl"
	{ /* ... */ }
// line 96 "zparse.rl"
	{ mark = p }
	goto st126
st126:
	p++
	if p == pe { goto _test_eof126 }
	fallthrough
case 126:
// line 2020 "zparse.go"
	switch data[p] {
		case 69: goto st15
		case 72: goto st127
		case 78: goto st24
		case 101: goto st15
		case 104: goto st127
		case 110: goto st24
	}
	goto st0
st127:
	p++
	if p == pe { goto _test_eof127 }
	fallthrough
case 127:
	switch data[p] {
		case 9: goto tr181
		case 32: goto tr181
	}
	goto st0
tr181:
// line 98 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st128
st128:
	p++
	if p == pe { goto _test_eof128 }
	fallthrough
case 128:
// line 2049 "zparse.go"
	switch data[p] {
		case 9: goto st128
		case 32: goto st128
		case 65: goto st4
		case 67: goto st23
		case 68: goto st31
		case 77: goto st55
		case 78: goto st60
		case 80: goto st89
		case 82: goto st95
		case 83: goto st103
		case 84: goto st114
		case 97: goto st4
		case 99: goto st23
		case 100: goto st31
		case 109: goto st55
		case 110: goto st60
		case 112: goto st89
		case 114: goto st95
		case 115: goto st103
		case 116: goto st114
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr183 }
	goto st0
tr183:
// line 96 "zparse.rl"
	{ mark = p }
	goto st129
st129:
	p++
	if p == pe { goto _test_eof129 }
	fallthrough
case 129:
// line 2083 "zparse.go"
	switch data[p] {
		case 9: goto tr184
		case 32: goto tr184
	}
	if 48 <= data[p] && data[p] <= 57 { goto st129 }
	goto st0
tr6:
// line 99 "zparse.rl"
	{ /* ... */ }
// line 96 "zparse.rl"
	{ mark = p }
	goto st130
st130:
	p++
	if p == pe { goto _test_eof130 }
	fallthrough
case 130:
// line 2101 "zparse.go"
	switch data[p] {
		case 83: goto st127
		case 115: goto st127
	}
	goto st0
tr7:
// line 99 "zparse.rl"
	{ /* ... */ }
// line 96 "zparse.rl"
	{ mark = p }
	goto st131
st131:
	p++
	if p == pe { goto _test_eof131 }
	fallthrough
case 131:
// line 2118 "zparse.go"
	switch data[p] {
		case 78: goto st127
		case 110: goto st127
	}
	goto st0
tr190:
// line 96 "zparse.rl"
	{ mark = p }
	goto st132
st132:
	p++
	if p == pe { goto _test_eof132 }
	fallthrough
case 132:
// line 2133 "zparse.go"
	switch data[p] {
		case 9: goto tr186
		case 32: goto tr186
		case 95: goto st132
	}
	if data[p] < 48 {
		if 45 <= data[p] && data[p] <= 46 { goto st132 }
	} else if data[p] > 57 {
		if data[p] > 90 {
			if 97 <= data[p] && data[p] <= 122 { goto st132 }
		} else if data[p] >= 65 {
			goto st132
		}
	} else {
		goto st132
	}
	goto st0
st133:
	p++
	if p == pe { goto _test_eof133 }
	fallthrough
case 133:
	if data[p] == 10 { goto tr189 }
	goto st133
	}
	_test_eof134: cs = 134; goto _test_eof; 
	_test_eof1: cs = 1; goto _test_eof; 
	_test_eof2: cs = 2; goto _test_eof; 
	_test_eof3: cs = 3; goto _test_eof; 
	_test_eof4: cs = 4; goto _test_eof; 
	_test_eof5: cs = 5; goto _test_eof; 
	_test_eof6: cs = 6; goto _test_eof; 
	_test_eof7: cs = 7; goto _test_eof; 
	_test_eof8: cs = 8; goto _test_eof; 
	_test_eof9: cs = 9; goto _test_eof; 
	_test_eof10: cs = 10; goto _test_eof; 
	_test_eof11: cs = 11; goto _test_eof; 
	_test_eof12: cs = 12; goto _test_eof; 
	_test_eof13: cs = 13; goto _test_eof; 
	_test_eof14: cs = 14; goto _test_eof; 
	_test_eof15: cs = 15; goto _test_eof; 
	_test_eof16: cs = 16; goto _test_eof; 
	_test_eof17: cs = 17; goto _test_eof; 
	_test_eof18: cs = 18; goto _test_eof; 
	_test_eof19: cs = 19; goto _test_eof; 
	_test_eof20: cs = 20; goto _test_eof; 
	_test_eof21: cs = 21; goto _test_eof; 
	_test_eof22: cs = 22; goto _test_eof; 
	_test_eof23: cs = 23; goto _test_eof; 
	_test_eof24: cs = 24; goto _test_eof; 
	_test_eof25: cs = 25; goto _test_eof; 
	_test_eof26: cs = 26; goto _test_eof; 
	_test_eof27: cs = 27; goto _test_eof; 
	_test_eof28: cs = 28; goto _test_eof; 
	_test_eof29: cs = 29; goto _test_eof; 
	_test_eof30: cs = 30; goto _test_eof; 
	_test_eof31: cs = 31; goto _test_eof; 
	_test_eof32: cs = 32; goto _test_eof; 
	_test_eof33: cs = 33; goto _test_eof; 
	_test_eof34: cs = 34; goto _test_eof; 
	_test_eof35: cs = 35; goto _test_eof; 
	_test_eof36: cs = 36; goto _test_eof; 
	_test_eof37: cs = 37; goto _test_eof; 
	_test_eof38: cs = 38; goto _test_eof; 
	_test_eof39: cs = 39; goto _test_eof; 
	_test_eof40: cs = 40; goto _test_eof; 
	_test_eof41: cs = 41; goto _test_eof; 
	_test_eof42: cs = 42; goto _test_eof; 
	_test_eof43: cs = 43; goto _test_eof; 
	_test_eof44: cs = 44; goto _test_eof; 
	_test_eof45: cs = 45; goto _test_eof; 
	_test_eof46: cs = 46; goto _test_eof; 
	_test_eof47: cs = 47; goto _test_eof; 
	_test_eof48: cs = 48; goto _test_eof; 
	_test_eof49: cs = 49; goto _test_eof; 
	_test_eof50: cs = 50; goto _test_eof; 
	_test_eof51: cs = 51; goto _test_eof; 
	_test_eof52: cs = 52; goto _test_eof; 
	_test_eof53: cs = 53; goto _test_eof; 
	_test_eof54: cs = 54; goto _test_eof; 
	_test_eof55: cs = 55; goto _test_eof; 
	_test_eof56: cs = 56; goto _test_eof; 
	_test_eof57: cs = 57; goto _test_eof; 
	_test_eof58: cs = 58; goto _test_eof; 
	_test_eof59: cs = 59; goto _test_eof; 
	_test_eof60: cs = 60; goto _test_eof; 
	_test_eof61: cs = 61; goto _test_eof; 
	_test_eof62: cs = 62; goto _test_eof; 
	_test_eof63: cs = 63; goto _test_eof; 
	_test_eof64: cs = 64; goto _test_eof; 
	_test_eof65: cs = 65; goto _test_eof; 
	_test_eof66: cs = 66; goto _test_eof; 
	_test_eof67: cs = 67; goto _test_eof; 
	_test_eof68: cs = 68; goto _test_eof; 
	_test_eof69: cs = 69; goto _test_eof; 
	_test_eof70: cs = 70; goto _test_eof; 
	_test_eof71: cs = 71; goto _test_eof; 
	_test_eof72: cs = 72; goto _test_eof; 
	_test_eof73: cs = 73; goto _test_eof; 
	_test_eof74: cs = 74; goto _test_eof; 
	_test_eof75: cs = 75; goto _test_eof; 
	_test_eof76: cs = 76; goto _test_eof; 
	_test_eof77: cs = 77; goto _test_eof; 
	_test_eof78: cs = 78; goto _test_eof; 
	_test_eof79: cs = 79; goto _test_eof; 
	_test_eof80: cs = 80; goto _test_eof; 
	_test_eof81: cs = 81; goto _test_eof; 
	_test_eof82: cs = 82; goto _test_eof; 
	_test_eof83: cs = 83; goto _test_eof; 
	_test_eof84: cs = 84; goto _test_eof; 
	_test_eof85: cs = 85; goto _test_eof; 
	_test_eof86: cs = 86; goto _test_eof; 
	_test_eof87: cs = 87; goto _test_eof; 
	_test_eof88: cs = 88; goto _test_eof; 
	_test_eof89: cs = 89; goto _test_eof; 
	_test_eof90: cs = 90; goto _test_eof; 
	_test_eof91: cs = 91; goto _test_eof; 
	_test_eof92: cs = 92; goto _test_eof; 
	_test_eof93: cs = 93; goto _test_eof; 
	_test_eof94: cs = 94; goto _test_eof; 
	_test_eof95: cs = 95; goto _test_eof; 
	_test_eof96: cs = 96; goto _test_eof; 
	_test_eof97: cs = 97; goto _test_eof; 
	_test_eof98: cs = 98; goto _test_eof; 
	_test_eof99: cs = 99; goto _test_eof; 
	_test_eof100: cs = 100; goto _test_eof; 
	_test_eof101: cs = 101; goto _test_eof; 
	_test_eof102: cs = 102; goto _test_eof; 
	_test_eof103: cs = 103; goto _test_eof; 
	_test_eof104: cs = 104; goto _test_eof; 
	_test_eof105: cs = 105; goto _test_eof; 
	_test_eof106: cs = 106; goto _test_eof; 
	_test_eof107: cs = 107; goto _test_eof; 
	_test_eof108: cs = 108; goto _test_eof; 
	_test_eof109: cs = 109; goto _test_eof; 
	_test_eof110: cs = 110; goto _test_eof; 
	_test_eof111: cs = 111; goto _test_eof; 
	_test_eof112: cs = 112; goto _test_eof; 
	_test_eof113: cs = 113; goto _test_eof; 
	_test_eof114: cs = 114; goto _test_eof; 
	_test_eof115: cs = 115; goto _test_eof; 
	_test_eof116: cs = 116; goto _test_eof; 
	_test_eof117: cs = 117; goto _test_eof; 
	_test_eof118: cs = 118; goto _test_eof; 
	_test_eof119: cs = 119; goto _test_eof; 
	_test_eof120: cs = 120; goto _test_eof; 
	_test_eof121: cs = 121; goto _test_eof; 
	_test_eof122: cs = 122; goto _test_eof; 
	_test_eof123: cs = 123; goto _test_eof; 
	_test_eof124: cs = 124; goto _test_eof; 
	_test_eof125: cs = 125; goto _test_eof; 
	_test_eof126: cs = 126; goto _test_eof; 
	_test_eof127: cs = 127; goto _test_eof; 
	_test_eof128: cs = 128; goto _test_eof; 
	_test_eof129: cs = 129; goto _test_eof; 
	_test_eof130: cs = 130; goto _test_eof; 
	_test_eof131: cs = 131; goto _test_eof; 
	_test_eof132: cs = 132; goto _test_eof; 
	_test_eof133: cs = 133; goto _test_eof; 

	_test_eof: {}
	_out: {}
	}

// line 157 "zparse.rl"

        
        if eof > -1 {
                if cs < z_first_final {
                        // No clue what I'm doing what so ever
                        if p == pe {
        println("p", p, "pe", pe)
        println("cs", cs, "z_first_final", z_first_final)
                                println("unexpected eof at line ", lines)
                                return z, nil
                        } else {
                                println("error at position ", p, "\"",data[mark:p],"\" at line ", lines)
                                return z, nil
                        }
                }
        }
        return z, nil
}
