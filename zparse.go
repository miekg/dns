
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

//const _IOBUF = 65365
const _IOBUF = 3e7

// Return the rdata fields as a string slice. 
// All starting whitespace is deleted.
// If i is 0 no space are deleted from the final rdfs
func fields(s string, i int) (rdf []string) {
    rdf = strings.Fields(strings.TrimSpace(s))
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


// line 47 "zparse.go"
var z_start int = 94
var z_first_final int = 94
var z_error int = 0

var z_en_main int = 94


// line 46 "zparse.rl"


// All the NewReader stuff is expensive...
// only works for short io.Readers as we put the whole thing
// in a string -- needs to be extended for large files (sliding window).
func Zparse(q io.Reader) (z *Zone, err os.Error) {
        buf := make([]byte, _IOBUF) 
        n, err := q.Read(buf)
        if err != nil {
            return nil, err
        }
        buf = buf[:n]
        z = new(Zone)

        data := string(buf)
        // guardian
        if data[len(data)-1] != '\n' {
            data += "\n"
        }
        cs, p, pe := 0, 0, len(data)
        eof := len(data)

//        brace := false
        lines := 0
        mark := 0
        hdr := new(RR_Header)

        
// line 84 "zparse.go"
	cs = z_start

// line 87 "zparse.go"
	{
	if p == pe { goto _test_eof }
	switch cs {
	case -666: // i am a hack D:
tr31:
// line 5 "types.rl"
	{
        rdf := fields(data[mark:p], 1)
        rr := new(RR_A)
        rr.Hdr = *hdr
        rr.Hdr.Rrtype = TypeA
        rr.A = net.ParseIP(rdf[0])
        z.Push(rr)
    }
// line 79 "zparse.rl"
	{ lines++ }
	goto st94
tr36:
// line 5 "types.rl"
	{
        rdf := fields(data[mark:p], 1)
        rr := new(RR_A)
        rr.Hdr = *hdr
        rr.Hdr.Rrtype = TypeA
        rr.A = net.ParseIP(rdf[0])
        z.Push(rr)
    }
// line 14 "types.rl"
	{
        rdf := fields(data[mark:p], 1)
        rr := new(RR_AAAA)
        rr.Hdr = *hdr
        rr.Hdr.Rrtype = TypeAAAA
        rr.AAAA = net.ParseIP(rdf[0])
        z.Push(rr)
    }
// line 79 "zparse.rl"
	{ lines++ }
	goto st94
tr44:
// line 179 "types.rl"
	{
    }
// line 79 "zparse.rl"
	{ lines++ }
	goto st94
tr53:
// line 42 "types.rl"
	{
        rdf := fields(data[mark:p], 1)
        rr := new(RR_CNAME)
        rr.Hdr = *hdr
        rr.Hdr.Rrtype = TypeCNAME
        rr.Cname = rdf[0]
        z.Push(rr)
    }
// line 79 "zparse.rl"
	{ lines++ }
	goto st94
tr60:
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
// line 79 "zparse.rl"
	{ lines++ }
	goto st94
tr67:
// line 185 "types.rl"
	{
    }
// line 79 "zparse.rl"
	{ lines++ }
	goto st94
tr73:
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
// line 79 "zparse.rl"
	{ lines++ }
	goto st94
tr76:
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
// line 79 "zparse.rl"
	{ lines++ }
	goto st94
tr80:
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
// line 79 "zparse.rl"
	{ lines++ }
	goto st94
tr88:
// line 188 "types.rl"
	{
    }
// line 79 "zparse.rl"
	{ lines++ }
	goto st94
tr92:
// line 23 "types.rl"
	{
        rdf := fields(data[mark:p], 1)
        rr := new(RR_NS)
        rr.Hdr = *hdr
        rr.Hdr.Rrtype = TypeNS
        rr.Ns = rdf[0]
        z.Push(rr)
    }
// line 79 "zparse.rl"
	{ lines++ }
	goto st94
tr97:
// line 23 "types.rl"
	{
        rdf := fields(data[mark:p], 1)
        rr := new(RR_NS)
        rr.Hdr = *hdr
        rr.Hdr.Rrtype = TypeNS
        rr.Ns = rdf[0]
        z.Push(rr)
    }
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
// line 79 "zparse.rl"
	{ lines++ }
	goto st94
tr101:
// line 23 "types.rl"
	{
        rdf := fields(data[mark:p], 1)
        rr := new(RR_NS)
        rr.Hdr = *hdr
        rr.Hdr.Rrtype = TypeNS
        rr.Ns = rdf[0]
        z.Push(rr)
    }
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
// line 79 "zparse.rl"
	{ lines++ }
	goto st94
tr108:
// line 23 "types.rl"
	{
        rdf := fields(data[mark:p], 1)
        rr := new(RR_NS)
        rr.Hdr = *hdr
        rr.Hdr.Rrtype = TypeNS
        rr.Ns = rdf[0]
        z.Push(rr)
    }
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
// line 167 "types.rl"
	{
    }
// line 79 "zparse.rl"
	{ lines++ }
	goto st94
tr113:
// line 182 "types.rl"
	{
    }
// line 79 "zparse.rl"
	{ lines++ }
	goto st94
tr120:
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
// line 79 "zparse.rl"
	{ lines++ }
	goto st94
tr126:
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
// line 79 "zparse.rl"
	{ lines++ }
	goto st94
tr130:
// line 176 "types.rl"
	{
    }
// line 79 "zparse.rl"
	{ lines++ }
	goto st94
tr135:
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
// line 79 "zparse.rl"
	{ lines++ }
	goto st94
tr139:
// line 173 "types.rl"
	{
    }
// line 79 "zparse.rl"
	{ lines++ }
	goto st94
tr149:
// line 79 "zparse.rl"
	{ lines++ }
	goto st94
st94:
	p++
	if p == pe { goto _test_eof94 }
	fallthrough
case 94:
// line 451 "zparse.go"
	switch data[p] {
		case 9: goto st1
		case 10: goto tr149
		case 32: goto st1
		case 59: goto st93
		case 95: goto tr150
	}
	if data[p] < 48 {
		if 45 <= data[p] && data[p] <= 46 { goto tr150 }
	} else if data[p] > 57 {
		if data[p] > 90 {
			if 97 <= data[p] && data[p] <= 122 { goto tr150 }
		} else if data[p] >= 65 {
			goto tr150
		}
	} else {
		goto tr150
	}
	goto st0
st0:
cs = 0;
	goto _out;
tr146:
// line 75 "zparse.rl"
	{ hdr.Name = data[mark:p] }
	goto st1
st1:
	p++
	if p == pe { goto _test_eof1 }
	fallthrough
case 1:
// line 483 "zparse.go"
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
// line 77 "zparse.rl"
	{ /* ... */ }
// line 74 "zparse.rl"
	{ mark = p }
	goto st2
st2:
	p++
	if p == pe { goto _test_eof2 }
	fallthrough
case 2:
// line 523 "zparse.go"
	switch data[p] {
		case 9: goto tr14
		case 32: goto tr14
	}
	if 48 <= data[p] && data[p] <= 57 { goto st2 }
	goto st0
tr14:
// line 78 "zparse.rl"
	{ ttl := atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st3
st3:
	p++
	if p == pe { goto _test_eof3 }
	fallthrough
case 3:
// line 539 "zparse.go"
	switch data[p] {
		case 9: goto st3
		case 32: goto st3
		case 65: goto st4
		case 67: goto tr18
		case 68: goto st23
		case 72: goto tr20
		case 73: goto tr21
		case 77: goto st39
		case 78: goto st42
		case 80: goto st61
		case 82: goto st65
		case 83: goto st71
		case 84: goto st78
		case 97: goto st4
		case 99: goto tr18
		case 100: goto st23
		case 104: goto tr20
		case 105: goto tr21
		case 109: goto st39
		case 110: goto st42
		case 112: goto st61
		case 114: goto st65
		case 115: goto st71
		case 116: goto st78
	}
	goto st0
tr3:
// line 77 "zparse.rl"
	{ /* ... */ }
	goto st4
st4:
	p++
	if p == pe { goto _test_eof4 }
	fallthrough
case 4:
// line 576 "zparse.go"
	switch data[p] {
		case 10: goto st0
		case 65: goto tr29
		case 97: goto tr29
	}
	goto tr28
tr28:
// line 74 "zparse.rl"
	{ mark = p }
	goto st5
st5:
	p++
	if p == pe { goto _test_eof5 }
	fallthrough
case 5:
// line 592 "zparse.go"
	if data[p] == 10 { goto tr31 }
	goto st5
tr29:
// line 74 "zparse.rl"
	{ mark = p }
	goto st6
st6:
	p++
	if p == pe { goto _test_eof6 }
	fallthrough
case 6:
// line 604 "zparse.go"
	switch data[p] {
		case 10: goto tr31
		case 65: goto st7
		case 97: goto st7
	}
	goto st5
st7:
	p++
	if p == pe { goto _test_eof7 }
	fallthrough
case 7:
	switch data[p] {
		case 10: goto tr31
		case 65: goto st8
		case 97: goto st8
	}
	goto st5
st8:
	p++
	if p == pe { goto _test_eof8 }
	fallthrough
case 8:
	if data[p] == 10 { goto tr31 }
	goto tr34
tr34:
// line 74 "zparse.rl"
	{ mark = p }
	goto st9
st9:
	p++
	if p == pe { goto _test_eof9 }
	fallthrough
case 9:
// line 638 "zparse.go"
	if data[p] == 10 { goto tr36 }
	goto st9
tr18:
// line 74 "zparse.rl"
	{ mark = p }
	goto st10
st10:
	p++
	if p == pe { goto _test_eof10 }
	fallthrough
case 10:
// line 650 "zparse.go"
	switch data[p] {
		case 69: goto st11
		case 72: goto st15
		case 78: goto st18
		case 101: goto st11
		case 104: goto st15
		case 110: goto st18
	}
	goto st0
st11:
	p++
	if p == pe { goto _test_eof11 }
	fallthrough
case 11:
	switch data[p] {
		case 82: goto st12
		case 114: goto st12
	}
	goto st0
st12:
	p++
	if p == pe { goto _test_eof12 }
	fallthrough
case 12:
	switch data[p] {
		case 84: goto st13
		case 116: goto st13
	}
	goto st0
st13:
	p++
	if p == pe { goto _test_eof13 }
	fallthrough
case 13:
	if data[p] == 10 { goto st0 }
	goto tr42
tr42:
// line 74 "zparse.rl"
	{ mark = p }
	goto st14
st14:
	p++
	if p == pe { goto _test_eof14 }
	fallthrough
case 14:
// line 696 "zparse.go"
	if data[p] == 10 { goto tr44 }
	goto st14
st15:
	p++
	if p == pe { goto _test_eof15 }
	fallthrough
case 15:
	switch data[p] {
		case 9: goto tr45
		case 32: goto tr45
	}
	goto st0
tr144:
// line 78 "zparse.rl"
	{ ttl := atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st16
tr45:
// line 76 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st16
st16:
	p++
	if p == pe { goto _test_eof16 }
	fallthrough
case 16:
// line 722 "zparse.go"
	switch data[p] {
		case 9: goto st16
		case 32: goto st16
		case 65: goto st4
		case 67: goto st17
		case 68: goto st23
		case 77: goto st39
		case 78: goto st42
		case 80: goto st61
		case 82: goto st65
		case 83: goto st71
		case 84: goto st78
		case 97: goto st4
		case 99: goto st17
		case 100: goto st23
		case 109: goto st39
		case 110: goto st42
		case 112: goto st61
		case 114: goto st65
		case 115: goto st71
		case 116: goto st78
	}
	goto st0
st17:
	p++
	if p == pe { goto _test_eof17 }
	fallthrough
case 17:
	switch data[p] {
		case 69: goto st11
		case 78: goto st18
		case 101: goto st11
		case 110: goto st18
	}
	goto st0
st18:
	p++
	if p == pe { goto _test_eof18 }
	fallthrough
case 18:
	switch data[p] {
		case 65: goto st19
		case 97: goto st19
	}
	goto st0
st19:
	p++
	if p == pe { goto _test_eof19 }
	fallthrough
case 19:
	switch data[p] {
		case 77: goto st20
		case 109: goto st20
	}
	goto st0
st20:
	p++
	if p == pe { goto _test_eof20 }
	fallthrough
case 20:
	switch data[p] {
		case 69: goto st21
		case 101: goto st21
	}
	goto st0
st21:
	p++
	if p == pe { goto _test_eof21 }
	fallthrough
case 21:
	if data[p] == 10 { goto st0 }
	goto tr51
tr51:
// line 74 "zparse.rl"
	{ mark = p }
	goto st22
st22:
	p++
	if p == pe { goto _test_eof22 }
	fallthrough
case 22:
// line 804 "zparse.go"
	if data[p] == 10 { goto tr53 }
	goto st22
tr5:
// line 77 "zparse.rl"
	{ /* ... */ }
	goto st23
st23:
	p++
	if p == pe { goto _test_eof23 }
	fallthrough
case 23:
// line 816 "zparse.go"
	switch data[p] {
		case 76: goto st24
		case 78: goto st27
		case 83: goto st37
		case 108: goto st24
		case 110: goto st27
		case 115: goto st37
	}
	goto st0
st24:
	p++
	if p == pe { goto _test_eof24 }
	fallthrough
case 24:
	switch data[p] {
		case 86: goto st25
		case 118: goto st25
	}
	goto st0
st25:
	p++
	if p == pe { goto _test_eof25 }
	fallthrough
case 25:
	if data[p] == 10 { goto st0 }
	goto tr58
tr58:
// line 74 "zparse.rl"
	{ mark = p }
	goto st26
st26:
	p++
	if p == pe { goto _test_eof26 }
	fallthrough
case 26:
// line 852 "zparse.go"
	if data[p] == 10 { goto tr60 }
	goto st26
st27:
	p++
	if p == pe { goto _test_eof27 }
	fallthrough
case 27:
	switch data[p] {
		case 65: goto st28
		case 83: goto st32
		case 97: goto st28
		case 115: goto st32
	}
	goto st0
st28:
	p++
	if p == pe { goto _test_eof28 }
	fallthrough
case 28:
	switch data[p] {
		case 77: goto st29
		case 109: goto st29
	}
	goto st0
st29:
	p++
	if p == pe { goto _test_eof29 }
	fallthrough
case 29:
	switch data[p] {
		case 69: goto st30
		case 101: goto st30
	}
	goto st0
st30:
	p++
	if p == pe { goto _test_eof30 }
	fallthrough
case 30:
	if data[p] == 10 { goto st0 }
	goto tr65
tr65:
// line 74 "zparse.rl"
	{ mark = p }
	goto st31
st31:
	p++
	if p == pe { goto _test_eof31 }
	fallthrough
case 31:
// line 903 "zparse.go"
	if data[p] == 10 { goto tr67 }
	goto st31
st32:
	p++
	if p == pe { goto _test_eof32 }
	fallthrough
case 32:
	switch data[p] {
		case 75: goto st33
		case 107: goto st33
	}
	goto st0
st33:
	p++
	if p == pe { goto _test_eof33 }
	fallthrough
case 33:
	switch data[p] {
		case 69: goto st34
		case 101: goto st34
	}
	goto st0
st34:
	p++
	if p == pe { goto _test_eof34 }
	fallthrough
case 34:
	switch data[p] {
		case 89: goto st35
		case 121: goto st35
	}
	goto st0
st35:
	p++
	if p == pe { goto _test_eof35 }
	fallthrough
case 35:
	if data[p] == 10 { goto st0 }
	goto tr71
tr71:
// line 74 "zparse.rl"
	{ mark = p }
	goto st36
st36:
	p++
	if p == pe { goto _test_eof36 }
	fallthrough
case 36:
// line 952 "zparse.go"
	if data[p] == 10 { goto tr73 }
	goto st36
st37:
	p++
	if p == pe { goto _test_eof37 }
	fallthrough
case 37:
	if data[p] == 10 { goto st0 }
	goto tr74
tr74:
// line 74 "zparse.rl"
	{ mark = p }
	goto st38
st38:
	p++
	if p == pe { goto _test_eof38 }
	fallthrough
case 38:
// line 971 "zparse.go"
	if data[p] == 10 { goto tr76 }
	goto st38
tr8:
// line 77 "zparse.rl"
	{ /* ... */ }
	goto st39
st39:
	p++
	if p == pe { goto _test_eof39 }
	fallthrough
case 39:
// line 983 "zparse.go"
	switch data[p] {
		case 88: goto st40
		case 120: goto st40
	}
	goto st0
st40:
	p++
	if p == pe { goto _test_eof40 }
	fallthrough
case 40:
	if data[p] == 10 { goto st0 }
	goto tr78
tr78:
// line 74 "zparse.rl"
	{ mark = p }
	goto st41
st41:
	p++
	if p == pe { goto _test_eof41 }
	fallthrough
case 41:
// line 1005 "zparse.go"
	if data[p] == 10 { goto tr80 }
	goto st41
tr9:
// line 77 "zparse.rl"
	{ /* ... */ }
	goto st42
st42:
	p++
	if p == pe { goto _test_eof42 }
	fallthrough
case 42:
// line 1017 "zparse.go"
	switch data[p] {
		case 65: goto st43
		case 83: goto st48
		case 97: goto st43
		case 115: goto st48
	}
	goto st0
st43:
	p++
	if p == pe { goto _test_eof43 }
	fallthrough
case 43:
	switch data[p] {
		case 80: goto st44
		case 112: goto st44
	}
	goto st0
st44:
	p++
	if p == pe { goto _test_eof44 }
	fallthrough
case 44:
	switch data[p] {
		case 84: goto st45
		case 116: goto st45
	}
	goto st0
st45:
	p++
	if p == pe { goto _test_eof45 }
	fallthrough
case 45:
	switch data[p] {
		case 82: goto st46
		case 114: goto st46
	}
	goto st0
st46:
	p++
	if p == pe { goto _test_eof46 }
	fallthrough
case 46:
	if data[p] == 10 { goto st0 }
	goto tr86
tr86:
// line 74 "zparse.rl"
	{ mark = p }
	goto st47
st47:
	p++
	if p == pe { goto _test_eof47 }
	fallthrough
case 47:
// line 1071 "zparse.go"
	if data[p] == 10 { goto tr88 }
	goto st47
st48:
	p++
	if p == pe { goto _test_eof48 }
	fallthrough
case 48:
	switch data[p] {
		case 10: goto st0
		case 69: goto tr90
		case 101: goto tr90
	}
	goto tr89
tr89:
// line 74 "zparse.rl"
	{ mark = p }
	goto st49
st49:
	p++
	if p == pe { goto _test_eof49 }
	fallthrough
case 49:
// line 1094 "zparse.go"
	if data[p] == 10 { goto tr92 }
	goto st49
tr90:
// line 74 "zparse.rl"
	{ mark = p }
	goto st50
st50:
	p++
	if p == pe { goto _test_eof50 }
	fallthrough
case 50:
// line 1106 "zparse.go"
	switch data[p] {
		case 10: goto tr92
		case 67: goto st51
		case 99: goto st51
	}
	goto st49
st51:
	p++
	if p == pe { goto _test_eof51 }
	fallthrough
case 51:
	switch data[p] {
		case 10: goto tr92
		case 51: goto tr95
	}
	goto tr94
tr94:
// line 74 "zparse.rl"
	{ mark = p }
	goto st52
st52:
	p++
	if p == pe { goto _test_eof52 }
	fallthrough
case 52:
// line 1132 "zparse.go"
	if data[p] == 10 { goto tr97 }
	goto st52
tr95:
// line 74 "zparse.rl"
	{ mark = p }
	goto st53
st53:
	p++
	if p == pe { goto _test_eof53 }
	fallthrough
case 53:
// line 1144 "zparse.go"
	switch data[p] {
		case 10: goto tr97
		case 80: goto tr99
		case 112: goto tr99
	}
	goto tr98
tr98:
// line 74 "zparse.rl"
	{ mark = p }
	goto st54
st54:
	p++
	if p == pe { goto _test_eof54 }
	fallthrough
case 54:
// line 1160 "zparse.go"
	if data[p] == 10 { goto tr101 }
	goto st54
tr99:
// line 74 "zparse.rl"
	{ mark = p }
	goto st55
st55:
	p++
	if p == pe { goto _test_eof55 }
	fallthrough
case 55:
// line 1172 "zparse.go"
	switch data[p] {
		case 10: goto tr101
		case 65: goto st56
		case 97: goto st56
	}
	goto st54
st56:
	p++
	if p == pe { goto _test_eof56 }
	fallthrough
case 56:
	switch data[p] {
		case 10: goto tr101
		case 82: goto st57
		case 114: goto st57
	}
	goto st54
st57:
	p++
	if p == pe { goto _test_eof57 }
	fallthrough
case 57:
	switch data[p] {
		case 10: goto tr101
		case 65: goto st58
		case 97: goto st58
	}
	goto st54
st58:
	p++
	if p == pe { goto _test_eof58 }
	fallthrough
case 58:
	switch data[p] {
		case 10: goto tr101
		case 77: goto st59
		case 109: goto st59
	}
	goto st54
st59:
	p++
	if p == pe { goto _test_eof59 }
	fallthrough
case 59:
	if data[p] == 10 { goto tr101 }
	goto tr106
tr106:
// line 74 "zparse.rl"
	{ mark = p }
	goto st60
st60:
	p++
	if p == pe { goto _test_eof60 }
	fallthrough
case 60:
// line 1228 "zparse.go"
	if data[p] == 10 { goto tr108 }
	goto st60
tr10:
// line 77 "zparse.rl"
	{ /* ... */ }
	goto st61
st61:
	p++
	if p == pe { goto _test_eof61 }
	fallthrough
case 61:
// line 1240 "zparse.go"
	switch data[p] {
		case 84: goto st62
		case 116: goto st62
	}
	goto st0
st62:
	p++
	if p == pe { goto _test_eof62 }
	fallthrough
case 62:
	switch data[p] {
		case 82: goto st63
		case 114: goto st63
	}
	goto st0
st63:
	p++
	if p == pe { goto _test_eof63 }
	fallthrough
case 63:
	if data[p] == 10 { goto st0 }
	goto tr111
tr111:
// line 74 "zparse.rl"
	{ mark = p }
	goto st64
st64:
	p++
	if p == pe { goto _test_eof64 }
	fallthrough
case 64:
// line 1272 "zparse.go"
	if data[p] == 10 { goto tr113 }
	goto st64
tr11:
// line 77 "zparse.rl"
	{ /* ... */ }
	goto st65
st65:
	p++
	if p == pe { goto _test_eof65 }
	fallthrough
case 65:
// line 1284 "zparse.go"
	switch data[p] {
		case 82: goto st66
		case 114: goto st66
	}
	goto st0
st66:
	p++
	if p == pe { goto _test_eof66 }
	fallthrough
case 66:
	switch data[p] {
		case 83: goto st67
		case 115: goto st67
	}
	goto st0
st67:
	p++
	if p == pe { goto _test_eof67 }
	fallthrough
case 67:
	switch data[p] {
		case 73: goto st68
		case 105: goto st68
	}
	goto st0
st68:
	p++
	if p == pe { goto _test_eof68 }
	fallthrough
case 68:
	switch data[p] {
		case 71: goto st69
		case 103: goto st69
	}
	goto st0
st69:
	p++
	if p == pe { goto _test_eof69 }
	fallthrough
case 69:
	if data[p] == 10 { goto st0 }
	goto tr118
tr118:
// line 74 "zparse.rl"
	{ mark = p }
	goto st70
st70:
	p++
	if p == pe { goto _test_eof70 }
	fallthrough
case 70:
// line 1336 "zparse.go"
	if data[p] == 10 { goto tr120 }
	goto st70
tr12:
// line 77 "zparse.rl"
	{ /* ... */ }
	goto st71
st71:
	p++
	if p == pe { goto _test_eof71 }
	fallthrough
case 71:
// line 1348 "zparse.go"
	switch data[p] {
		case 79: goto st72
		case 82: goto st75
		case 111: goto st72
		case 114: goto st75
	}
	goto st0
st72:
	p++
	if p == pe { goto _test_eof72 }
	fallthrough
case 72:
	switch data[p] {
		case 65: goto st73
		case 97: goto st73
	}
	goto st0
st73:
	p++
	if p == pe { goto _test_eof73 }
	fallthrough
case 73:
	if data[p] == 10 { goto st0 }
	goto tr124
tr124:
// line 74 "zparse.rl"
	{ mark = p }
	goto st74
st74:
	p++
	if p == pe { goto _test_eof74 }
	fallthrough
case 74:
// line 1382 "zparse.go"
	if data[p] == 10 { goto tr126 }
	goto st74
st75:
	p++
	if p == pe { goto _test_eof75 }
	fallthrough
case 75:
	switch data[p] {
		case 86: goto st76
		case 118: goto st76
	}
	goto st0
st76:
	p++
	if p == pe { goto _test_eof76 }
	fallthrough
case 76:
	if data[p] == 10 { goto st0 }
	goto tr128
tr128:
// line 74 "zparse.rl"
	{ mark = p }
	goto st77
st77:
	p++
	if p == pe { goto _test_eof77 }
	fallthrough
case 77:
// line 1411 "zparse.go"
	if data[p] == 10 { goto tr130 }
	goto st77
tr13:
// line 77 "zparse.rl"
	{ /* ... */ }
	goto st78
st78:
	p++
	if p == pe { goto _test_eof78 }
	fallthrough
case 78:
// line 1423 "zparse.go"
	switch data[p] {
		case 65: goto st79
		case 88: goto st81
		case 97: goto st79
		case 120: goto st81
	}
	goto st0
st79:
	p++
	if p == pe { goto _test_eof79 }
	fallthrough
case 79:
	if data[p] == 10 { goto st0 }
	goto tr133
tr133:
// line 74 "zparse.rl"
	{ mark = p }
	goto st80
st80:
	p++
	if p == pe { goto _test_eof80 }
	fallthrough
case 80:
// line 1447 "zparse.go"
	if data[p] == 10 { goto tr135 }
	goto st80
st81:
	p++
	if p == pe { goto _test_eof81 }
	fallthrough
case 81:
	switch data[p] {
		case 84: goto st82
		case 116: goto st82
	}
	goto st0
st82:
	p++
	if p == pe { goto _test_eof82 }
	fallthrough
case 82:
	if data[p] == 10 { goto st0 }
	goto tr137
tr137:
// line 74 "zparse.rl"
	{ mark = p }
	goto st83
st83:
	p++
	if p == pe { goto _test_eof83 }
	fallthrough
case 83:
// line 1476 "zparse.go"
	if data[p] == 10 { goto tr139 }
	goto st83
tr20:
// line 74 "zparse.rl"
	{ mark = p }
	goto st84
st84:
	p++
	if p == pe { goto _test_eof84 }
	fallthrough
case 84:
// line 1488 "zparse.go"
	switch data[p] {
		case 83: goto st15
		case 115: goto st15
	}
	goto st0
tr21:
// line 74 "zparse.rl"
	{ mark = p }
	goto st85
st85:
	p++
	if p == pe { goto _test_eof85 }
	fallthrough
case 85:
// line 1503 "zparse.go"
	switch data[p] {
		case 78: goto st15
		case 110: goto st15
	}
	goto st0
tr4:
// line 77 "zparse.rl"
	{ /* ... */ }
// line 74 "zparse.rl"
	{ mark = p }
	goto st86
st86:
	p++
	if p == pe { goto _test_eof86 }
	fallthrough
case 86:
// line 1520 "zparse.go"
	switch data[p] {
		case 69: goto st11
		case 72: goto st87
		case 78: goto st18
		case 101: goto st11
		case 104: goto st87
		case 110: goto st18
	}
	goto st0
st87:
	p++
	if p == pe { goto _test_eof87 }
	fallthrough
case 87:
	switch data[p] {
		case 9: goto tr141
		case 32: goto tr141
	}
	goto st0
tr141:
// line 76 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st88
st88:
	p++
	if p == pe { goto _test_eof88 }
	fallthrough
case 88:
// line 1549 "zparse.go"
	switch data[p] {
		case 9: goto st88
		case 32: goto st88
		case 65: goto st4
		case 67: goto st17
		case 68: goto st23
		case 77: goto st39
		case 78: goto st42
		case 80: goto st61
		case 82: goto st65
		case 83: goto st71
		case 84: goto st78
		case 97: goto st4
		case 99: goto st17
		case 100: goto st23
		case 109: goto st39
		case 110: goto st42
		case 112: goto st61
		case 114: goto st65
		case 115: goto st71
		case 116: goto st78
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr143 }
	goto st0
tr143:
// line 74 "zparse.rl"
	{ mark = p }
	goto st89
st89:
	p++
	if p == pe { goto _test_eof89 }
	fallthrough
case 89:
// line 1583 "zparse.go"
	switch data[p] {
		case 9: goto tr144
		case 32: goto tr144
	}
	if 48 <= data[p] && data[p] <= 57 { goto st89 }
	goto st0
tr6:
// line 77 "zparse.rl"
	{ /* ... */ }
// line 74 "zparse.rl"
	{ mark = p }
	goto st90
st90:
	p++
	if p == pe { goto _test_eof90 }
	fallthrough
case 90:
// line 1601 "zparse.go"
	switch data[p] {
		case 83: goto st87
		case 115: goto st87
	}
	goto st0
tr7:
// line 77 "zparse.rl"
	{ /* ... */ }
// line 74 "zparse.rl"
	{ mark = p }
	goto st91
st91:
	p++
	if p == pe { goto _test_eof91 }
	fallthrough
case 91:
// line 1618 "zparse.go"
	switch data[p] {
		case 78: goto st87
		case 110: goto st87
	}
	goto st0
tr150:
// line 74 "zparse.rl"
	{ mark = p }
	goto st92
st92:
	p++
	if p == pe { goto _test_eof92 }
	fallthrough
case 92:
// line 1633 "zparse.go"
	switch data[p] {
		case 9: goto tr146
		case 32: goto tr146
		case 95: goto st92
	}
	if data[p] < 48 {
		if 45 <= data[p] && data[p] <= 46 { goto st92 }
	} else if data[p] > 57 {
		if data[p] > 90 {
			if 97 <= data[p] && data[p] <= 122 { goto st92 }
		} else if data[p] >= 65 {
			goto st92
		}
	} else {
		goto st92
	}
	goto st0
st93:
	p++
	if p == pe { goto _test_eof93 }
	fallthrough
case 93:
	if data[p] == 10 { goto tr149 }
	goto st93
	}
	_test_eof94: cs = 94; goto _test_eof; 
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

	_test_eof: {}
	_out: {}
	}

// line 135 "zparse.rl"

        
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
