
// line 1 "zparse.rl"
package dns

// Parse RRs
// With the thankful help of gdnsd and the Go examples for Ragel.
// 

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
func fields(s string, i int) (rdf []string) {
    rdf = strings.Fields(strings.TrimSpace(s))
    for i, _ := range rdf {
        rdf[i] = strings.TrimSpace(rdf[i])
    }
    if len(rdf) > i {
        // The last rdf contained embedded spaces, glue it back together.
        for j := i; j < len(rdf); j++ {
            rdf[i-1] += rdf[j]
        }
    }
    return
}

func atoi(s string) uint {
    i, err :=  strconv.Atoui(s)
    if err != nil {
        panic("not a number: " + s + " " + err.String())
    }
    return i
}


// line 46 "zparse.go"
var z_start int = 54
var z_first_final int = 54
var z_error int = 0

var z_en_main int = 54


// line 45 "zparse.rl"


// SetString
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
        cs, p, pe := 0, 0, len(data)
        eof := len(data)

//        brace := false
        lines := 0
        mark := 0
        hdr := new(RR_Header)

        
// line 80 "zparse.go"
	cs = z_start

// line 83 "zparse.go"
	{
	if p == pe { goto _test_eof }
	switch cs {
	case -666: // i am a hack D:
tr27:
// line 5 "types.rl"
	{
        rdf := fields(data[mark:p], 1)
        rr := new(RR_A)
        rr.Hdr = *hdr
        rr.Hdr.Rrtype = TypeA
        rr.A = net.ParseIP(rdf[0])
        z.Push(rr)
    }
// line 75 "zparse.rl"
	{ lines++ }
	goto st54
tr32:
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
// line 75 "zparse.rl"
	{ lines++ }
	goto st54
tr43:
// line 42 "types.rl"
	{
        rdf := fields(data[mark:p], 1)
        rr := new(RR_CNAME)
        rr.Hdr = *hdr
        rr.Hdr.Rrtype = TypeCNAME
        rr.Cname = rdf[0]
        z.Push(rr)
    }
// line 75 "zparse.rl"
	{ lines++ }
	goto st54
tr52:
// line 78 "types.rl"
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
// line 75 "zparse.rl"
	{ lines++ }
	goto st54
tr55:
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
// line 75 "zparse.rl"
	{ lines++ }
	goto st54
tr59:
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
// line 75 "zparse.rl"
	{ lines++ }
	goto st54
tr63:
// line 23 "types.rl"
	{
        rdf := fields(data[mark:p], 1)
        rr := new(RR_NS)
        rr.Hdr = *hdr
        rr.Hdr.Rrtype = TypeNS
        rr.Ns = rdf[0]
        z.Push(rr)
    }
// line 75 "zparse.rl"
	{ lines++ }
	goto st54
tr70:
// line 90 "types.rl"
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
// line 75 "zparse.rl"
	{ lines++ }
	goto st54
tr75:
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
// line 75 "zparse.rl"
	{ lines++ }
	goto st54
tr85:
// line 75 "zparse.rl"
	{ lines++ }
	goto st54
st54:
	p++
	if p == pe { goto _test_eof54 }
	fallthrough
case 54:
// line 244 "zparse.go"
	switch data[p] {
		case 9: goto st1
		case 10: goto tr85
		case 32: goto st1
		case 59: goto st53
		case 95: goto tr86
	}
	if data[p] < 48 {
		if 45 <= data[p] && data[p] <= 46 { goto tr86 }
	} else if data[p] > 57 {
		if data[p] > 90 {
			if 97 <= data[p] && data[p] <= 122 { goto tr86 }
		} else if data[p] >= 65 {
			goto tr86
		}
	} else {
		goto tr86
	}
	goto st0
st0:
cs = 0;
	goto _out;
tr82:
// line 71 "zparse.rl"
	{ hdr.Name = data[mark:p] }
	goto st1
st1:
	p++
	if p == pe { goto _test_eof1 }
	fallthrough
case 1:
// line 276 "zparse.go"
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
		case 82: goto tr10
		case 83: goto tr11
		case 97: goto tr3
		case 99: goto tr4
		case 100: goto tr5
		case 104: goto tr6
		case 105: goto tr7
		case 109: goto tr8
		case 110: goto tr9
		case 114: goto tr10
		case 115: goto tr11
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr2 }
	goto st0
tr2:
// line 73 "zparse.rl"
	{ /* ... */ }
// line 70 "zparse.rl"
	{ mark = p }
	goto st2
st2:
	p++
	if p == pe { goto _test_eof2 }
	fallthrough
case 2:
// line 312 "zparse.go"
	switch data[p] {
		case 9: goto tr12
		case 32: goto tr12
	}
	if 48 <= data[p] && data[p] <= 57 { goto st2 }
	goto st0
tr12:
// line 74 "zparse.rl"
	{ ttl := atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st3
st3:
	p++
	if p == pe { goto _test_eof3 }
	fallthrough
case 3:
// line 328 "zparse.go"
	switch data[p] {
		case 9: goto st3
		case 32: goto st3
		case 65: goto st4
		case 67: goto tr16
		case 68: goto st19
		case 72: goto tr18
		case 73: goto tr19
		case 77: goto st28
		case 78: goto st31
		case 82: goto st34
		case 83: goto st40
		case 97: goto st4
		case 99: goto tr16
		case 100: goto st19
		case 104: goto tr18
		case 105: goto tr19
		case 109: goto st28
		case 110: goto st31
		case 114: goto st34
		case 115: goto st40
	}
	goto st0
tr3:
// line 73 "zparse.rl"
	{ /* ... */ }
	goto st4
st4:
	p++
	if p == pe { goto _test_eof4 }
	fallthrough
case 4:
// line 361 "zparse.go"
	switch data[p] {
		case 10: goto st0
		case 65: goto tr25
		case 97: goto tr25
	}
	goto tr24
tr24:
// line 70 "zparse.rl"
	{ mark = p }
	goto st5
st5:
	p++
	if p == pe { goto _test_eof5 }
	fallthrough
case 5:
// line 377 "zparse.go"
	if data[p] == 10 { goto tr27 }
	goto st5
tr25:
// line 70 "zparse.rl"
	{ mark = p }
	goto st6
st6:
	p++
	if p == pe { goto _test_eof6 }
	fallthrough
case 6:
// line 389 "zparse.go"
	switch data[p] {
		case 10: goto tr27
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
		case 10: goto tr27
		case 65: goto st8
		case 97: goto st8
	}
	goto st5
st8:
	p++
	if p == pe { goto _test_eof8 }
	fallthrough
case 8:
	if data[p] == 10 { goto tr27 }
	goto tr30
tr30:
// line 70 "zparse.rl"
	{ mark = p }
	goto st9
st9:
	p++
	if p == pe { goto _test_eof9 }
	fallthrough
case 9:
// line 423 "zparse.go"
	if data[p] == 10 { goto tr32 }
	goto st9
tr16:
// line 70 "zparse.rl"
	{ mark = p }
	goto st10
st10:
	p++
	if p == pe { goto _test_eof10 }
	fallthrough
case 10:
// line 435 "zparse.go"
	switch data[p] {
		case 72: goto st11
		case 78: goto st14
		case 104: goto st11
		case 110: goto st14
	}
	goto st0
st11:
	p++
	if p == pe { goto _test_eof11 }
	fallthrough
case 11:
	switch data[p] {
		case 9: goto tr35
		case 32: goto tr35
	}
	goto st0
tr80:
// line 74 "zparse.rl"
	{ ttl := atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st12
tr35:
// line 72 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st12
st12:
	p++
	if p == pe { goto _test_eof12 }
	fallthrough
case 12:
// line 466 "zparse.go"
	switch data[p] {
		case 9: goto st12
		case 32: goto st12
		case 65: goto st4
		case 67: goto st13
		case 68: goto st19
		case 77: goto st28
		case 78: goto st31
		case 82: goto st34
		case 83: goto st40
		case 97: goto st4
		case 99: goto st13
		case 100: goto st19
		case 109: goto st28
		case 110: goto st31
		case 114: goto st34
		case 115: goto st40
	}
	goto st0
st13:
	p++
	if p == pe { goto _test_eof13 }
	fallthrough
case 13:
	switch data[p] {
		case 78: goto st14
		case 110: goto st14
	}
	goto st0
st14:
	p++
	if p == pe { goto _test_eof14 }
	fallthrough
case 14:
	switch data[p] {
		case 65: goto st15
		case 97: goto st15
	}
	goto st0
st15:
	p++
	if p == pe { goto _test_eof15 }
	fallthrough
case 15:
	switch data[p] {
		case 77: goto st16
		case 109: goto st16
	}
	goto st0
st16:
	p++
	if p == pe { goto _test_eof16 }
	fallthrough
case 16:
	switch data[p] {
		case 69: goto st17
		case 101: goto st17
	}
	goto st0
st17:
	p++
	if p == pe { goto _test_eof17 }
	fallthrough
case 17:
	if data[p] == 10 { goto st0 }
	goto tr41
tr41:
// line 70 "zparse.rl"
	{ mark = p }
	goto st18
st18:
	p++
	if p == pe { goto _test_eof18 }
	fallthrough
case 18:
// line 542 "zparse.go"
	if data[p] == 10 { goto tr43 }
	goto st18
tr5:
// line 73 "zparse.rl"
	{ /* ... */ }
	goto st19
st19:
	p++
	if p == pe { goto _test_eof19 }
	fallthrough
case 19:
// line 554 "zparse.go"
	switch data[p] {
		case 78: goto st20
		case 83: goto st26
		case 110: goto st20
		case 115: goto st26
	}
	goto st0
st20:
	p++
	if p == pe { goto _test_eof20 }
	fallthrough
case 20:
	switch data[p] {
		case 83: goto st21
		case 115: goto st21
	}
	goto st0
st21:
	p++
	if p == pe { goto _test_eof21 }
	fallthrough
case 21:
	switch data[p] {
		case 75: goto st22
		case 107: goto st22
	}
	goto st0
st22:
	p++
	if p == pe { goto _test_eof22 }
	fallthrough
case 22:
	switch data[p] {
		case 69: goto st23
		case 101: goto st23
	}
	goto st0
st23:
	p++
	if p == pe { goto _test_eof23 }
	fallthrough
case 23:
	switch data[p] {
		case 89: goto st24
		case 121: goto st24
	}
	goto st0
st24:
	p++
	if p == pe { goto _test_eof24 }
	fallthrough
case 24:
	if data[p] == 10 { goto st0 }
	goto tr50
tr50:
// line 70 "zparse.rl"
	{ mark = p }
	goto st25
st25:
	p++
	if p == pe { goto _test_eof25 }
	fallthrough
case 25:
// line 618 "zparse.go"
	if data[p] == 10 { goto tr52 }
	goto st25
st26:
	p++
	if p == pe { goto _test_eof26 }
	fallthrough
case 26:
	if data[p] == 10 { goto st0 }
	goto tr53
tr53:
// line 70 "zparse.rl"
	{ mark = p }
	goto st27
st27:
	p++
	if p == pe { goto _test_eof27 }
	fallthrough
case 27:
// line 637 "zparse.go"
	if data[p] == 10 { goto tr55 }
	goto st27
tr8:
// line 73 "zparse.rl"
	{ /* ... */ }
	goto st28
st28:
	p++
	if p == pe { goto _test_eof28 }
	fallthrough
case 28:
// line 649 "zparse.go"
	switch data[p] {
		case 88: goto st29
		case 120: goto st29
	}
	goto st0
st29:
	p++
	if p == pe { goto _test_eof29 }
	fallthrough
case 29:
	if data[p] == 10 { goto st0 }
	goto tr57
tr57:
// line 70 "zparse.rl"
	{ mark = p }
	goto st30
st30:
	p++
	if p == pe { goto _test_eof30 }
	fallthrough
case 30:
// line 671 "zparse.go"
	if data[p] == 10 { goto tr59 }
	goto st30
tr9:
// line 73 "zparse.rl"
	{ /* ... */ }
	goto st31
st31:
	p++
	if p == pe { goto _test_eof31 }
	fallthrough
case 31:
// line 683 "zparse.go"
	switch data[p] {
		case 83: goto st32
		case 115: goto st32
	}
	goto st0
st32:
	p++
	if p == pe { goto _test_eof32 }
	fallthrough
case 32:
	if data[p] == 10 { goto st0 }
	goto tr61
tr61:
// line 70 "zparse.rl"
	{ mark = p }
	goto st33
st33:
	p++
	if p == pe { goto _test_eof33 }
	fallthrough
case 33:
// line 705 "zparse.go"
	if data[p] == 10 { goto tr63 }
	goto st33
tr10:
// line 73 "zparse.rl"
	{ /* ... */ }
	goto st34
st34:
	p++
	if p == pe { goto _test_eof34 }
	fallthrough
case 34:
// line 717 "zparse.go"
	switch data[p] {
		case 82: goto st35
		case 114: goto st35
	}
	goto st0
st35:
	p++
	if p == pe { goto _test_eof35 }
	fallthrough
case 35:
	switch data[p] {
		case 83: goto st36
		case 115: goto st36
	}
	goto st0
st36:
	p++
	if p == pe { goto _test_eof36 }
	fallthrough
case 36:
	switch data[p] {
		case 73: goto st37
		case 105: goto st37
	}
	goto st0
st37:
	p++
	if p == pe { goto _test_eof37 }
	fallthrough
case 37:
	switch data[p] {
		case 71: goto st38
		case 103: goto st38
	}
	goto st0
st38:
	p++
	if p == pe { goto _test_eof38 }
	fallthrough
case 38:
	if data[p] == 10 { goto st0 }
	goto tr68
tr68:
// line 70 "zparse.rl"
	{ mark = p }
	goto st39
st39:
	p++
	if p == pe { goto _test_eof39 }
	fallthrough
case 39:
// line 769 "zparse.go"
	if data[p] == 10 { goto tr70 }
	goto st39
tr11:
// line 73 "zparse.rl"
	{ /* ... */ }
	goto st40
st40:
	p++
	if p == pe { goto _test_eof40 }
	fallthrough
case 40:
// line 781 "zparse.go"
	switch data[p] {
		case 79: goto st41
		case 111: goto st41
	}
	goto st0
st41:
	p++
	if p == pe { goto _test_eof41 }
	fallthrough
case 41:
	switch data[p] {
		case 65: goto st42
		case 97: goto st42
	}
	goto st0
st42:
	p++
	if p == pe { goto _test_eof42 }
	fallthrough
case 42:
	if data[p] == 10 { goto st0 }
	goto tr73
tr73:
// line 70 "zparse.rl"
	{ mark = p }
	goto st43
st43:
	p++
	if p == pe { goto _test_eof43 }
	fallthrough
case 43:
// line 813 "zparse.go"
	if data[p] == 10 { goto tr75 }
	goto st43
tr18:
// line 70 "zparse.rl"
	{ mark = p }
	goto st44
st44:
	p++
	if p == pe { goto _test_eof44 }
	fallthrough
case 44:
// line 825 "zparse.go"
	switch data[p] {
		case 83: goto st11
		case 115: goto st11
	}
	goto st0
tr19:
// line 70 "zparse.rl"
	{ mark = p }
	goto st45
st45:
	p++
	if p == pe { goto _test_eof45 }
	fallthrough
case 45:
// line 840 "zparse.go"
	switch data[p] {
		case 78: goto st11
		case 110: goto st11
	}
	goto st0
tr4:
// line 73 "zparse.rl"
	{ /* ... */ }
// line 70 "zparse.rl"
	{ mark = p }
	goto st46
st46:
	p++
	if p == pe { goto _test_eof46 }
	fallthrough
case 46:
// line 857 "zparse.go"
	switch data[p] {
		case 72: goto st47
		case 78: goto st14
		case 104: goto st47
		case 110: goto st14
	}
	goto st0
st47:
	p++
	if p == pe { goto _test_eof47 }
	fallthrough
case 47:
	switch data[p] {
		case 9: goto tr77
		case 32: goto tr77
	}
	goto st0
tr77:
// line 72 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st48
st48:
	p++
	if p == pe { goto _test_eof48 }
	fallthrough
case 48:
// line 884 "zparse.go"
	switch data[p] {
		case 9: goto st48
		case 32: goto st48
		case 65: goto st4
		case 67: goto st13
		case 68: goto st19
		case 77: goto st28
		case 78: goto st31
		case 82: goto st34
		case 83: goto st40
		case 97: goto st4
		case 99: goto st13
		case 100: goto st19
		case 109: goto st28
		case 110: goto st31
		case 114: goto st34
		case 115: goto st40
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr79 }
	goto st0
tr79:
// line 70 "zparse.rl"
	{ mark = p }
	goto st49
st49:
	p++
	if p == pe { goto _test_eof49 }
	fallthrough
case 49:
// line 914 "zparse.go"
	switch data[p] {
		case 9: goto tr80
		case 32: goto tr80
	}
	if 48 <= data[p] && data[p] <= 57 { goto st49 }
	goto st0
tr6:
// line 73 "zparse.rl"
	{ /* ... */ }
// line 70 "zparse.rl"
	{ mark = p }
	goto st50
st50:
	p++
	if p == pe { goto _test_eof50 }
	fallthrough
case 50:
// line 932 "zparse.go"
	switch data[p] {
		case 83: goto st47
		case 115: goto st47
	}
	goto st0
tr7:
// line 73 "zparse.rl"
	{ /* ... */ }
// line 70 "zparse.rl"
	{ mark = p }
	goto st51
st51:
	p++
	if p == pe { goto _test_eof51 }
	fallthrough
case 51:
// line 949 "zparse.go"
	switch data[p] {
		case 78: goto st47
		case 110: goto st47
	}
	goto st0
tr86:
// line 70 "zparse.rl"
	{ mark = p }
	goto st52
st52:
	p++
	if p == pe { goto _test_eof52 }
	fallthrough
case 52:
// line 964 "zparse.go"
	switch data[p] {
		case 9: goto tr82
		case 32: goto tr82
		case 95: goto st52
	}
	if data[p] < 48 {
		if 45 <= data[p] && data[p] <= 46 { goto st52 }
	} else if data[p] > 57 {
		if data[p] > 90 {
			if 97 <= data[p] && data[p] <= 122 { goto st52 }
		} else if data[p] >= 65 {
			goto st52
		}
	} else {
		goto st52
	}
	goto st0
st53:
	p++
	if p == pe { goto _test_eof53 }
	fallthrough
case 53:
	if data[p] == 10 { goto tr85 }
	goto st53
	}
	_test_eof54: cs = 54; goto _test_eof; 
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

	_test_eof: {}
	_out: {}
	}

// line 121 "zparse.rl"

        
        if eof > -1 {
                if cs < z_first_final {
                        // No clue what I'm doing what so ever
                        if p == pe {
                                println("unexpected eof at line", lines)
                                return z, nil
                        } else {
                                println("error at position ", p, "\"",data[mark:p],"\" at line ", lines)
                                return z, nil
                        }
                }
        }
        return z, nil
}
