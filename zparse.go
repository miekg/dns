
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

const _IOBUF = 65365

// Return the rdata fields as a slice. All starting whitespace deleted
func fields(s string, i int) (rdf []string) {
    rdf = strings.Fields(strings.TrimSpace(s))
    for i, _ := range rdf {
        rdf[i] = strings.TrimSpace(rdf[i])
    }
    // every rdf above i should be stiched together without
    // the spaces
    return
}

func atoi(s string) int {
    i, err :=  strconv.Atoi(s)
    if err != nil {
        panic("not a number: " + s)
    }
    return i
}

/*
func rdata_ds(hdr RR_Header, tok *token) RR {
        rr := new(RR_DS)
        rr.Hdr = hdr;
        rr.Hdr.Rrtype = TypeDS
        rr.KeyTag = uint16(tok.N[0])
        rr.Algorithm = uint8(tok.N[1])
        rr.DigestType = uint8(tok.N[2])
        rr.Digest = tok.T[0]
        return rr
}
func rdata_dnskey(hdr RR_Header, tok *token) RR {
        rr := new(RR_DNSKEY)
        rr.Hdr = hdr;
        rr.Hdr.Rrtype = TypeDNSKEY
        rr.Flags = uint16(tok.N[0])
        rr.Protocol = uint8(tok.N[1])
        rr.Algorithm = uint8(tok.N[2])
        rr.PublicKey = tok.T[0]
        return rr
}
func rdata_rrsig(hdr RR_Header, tok *token) RR {
        rr := new(RR_RRSIG)
        rr.Hdr = hdr;
        rr.Hdr.Rrtype = TypeRRSIG
        rr.TypeCovered = uint16(tok.N[0])
        rr.Algorithm = uint8(tok.N[1])
        rr.Labels = uint8(tok.N[2])
        rr.OrigTtl = uint32(tok.N[3])
        rr.Expiration = uint32(tok.N[4])
        rr.Inception = uint32(tok.N[5])
        rr.KeyTag = uint16(tok.N[6])
        rr.SignerName = tok.T[0]
        rr.Signature = tok.T[1]
        return rr
}
*/


// line 78 "zparse.go"
var z_start int = 38
var z_first_final int = 38
var z_error int = 0

var z_en_main int = 38


// line 77 "zparse.rl"


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

        
// line 112 "zparse.go"
	cs = z_start

// line 115 "zparse.go"
	{
	if p == pe { goto _test_eof }
	switch cs {
	case -666: // i am a hack D:
tr23:
// line 5 "types.rl"
	{
        rdf := fields(data[mark:p], 1)
        rr := new(RR_A)
        rr.Hdr = *hdr
        rr.Hdr.Rrtype = TypeA
        rr.A = net.ParseIP(rdf[0])
        z.Push(rr)
    }
// line 107 "zparse.rl"
	{ lines++ }
	goto st38
tr28:
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
// line 107 "zparse.rl"
	{ lines++ }
	goto st38
tr39:
// line 43 "types.rl"
	{
        rdf := fields(data[mark:p], 1)
        rr := new(RR_CNAME)
        rr.Hdr = *hdr
        rr.Hdr.Rrtype = TypeCNAME
        rr.Cname = rdf[0]
        z.Push(rr)
    }
// line 107 "zparse.rl"
	{ lines++ }
	goto st38
tr43:
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
// line 107 "zparse.rl"
	{ lines++ }
	goto st38
tr47:
// line 23 "types.rl"
	{
        rdf := fields(data[mark:p], 1)
        rr := new(RR_NS)
        rr.Hdr = *hdr
        rr.Hdr.Rrtype = TypeNS
        rr.Ns = rdf[0]
        z.Push(rr)
    }
// line 107 "zparse.rl"
	{ lines++ }
	goto st38
tr52:
// line 52 "types.rl"
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
// line 107 "zparse.rl"
	{ lines++ }
	goto st38
tr60:
// line 107 "zparse.rl"
	{ lines++ }
	goto st38
st38:
	p++
	if p == pe { goto _test_eof38 }
	fallthrough
case 38:
// line 223 "zparse.go"
	switch data[p] {
		case 9: goto st1
		case 10: goto tr60
		case 32: goto st1
		case 95: goto tr61
	}
	if data[p] < 48 {
		if 45 <= data[p] && data[p] <= 46 { goto tr61 }
	} else if data[p] > 57 {
		if data[p] > 90 {
			if 97 <= data[p] && data[p] <= 122 { goto tr61 }
		} else if data[p] >= 65 {
			goto tr61
		}
	} else {
		goto tr61
	}
	goto st0
st0:
cs = 0;
	goto _out;
tr58:
// line 103 "zparse.rl"
	{ hdr.Name = data[mark:p] }
	goto st1
st1:
	p++
	if p == pe { goto _test_eof1 }
	fallthrough
case 1:
// line 254 "zparse.go"
	switch data[p] {
		case 9: goto st1
		case 32: goto st1
		case 65: goto tr3
		case 67: goto tr4
		case 72: goto tr5
		case 73: goto tr6
		case 77: goto tr7
		case 78: goto tr8
		case 83: goto tr9
		case 97: goto tr3
		case 99: goto tr4
		case 104: goto tr5
		case 105: goto tr6
		case 109: goto tr7
		case 110: goto tr8
		case 115: goto tr9
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr2 }
	goto st0
tr2:
// line 105 "zparse.rl"
	{ /* ... */ }
	goto st2
st2:
	p++
	if p == pe { goto _test_eof2 }
	fallthrough
case 2:
// line 284 "zparse.go"
	switch data[p] {
		case 9: goto tr10
		case 32: goto tr10
	}
	if 48 <= data[p] && data[p] <= 57 { goto st2 }
	goto st0
tr10:
// line 106 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st3
st3:
	p++
	if p == pe { goto _test_eof3 }
	fallthrough
case 3:
// line 300 "zparse.go"
	switch data[p] {
		case 9: goto st3
		case 32: goto st3
		case 65: goto st4
		case 67: goto tr14
		case 72: goto tr15
		case 73: goto tr16
		case 77: goto st19
		case 78: goto st22
		case 83: goto st25
		case 97: goto st4
		case 99: goto tr14
		case 104: goto tr15
		case 105: goto tr16
		case 109: goto st19
		case 110: goto st22
		case 115: goto st25
	}
	goto st0
tr3:
// line 105 "zparse.rl"
	{ /* ... */ }
	goto st4
st4:
	p++
	if p == pe { goto _test_eof4 }
	fallthrough
case 4:
// line 329 "zparse.go"
	switch data[p] {
		case 10: goto st0
		case 65: goto tr21
		case 97: goto tr21
	}
	goto tr20
tr20:
// line 102 "zparse.rl"
	{ mark = p }
	goto st5
st5:
	p++
	if p == pe { goto _test_eof5 }
	fallthrough
case 5:
// line 345 "zparse.go"
	if data[p] == 10 { goto tr23 }
	goto st5
tr21:
// line 102 "zparse.rl"
	{ mark = p }
	goto st6
st6:
	p++
	if p == pe { goto _test_eof6 }
	fallthrough
case 6:
// line 357 "zparse.go"
	switch data[p] {
		case 10: goto tr23
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
		case 10: goto tr23
		case 65: goto st8
		case 97: goto st8
	}
	goto st5
st8:
	p++
	if p == pe { goto _test_eof8 }
	fallthrough
case 8:
	if data[p] == 10 { goto tr23 }
	goto tr26
tr26:
// line 102 "zparse.rl"
	{ mark = p }
	goto st9
st9:
	p++
	if p == pe { goto _test_eof9 }
	fallthrough
case 9:
// line 391 "zparse.go"
	if data[p] == 10 { goto tr28 }
	goto st9
tr14:
// line 102 "zparse.rl"
	{ mark = p }
	goto st10
st10:
	p++
	if p == pe { goto _test_eof10 }
	fallthrough
case 10:
// line 403 "zparse.go"
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
		case 9: goto tr31
		case 32: goto tr31
	}
	goto st0
tr57:
// line 106 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st12
tr31:
// line 104 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st12
st12:
	p++
	if p == pe { goto _test_eof12 }
	fallthrough
case 12:
// line 434 "zparse.go"
	switch data[p] {
		case 9: goto st12
		case 32: goto st12
		case 65: goto st4
		case 67: goto st13
		case 77: goto st19
		case 78: goto st22
		case 83: goto st25
		case 97: goto st4
		case 99: goto st13
		case 109: goto st19
		case 110: goto st22
		case 115: goto st25
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
	goto tr37
tr37:
// line 102 "zparse.rl"
	{ mark = p }
	goto st18
st18:
	p++
	if p == pe { goto _test_eof18 }
	fallthrough
case 18:
// line 506 "zparse.go"
	if data[p] == 10 { goto tr39 }
	goto st18
tr7:
// line 105 "zparse.rl"
	{ /* ... */ }
	goto st19
st19:
	p++
	if p == pe { goto _test_eof19 }
	fallthrough
case 19:
// line 518 "zparse.go"
	switch data[p] {
		case 88: goto st20
		case 120: goto st20
	}
	goto st0
st20:
	p++
	if p == pe { goto _test_eof20 }
	fallthrough
case 20:
	if data[p] == 10 { goto st0 }
	goto tr41
tr41:
// line 102 "zparse.rl"
	{ mark = p }
	goto st21
st21:
	p++
	if p == pe { goto _test_eof21 }
	fallthrough
case 21:
// line 540 "zparse.go"
	if data[p] == 10 { goto tr43 }
	goto st21
tr8:
// line 105 "zparse.rl"
	{ /* ... */ }
	goto st22
st22:
	p++
	if p == pe { goto _test_eof22 }
	fallthrough
case 22:
// line 552 "zparse.go"
	switch data[p] {
		case 83: goto st23
		case 115: goto st23
	}
	goto st0
st23:
	p++
	if p == pe { goto _test_eof23 }
	fallthrough
case 23:
	if data[p] == 10 { goto st0 }
	goto tr45
tr45:
// line 102 "zparse.rl"
	{ mark = p }
	goto st24
st24:
	p++
	if p == pe { goto _test_eof24 }
	fallthrough
case 24:
// line 574 "zparse.go"
	if data[p] == 10 { goto tr47 }
	goto st24
tr9:
// line 105 "zparse.rl"
	{ /* ... */ }
	goto st25
st25:
	p++
	if p == pe { goto _test_eof25 }
	fallthrough
case 25:
// line 586 "zparse.go"
	switch data[p] {
		case 79: goto st26
		case 111: goto st26
	}
	goto st0
st26:
	p++
	if p == pe { goto _test_eof26 }
	fallthrough
case 26:
	switch data[p] {
		case 65: goto st27
		case 97: goto st27
	}
	goto st0
st27:
	p++
	if p == pe { goto _test_eof27 }
	fallthrough
case 27:
	if data[p] == 10 { goto st0 }
	goto tr50
tr50:
// line 102 "zparse.rl"
	{ mark = p }
	goto st28
st28:
	p++
	if p == pe { goto _test_eof28 }
	fallthrough
case 28:
// line 618 "zparse.go"
	if data[p] == 10 { goto tr52 }
	goto st28
tr15:
// line 102 "zparse.rl"
	{ mark = p }
	goto st29
st29:
	p++
	if p == pe { goto _test_eof29 }
	fallthrough
case 29:
// line 630 "zparse.go"
	switch data[p] {
		case 83: goto st11
		case 115: goto st11
	}
	goto st0
tr16:
// line 102 "zparse.rl"
	{ mark = p }
	goto st30
st30:
	p++
	if p == pe { goto _test_eof30 }
	fallthrough
case 30:
// line 645 "zparse.go"
	switch data[p] {
		case 78: goto st11
		case 110: goto st11
	}
	goto st0
tr4:
// line 105 "zparse.rl"
	{ /* ... */ }
// line 102 "zparse.rl"
	{ mark = p }
	goto st31
st31:
	p++
	if p == pe { goto _test_eof31 }
	fallthrough
case 31:
// line 662 "zparse.go"
	switch data[p] {
		case 72: goto st32
		case 78: goto st14
		case 104: goto st32
		case 110: goto st14
	}
	goto st0
st32:
	p++
	if p == pe { goto _test_eof32 }
	fallthrough
case 32:
	switch data[p] {
		case 9: goto tr54
		case 32: goto tr54
	}
	goto st0
tr54:
// line 104 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st33
st33:
	p++
	if p == pe { goto _test_eof33 }
	fallthrough
case 33:
// line 689 "zparse.go"
	switch data[p] {
		case 9: goto st33
		case 32: goto st33
		case 65: goto st4
		case 67: goto st13
		case 77: goto st19
		case 78: goto st22
		case 83: goto st25
		case 97: goto st4
		case 99: goto st13
		case 109: goto st19
		case 110: goto st22
		case 115: goto st25
	}
	if 48 <= data[p] && data[p] <= 57 { goto st34 }
	goto st0
st34:
	p++
	if p == pe { goto _test_eof34 }
	fallthrough
case 34:
	switch data[p] {
		case 9: goto tr57
		case 32: goto tr57
	}
	if 48 <= data[p] && data[p] <= 57 { goto st34 }
	goto st0
tr5:
// line 105 "zparse.rl"
	{ /* ... */ }
// line 102 "zparse.rl"
	{ mark = p }
	goto st35
st35:
	p++
	if p == pe { goto _test_eof35 }
	fallthrough
case 35:
// line 728 "zparse.go"
	switch data[p] {
		case 83: goto st32
		case 115: goto st32
	}
	goto st0
tr6:
// line 105 "zparse.rl"
	{ /* ... */ }
// line 102 "zparse.rl"
	{ mark = p }
	goto st36
st36:
	p++
	if p == pe { goto _test_eof36 }
	fallthrough
case 36:
// line 745 "zparse.go"
	switch data[p] {
		case 78: goto st32
		case 110: goto st32
	}
	goto st0
tr61:
// line 102 "zparse.rl"
	{ mark = p }
	goto st37
st37:
	p++
	if p == pe { goto _test_eof37 }
	fallthrough
case 37:
// line 760 "zparse.go"
	switch data[p] {
		case 9: goto tr58
		case 32: goto tr58
		case 95: goto st37
	}
	if data[p] < 48 {
		if 45 <= data[p] && data[p] <= 46 { goto st37 }
	} else if data[p] > 57 {
		if data[p] > 90 {
			if 97 <= data[p] && data[p] <= 122 { goto st37 }
		} else if data[p] >= 65 {
			goto st37
		}
	} else {
		goto st37
	}
	goto st0
	}
	_test_eof38: cs = 38; goto _test_eof; 
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

	_test_eof: {}
	_out: {}
	}

// line 150 "zparse.rl"

        
        if eof > -1 {
                if cs < z_first_final {
                        // No clue what I'm doing what so ever
                        if p == pe {
                                println("unexpected eof")
                                return z, nil
                        } else {
                                println("error at position ", p, "\"",data[mark:p],"\"")
                                return z, nil
                        }
                }
        }
        return z, nil
}
