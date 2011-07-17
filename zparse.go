
// line 1 "zparse.rl"
package dns

// Parse RRs
// With the thankful help of gdnsd and the Go examples for Ragel 

import (
    "os"
    "io"
    "net"
    "bufio"
    "strconv"
)

const _RDATAMAX = 7
const _IOBUF = 65365

// Save up tokens, after we've seen the entire rdata
// we can use this.
type token struct {
    T []string      // text
    N []int         // number
    ti int          // text counter
    ni int          // number counter
}

func newToken() *token {
    to := new(token)
    to.T = make([]string, _RDATAMAX)
    to.N = make([]int, _RDATAMAX)
    to.ni, to.ti = 0, 0
    return to
}

// Only push functions are provided. Reading is done, by directly
// accessing the members (T and N). See types.rl.
func (to *token) pushInt(s string) {
    i, err := strconv.Atoi(s)
    if err != nil {
        panic("Failure to parse to int: " + s)
    }
    to.N[to.ni] = i
    to.ni++
    if to.ni > _RDATAMAX {
        panic("Too much rdata (int)")
    }
}

func (to *token) pushString(s string) {
    to.T[to.ti] = s
    to.ti++
    if to.ti > _RDATAMAX {
        panic("Too much rdata (string)")
    }
}

func (to *token) reset() {
    to.ni, to.ti = 0, 0
}


// line 64 "zparse.go"
var z_start int = 1
var z_first_final int = 102
var z_error int = 0

var z_en_main int = 1


// line 63 "zparse.rl"


// only works for short io.Readers as we put the whole thing
// in a string -- needs to be extended for large files (sliding window).
func Zparse(q io.Reader) (rr RR, err os.Error) {
        r := bufio.NewReader(q)
        buf := make([]byte, _IOBUF) 
        n, err := r.Read(buf)
        if err != nil {
            return nil, err
        }
        buf = buf[:n]

        data := string(buf)
        cs, p, pe, eof := 0, 0, len(data), len(data)
        mark := 0
        hdr := new(RR_Header)
        tok := newToken()

        
// line 93 "zparse.go"
	cs = z_start

// line 96 "zparse.go"
	{
	if p == pe { goto _test_eof }
	switch cs {
	case -666: // i am a hack D:
	fallthrough
case 1:
	switch data[p] {
		case 9: goto st2
		case 32: goto st2
		case 46: goto st84
		case 92: goto st84
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st84 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st84 }
	} else {
		goto st84
	}
	goto st0
st0:
cs = 0;
	goto _out;
tr158:
// line 84 "zparse.rl"
	{ hdr.Name = data[mark:p] }
	goto st2
tr170:
// line 89 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr.(*RR_A).Hdr = *hdr
            rr.(*RR_A).A = net.ParseIP(data[mark:p])
        }
	goto st2
tr172:
// line 89 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 12 "types.rl"
	{
            rr.(*RR_CNAME).Hdr = *hdr
            rr.(*RR_CNAME).Cname = tok.T[0]
        }
	goto st2
tr174:
// line 89 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 38 "types.rl"
	{
            rr.(*RR_DNSKEY).Hdr = *hdr;
            rr.(*RR_DNSKEY).Flags = uint16(tok.N[0])
            rr.(*RR_DNSKEY).Protocol = uint8(tok.N[1])
            rr.(*RR_DNSKEY).Algorithm = uint8(tok.N[2])
            rr.(*RR_DNSKEY).PublicKey = tok.T[0]
        }
	goto st2
tr176:
// line 89 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 31 "types.rl"
	{
            rr.(*RR_DS).Hdr = *hdr;
            rr.(*RR_DS).KeyTag = uint16(tok.N[0])
            rr.(*RR_DS).Algorithm = uint8(tok.N[1])
            rr.(*RR_DS).DigestType = uint8(tok.N[2])
            rr.(*RR_DS).Digest = tok.T[0]
        }
	goto st2
tr178:
// line 89 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 26 "types.rl"
	{
            rr.(*RR_MX).Hdr = *hdr;
            rr.(*RR_MX).Pref = uint16(tok.N[0])
            rr.(*RR_MX).Mx = tok.T[0]
        }
	goto st2
tr180:
// line 89 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 8 "types.rl"
	{
            rr.(*RR_NS).Hdr = *hdr
            rr.(*RR_NS).Ns = tok.T[0]
        }
	goto st2
tr182:
// line 89 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr.(*RR_RRSIG).Hdr = *hdr;
            rr.(*RR_RRSIG).TypeCovered = uint16(tok.N[0])
            rr.(*RR_RRSIG).Algorithm = uint8(tok.N[1])
            rr.(*RR_RRSIG).Labels = uint8(tok.N[2])
            rr.(*RR_RRSIG).OrigTtl = uint32(tok.N[3])
            rr.(*RR_RRSIG).Expiration = uint32(tok.N[4])
            rr.(*RR_RRSIG).Inception = uint32(tok.N[5])
            rr.(*RR_RRSIG).KeyTag = uint16(tok.N[6])
            rr.(*RR_RRSIG).SignerName = tok.T[0]
            rr.(*RR_RRSIG).Signature = tok.T[1]
        }
	goto st2
tr184:
// line 88 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 16 "types.rl"
	{
            rr.(*RR_SOA).Hdr = *hdr
            rr.(*RR_SOA).Ns = tok.T[0]
            rr.(*RR_SOA).Mbox = tok.T[1]
            rr.(*RR_SOA).Serial = uint32(tok.N[0])
            rr.(*RR_SOA).Refresh = uint32(tok.N[1])
            rr.(*RR_SOA).Retry = uint32(tok.N[2])
            rr.(*RR_SOA).Expire = uint32(tok.N[3])
            rr.(*RR_SOA).Minttl = uint32(tok.N[4])
        }
	goto st2
st2:
	p++
	if p == pe { goto _test_eof2 }
	fallthrough
case 2:
// line 222 "zparse.go"
	switch data[p] {
		case 9: goto st2
		case 32: goto st2
		case 65: goto tr4
		case 67: goto tr5
		case 68: goto tr6
		case 72: goto tr7
		case 73: goto tr8
		case 77: goto tr9
		case 78: goto tr10
		case 82: goto tr11
		case 83: goto tr12
		case 97: goto tr4
		case 99: goto tr5
		case 100: goto tr6
		case 104: goto tr7
		case 105: goto tr8
		case 109: goto tr9
		case 110: goto tr10
		case 114: goto tr11
		case 115: goto tr12
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr3 }
	goto st0
tr3:
// line 83 "zparse.rl"
	{ mark = p }
// line 86 "zparse.rl"
	{ /* ... */ }
	goto st3
st3:
	p++
	if p == pe { goto _test_eof3 }
	fallthrough
case 3:
// line 258 "zparse.go"
	switch data[p] {
		case 9: goto tr13
		case 32: goto tr13
	}
	if 48 <= data[p] && data[p] <= 57 { goto st3 }
	goto st0
tr13:
// line 87 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st4
st4:
	p++
	if p == pe { goto _test_eof4 }
	fallthrough
case 4:
// line 274 "zparse.go"
	switch data[p] {
		case 9: goto st4
		case 32: goto st4
		case 65: goto tr16
		case 67: goto tr17
		case 68: goto tr18
		case 72: goto tr19
		case 73: goto tr20
		case 77: goto tr21
		case 78: goto tr22
		case 82: goto tr23
		case 83: goto tr24
		case 97: goto tr16
		case 99: goto tr17
		case 100: goto tr18
		case 104: goto tr19
		case 105: goto tr20
		case 109: goto tr21
		case 110: goto tr22
		case 114: goto tr23
		case 115: goto tr24
	}
	goto st0
tr16:
// line 83 "zparse.rl"
	{ mark = p }
	goto st5
st5:
	p++
	if p == pe { goto _test_eof5 }
	fallthrough
case 5:
// line 307 "zparse.go"
	switch data[p] {
		case 9: goto tr25
		case 32: goto tr25
		case 78: goto st7
		case 110: goto st7
	}
	goto st0
tr25:
// line 92 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    rr = mk()
                    hdr.Rrtype = i
                }
	goto st6
st6:
	p++
	if p == pe { goto _test_eof6 }
	fallthrough
case 6:
// line 332 "zparse.go"
	switch data[p] {
		case 9: goto st6
		case 32: goto st6
		case 43: goto tr28
		case 61: goto tr28
		case 92: goto tr28
	}
	if data[p] < 65 {
		if 46 <= data[p] && data[p] <= 57 { goto tr28 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr28 }
	} else {
		goto tr28
	}
	goto st0
tr28:
// line 83 "zparse.rl"
	{ mark = p }
	goto st102
st102:
	p++
	if p == pe { goto _test_eof102 }
	fallthrough
case 102:
// line 357 "zparse.go"
	switch data[p] {
		case 9: goto tr170
		case 32: goto tr170
		case 43: goto st102
		case 61: goto st102
		case 92: goto st102
	}
	if data[p] < 65 {
		if 46 <= data[p] && data[p] <= 57 { goto st102 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st102 }
	} else {
		goto st102
	}
	goto st0
st7:
	p++
	if p == pe { goto _test_eof7 }
	fallthrough
case 7:
	switch data[p] {
		case 89: goto st8
		case 121: goto st8
	}
	goto st0
st8:
	p++
	if p == pe { goto _test_eof8 }
	fallthrough
case 8:
	switch data[p] {
		case 9: goto tr30
		case 32: goto tr30
	}
	goto st0
tr166:
// line 87 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st9
tr30:
// line 85 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st9
st9:
	p++
	if p == pe { goto _test_eof9 }
	fallthrough
case 9:
// line 406 "zparse.go"
	switch data[p] {
		case 9: goto st9
		case 32: goto st9
		case 65: goto tr32
		case 67: goto tr33
		case 68: goto tr18
		case 77: goto tr21
		case 78: goto tr34
		case 82: goto tr23
		case 83: goto tr24
		case 97: goto tr32
		case 99: goto tr33
		case 100: goto tr18
		case 109: goto tr21
		case 110: goto tr34
		case 114: goto tr23
		case 115: goto tr24
	}
	goto st0
tr32:
// line 83 "zparse.rl"
	{ mark = p }
	goto st10
st10:
	p++
	if p == pe { goto _test_eof10 }
	fallthrough
case 10:
// line 435 "zparse.go"
	switch data[p] {
		case 9: goto tr25
		case 32: goto tr25
	}
	goto st0
tr33:
// line 83 "zparse.rl"
	{ mark = p }
	goto st11
st11:
	p++
	if p == pe { goto _test_eof11 }
	fallthrough
case 11:
// line 450 "zparse.go"
	switch data[p] {
		case 78: goto st12
		case 110: goto st12
	}
	goto st0
st12:
	p++
	if p == pe { goto _test_eof12 }
	fallthrough
case 12:
	switch data[p] {
		case 65: goto st13
		case 97: goto st13
	}
	goto st0
st13:
	p++
	if p == pe { goto _test_eof13 }
	fallthrough
case 13:
	switch data[p] {
		case 77: goto st14
		case 109: goto st14
	}
	goto st0
st14:
	p++
	if p == pe { goto _test_eof14 }
	fallthrough
case 14:
	switch data[p] {
		case 69: goto st15
		case 101: goto st15
	}
	goto st0
st15:
	p++
	if p == pe { goto _test_eof15 }
	fallthrough
case 15:
	switch data[p] {
		case 9: goto tr39
		case 32: goto tr39
	}
	goto st0
tr39:
// line 92 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    rr = mk()
                    hdr.Rrtype = i
                }
	goto st16
st16:
	p++
	if p == pe { goto _test_eof16 }
	fallthrough
case 16:
// line 513 "zparse.go"
	switch data[p] {
		case 9: goto st16
		case 32: goto st16
		case 43: goto tr41
		case 61: goto tr41
		case 92: goto tr41
	}
	if data[p] < 65 {
		if 46 <= data[p] && data[p] <= 57 { goto tr41 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr41 }
	} else {
		goto tr41
	}
	goto st0
tr41:
// line 83 "zparse.rl"
	{ mark = p }
	goto st103
st103:
	p++
	if p == pe { goto _test_eof103 }
	fallthrough
case 103:
// line 538 "zparse.go"
	switch data[p] {
		case 9: goto tr172
		case 32: goto tr172
		case 43: goto st103
		case 61: goto st103
		case 92: goto st103
	}
	if data[p] < 65 {
		if 46 <= data[p] && data[p] <= 57 { goto st103 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st103 }
	} else {
		goto st103
	}
	goto st0
tr6:
// line 83 "zparse.rl"
	{ mark = p }
// line 86 "zparse.rl"
	{ /* ... */ }
	goto st17
tr18:
// line 83 "zparse.rl"
	{ mark = p }
	goto st17
st17:
	p++
	if p == pe { goto _test_eof17 }
	fallthrough
case 17:
// line 569 "zparse.go"
	switch data[p] {
		case 78: goto st18
		case 83: goto st30
		case 110: goto st18
		case 115: goto st30
	}
	goto st0
st18:
	p++
	if p == pe { goto _test_eof18 }
	fallthrough
case 18:
	switch data[p] {
		case 83: goto st19
		case 115: goto st19
	}
	goto st0
st19:
	p++
	if p == pe { goto _test_eof19 }
	fallthrough
case 19:
	switch data[p] {
		case 75: goto st20
		case 107: goto st20
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
	switch data[p] {
		case 89: goto st22
		case 121: goto st22
	}
	goto st0
st22:
	p++
	if p == pe { goto _test_eof22 }
	fallthrough
case 22:
	switch data[p] {
		case 9: goto tr48
		case 32: goto tr48
	}
	goto st0
tr48:
// line 92 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    rr = mk()
                    hdr.Rrtype = i
                }
	goto st23
st23:
	p++
	if p == pe { goto _test_eof23 }
	fallthrough
case 23:
// line 644 "zparse.go"
	switch data[p] {
		case 9: goto st23
		case 32: goto st23
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr50 }
	goto st0
tr50:
// line 83 "zparse.rl"
	{ mark = p }
	goto st24
st24:
	p++
	if p == pe { goto _test_eof24 }
	fallthrough
case 24:
// line 660 "zparse.go"
	switch data[p] {
		case 9: goto tr51
		case 32: goto tr51
	}
	if 48 <= data[p] && data[p] <= 57 { goto st24 }
	goto st0
tr51:
// line 88 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st25
st25:
	p++
	if p == pe { goto _test_eof25 }
	fallthrough
case 25:
// line 676 "zparse.go"
	switch data[p] {
		case 9: goto st25
		case 32: goto st25
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr54 }
	goto st0
tr54:
// line 83 "zparse.rl"
	{ mark = p }
	goto st26
st26:
	p++
	if p == pe { goto _test_eof26 }
	fallthrough
case 26:
// line 692 "zparse.go"
	switch data[p] {
		case 9: goto tr55
		case 32: goto tr55
	}
	if 48 <= data[p] && data[p] <= 57 { goto st26 }
	goto st0
tr55:
// line 88 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st27
st27:
	p++
	if p == pe { goto _test_eof27 }
	fallthrough
case 27:
// line 708 "zparse.go"
	switch data[p] {
		case 9: goto st27
		case 32: goto st27
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr58 }
	goto st0
tr58:
// line 83 "zparse.rl"
	{ mark = p }
	goto st28
st28:
	p++
	if p == pe { goto _test_eof28 }
	fallthrough
case 28:
// line 724 "zparse.go"
	switch data[p] {
		case 9: goto tr59
		case 32: goto tr59
	}
	if 48 <= data[p] && data[p] <= 57 { goto st28 }
	goto st0
tr59:
// line 88 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st29
st29:
	p++
	if p == pe { goto _test_eof29 }
	fallthrough
case 29:
// line 740 "zparse.go"
	switch data[p] {
		case 9: goto st29
		case 32: goto st29
		case 43: goto tr62
		case 61: goto tr62
		case 92: goto tr62
	}
	if data[p] < 65 {
		if 46 <= data[p] && data[p] <= 57 { goto tr62 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr62 }
	} else {
		goto tr62
	}
	goto st0
tr62:
// line 83 "zparse.rl"
	{ mark = p }
	goto st104
st104:
	p++
	if p == pe { goto _test_eof104 }
	fallthrough
case 104:
// line 765 "zparse.go"
	switch data[p] {
		case 9: goto tr174
		case 32: goto tr174
		case 43: goto st104
		case 61: goto st104
		case 92: goto st104
	}
	if data[p] < 65 {
		if 46 <= data[p] && data[p] <= 57 { goto st104 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st104 }
	} else {
		goto st104
	}
	goto st0
st30:
	p++
	if p == pe { goto _test_eof30 }
	fallthrough
case 30:
	switch data[p] {
		case 9: goto tr63
		case 32: goto tr63
	}
	goto st0
tr63:
// line 92 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    rr = mk()
                    hdr.Rrtype = i
                }
	goto st31
st31:
	p++
	if p == pe { goto _test_eof31 }
	fallthrough
case 31:
// line 808 "zparse.go"
	switch data[p] {
		case 9: goto st31
		case 32: goto st31
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr65 }
	goto st0
tr65:
// line 83 "zparse.rl"
	{ mark = p }
	goto st32
st32:
	p++
	if p == pe { goto _test_eof32 }
	fallthrough
case 32:
// line 824 "zparse.go"
	switch data[p] {
		case 9: goto tr66
		case 32: goto tr66
	}
	if 48 <= data[p] && data[p] <= 57 { goto st32 }
	goto st0
tr66:
// line 88 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st33
st33:
	p++
	if p == pe { goto _test_eof33 }
	fallthrough
case 33:
// line 840 "zparse.go"
	switch data[p] {
		case 9: goto st33
		case 32: goto st33
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr69 }
	goto st0
tr69:
// line 83 "zparse.rl"
	{ mark = p }
	goto st34
st34:
	p++
	if p == pe { goto _test_eof34 }
	fallthrough
case 34:
// line 856 "zparse.go"
	switch data[p] {
		case 9: goto tr70
		case 32: goto tr70
	}
	if 48 <= data[p] && data[p] <= 57 { goto st34 }
	goto st0
tr70:
// line 88 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st35
st35:
	p++
	if p == pe { goto _test_eof35 }
	fallthrough
case 35:
// line 872 "zparse.go"
	switch data[p] {
		case 9: goto st35
		case 32: goto st35
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr73 }
	goto st0
tr73:
// line 83 "zparse.rl"
	{ mark = p }
	goto st36
st36:
	p++
	if p == pe { goto _test_eof36 }
	fallthrough
case 36:
// line 888 "zparse.go"
	switch data[p] {
		case 9: goto tr74
		case 32: goto tr74
	}
	if 48 <= data[p] && data[p] <= 57 { goto st36 }
	goto st0
tr74:
// line 88 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st37
st37:
	p++
	if p == pe { goto _test_eof37 }
	fallthrough
case 37:
// line 904 "zparse.go"
	switch data[p] {
		case 9: goto st37
		case 32: goto st37
		case 43: goto tr77
		case 61: goto tr77
		case 92: goto tr77
	}
	if data[p] < 65 {
		if 46 <= data[p] && data[p] <= 57 { goto tr77 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr77 }
	} else {
		goto tr77
	}
	goto st0
tr77:
// line 83 "zparse.rl"
	{ mark = p }
	goto st105
st105:
	p++
	if p == pe { goto _test_eof105 }
	fallthrough
case 105:
// line 929 "zparse.go"
	switch data[p] {
		case 9: goto tr176
		case 32: goto tr176
		case 43: goto st105
		case 61: goto st105
		case 92: goto st105
	}
	if data[p] < 65 {
		if 46 <= data[p] && data[p] <= 57 { goto st105 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st105 }
	} else {
		goto st105
	}
	goto st0
tr9:
// line 83 "zparse.rl"
	{ mark = p }
// line 86 "zparse.rl"
	{ /* ... */ }
	goto st38
tr21:
// line 83 "zparse.rl"
	{ mark = p }
	goto st38
st38:
	p++
	if p == pe { goto _test_eof38 }
	fallthrough
case 38:
// line 960 "zparse.go"
	switch data[p] {
		case 88: goto st39
		case 120: goto st39
	}
	goto st0
st39:
	p++
	if p == pe { goto _test_eof39 }
	fallthrough
case 39:
	switch data[p] {
		case 9: goto tr79
		case 32: goto tr79
	}
	goto st0
tr79:
// line 92 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    rr = mk()
                    hdr.Rrtype = i
                }
	goto st40
st40:
	p++
	if p == pe { goto _test_eof40 }
	fallthrough
case 40:
// line 993 "zparse.go"
	switch data[p] {
		case 9: goto st40
		case 32: goto st40
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr81 }
	goto st0
tr81:
// line 83 "zparse.rl"
	{ mark = p }
	goto st41
st41:
	p++
	if p == pe { goto _test_eof41 }
	fallthrough
case 41:
// line 1009 "zparse.go"
	switch data[p] {
		case 9: goto tr82
		case 32: goto tr82
	}
	if 48 <= data[p] && data[p] <= 57 { goto st41 }
	goto st0
tr82:
// line 88 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st42
st42:
	p++
	if p == pe { goto _test_eof42 }
	fallthrough
case 42:
// line 1025 "zparse.go"
	switch data[p] {
		case 9: goto st42
		case 32: goto st42
		case 43: goto tr85
		case 61: goto tr85
		case 92: goto tr85
	}
	if data[p] < 65 {
		if 46 <= data[p] && data[p] <= 57 { goto tr85 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr85 }
	} else {
		goto tr85
	}
	goto st0
tr85:
// line 83 "zparse.rl"
	{ mark = p }
	goto st106
st106:
	p++
	if p == pe { goto _test_eof106 }
	fallthrough
case 106:
// line 1050 "zparse.go"
	switch data[p] {
		case 9: goto tr178
		case 32: goto tr178
		case 43: goto st106
		case 61: goto st106
		case 92: goto st106
	}
	if data[p] < 65 {
		if 46 <= data[p] && data[p] <= 57 { goto st106 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st106 }
	} else {
		goto st106
	}
	goto st0
tr34:
// line 83 "zparse.rl"
	{ mark = p }
	goto st43
st43:
	p++
	if p == pe { goto _test_eof43 }
	fallthrough
case 43:
// line 1075 "zparse.go"
	switch data[p] {
		case 83: goto st44
		case 115: goto st44
	}
	goto st0
st44:
	p++
	if p == pe { goto _test_eof44 }
	fallthrough
case 44:
	switch data[p] {
		case 9: goto tr87
		case 32: goto tr87
	}
	goto st0
tr87:
// line 92 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    rr = mk()
                    hdr.Rrtype = i
                }
	goto st45
st45:
	p++
	if p == pe { goto _test_eof45 }
	fallthrough
case 45:
// line 1108 "zparse.go"
	switch data[p] {
		case 9: goto st45
		case 32: goto st45
		case 43: goto tr89
		case 61: goto tr89
		case 92: goto tr89
	}
	if data[p] < 65 {
		if 46 <= data[p] && data[p] <= 57 { goto tr89 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr89 }
	} else {
		goto tr89
	}
	goto st0
tr89:
// line 83 "zparse.rl"
	{ mark = p }
	goto st107
st107:
	p++
	if p == pe { goto _test_eof107 }
	fallthrough
case 107:
// line 1133 "zparse.go"
	switch data[p] {
		case 9: goto tr180
		case 32: goto tr180
		case 43: goto st107
		case 61: goto st107
		case 92: goto st107
	}
	if data[p] < 65 {
		if 46 <= data[p] && data[p] <= 57 { goto st107 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st107 }
	} else {
		goto st107
	}
	goto st0
tr11:
// line 83 "zparse.rl"
	{ mark = p }
// line 86 "zparse.rl"
	{ /* ... */ }
	goto st46
tr23:
// line 83 "zparse.rl"
	{ mark = p }
	goto st46
st46:
	p++
	if p == pe { goto _test_eof46 }
	fallthrough
case 46:
// line 1164 "zparse.go"
	switch data[p] {
		case 82: goto st47
		case 114: goto st47
	}
	goto st0
st47:
	p++
	if p == pe { goto _test_eof47 }
	fallthrough
case 47:
	switch data[p] {
		case 83: goto st48
		case 115: goto st48
	}
	goto st0
st48:
	p++
	if p == pe { goto _test_eof48 }
	fallthrough
case 48:
	switch data[p] {
		case 73: goto st49
		case 105: goto st49
	}
	goto st0
st49:
	p++
	if p == pe { goto _test_eof49 }
	fallthrough
case 49:
	switch data[p] {
		case 71: goto st50
		case 103: goto st50
	}
	goto st0
st50:
	p++
	if p == pe { goto _test_eof50 }
	fallthrough
case 50:
	switch data[p] {
		case 9: goto tr94
		case 32: goto tr94
	}
	goto st0
tr94:
// line 92 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    rr = mk()
                    hdr.Rrtype = i
                }
	goto st51
st51:
	p++
	if p == pe { goto _test_eof51 }
	fallthrough
case 51:
// line 1227 "zparse.go"
	switch data[p] {
		case 9: goto st51
		case 32: goto st51
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr96 }
	goto st0
tr96:
// line 83 "zparse.rl"
	{ mark = p }
	goto st52
st52:
	p++
	if p == pe { goto _test_eof52 }
	fallthrough
case 52:
// line 1243 "zparse.go"
	switch data[p] {
		case 9: goto tr97
		case 32: goto tr97
	}
	if 48 <= data[p] && data[p] <= 57 { goto st52 }
	goto st0
tr97:
// line 88 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st53
st53:
	p++
	if p == pe { goto _test_eof53 }
	fallthrough
case 53:
// line 1259 "zparse.go"
	switch data[p] {
		case 9: goto st53
		case 32: goto st53
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr100 }
	goto st0
tr100:
// line 83 "zparse.rl"
	{ mark = p }
	goto st54
st54:
	p++
	if p == pe { goto _test_eof54 }
	fallthrough
case 54:
// line 1275 "zparse.go"
	switch data[p] {
		case 9: goto tr101
		case 32: goto tr101
	}
	if 48 <= data[p] && data[p] <= 57 { goto st54 }
	goto st0
tr101:
// line 88 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st55
st55:
	p++
	if p == pe { goto _test_eof55 }
	fallthrough
case 55:
// line 1291 "zparse.go"
	switch data[p] {
		case 9: goto st55
		case 32: goto st55
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr104 }
	goto st0
tr104:
// line 83 "zparse.rl"
	{ mark = p }
	goto st56
st56:
	p++
	if p == pe { goto _test_eof56 }
	fallthrough
case 56:
// line 1307 "zparse.go"
	switch data[p] {
		case 9: goto tr105
		case 32: goto tr105
	}
	if 48 <= data[p] && data[p] <= 57 { goto st56 }
	goto st0
tr105:
// line 88 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st57
st57:
	p++
	if p == pe { goto _test_eof57 }
	fallthrough
case 57:
// line 1323 "zparse.go"
	switch data[p] {
		case 9: goto st57
		case 32: goto st57
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr108 }
	goto st0
tr108:
// line 83 "zparse.rl"
	{ mark = p }
	goto st58
st58:
	p++
	if p == pe { goto _test_eof58 }
	fallthrough
case 58:
// line 1339 "zparse.go"
	switch data[p] {
		case 9: goto tr109
		case 32: goto tr109
	}
	if 48 <= data[p] && data[p] <= 57 { goto st58 }
	goto st0
tr109:
// line 88 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st59
st59:
	p++
	if p == pe { goto _test_eof59 }
	fallthrough
case 59:
// line 1355 "zparse.go"
	switch data[p] {
		case 9: goto st59
		case 32: goto st59
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr112 }
	goto st0
tr112:
// line 83 "zparse.rl"
	{ mark = p }
	goto st60
st60:
	p++
	if p == pe { goto _test_eof60 }
	fallthrough
case 60:
// line 1371 "zparse.go"
	switch data[p] {
		case 9: goto tr113
		case 32: goto tr113
	}
	if 48 <= data[p] && data[p] <= 57 { goto st60 }
	goto st0
tr113:
// line 88 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st61
st61:
	p++
	if p == pe { goto _test_eof61 }
	fallthrough
case 61:
// line 1387 "zparse.go"
	switch data[p] {
		case 9: goto st61
		case 32: goto st61
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr116 }
	goto st0
tr116:
// line 83 "zparse.rl"
	{ mark = p }
	goto st62
st62:
	p++
	if p == pe { goto _test_eof62 }
	fallthrough
case 62:
// line 1403 "zparse.go"
	switch data[p] {
		case 9: goto tr117
		case 32: goto tr117
	}
	if 48 <= data[p] && data[p] <= 57 { goto st62 }
	goto st0
tr117:
// line 88 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st63
st63:
	p++
	if p == pe { goto _test_eof63 }
	fallthrough
case 63:
// line 1419 "zparse.go"
	switch data[p] {
		case 9: goto st63
		case 32: goto st63
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr120 }
	goto st0
tr120:
// line 83 "zparse.rl"
	{ mark = p }
	goto st64
st64:
	p++
	if p == pe { goto _test_eof64 }
	fallthrough
case 64:
// line 1435 "zparse.go"
	switch data[p] {
		case 9: goto tr121
		case 32: goto tr121
	}
	if 48 <= data[p] && data[p] <= 57 { goto st64 }
	goto st0
tr121:
// line 88 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st65
st65:
	p++
	if p == pe { goto _test_eof65 }
	fallthrough
case 65:
// line 1451 "zparse.go"
	switch data[p] {
		case 9: goto st65
		case 32: goto st65
		case 43: goto tr124
		case 61: goto tr124
		case 92: goto tr124
	}
	if data[p] < 65 {
		if 46 <= data[p] && data[p] <= 57 { goto tr124 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr124 }
	} else {
		goto tr124
	}
	goto st0
tr124:
// line 83 "zparse.rl"
	{ mark = p }
	goto st66
st66:
	p++
	if p == pe { goto _test_eof66 }
	fallthrough
case 66:
// line 1476 "zparse.go"
	switch data[p] {
		case 9: goto tr125
		case 32: goto tr125
		case 43: goto st66
		case 61: goto st66
		case 92: goto st66
	}
	if data[p] < 65 {
		if 46 <= data[p] && data[p] <= 57 { goto st66 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st66 }
	} else {
		goto st66
	}
	goto st0
tr125:
// line 89 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
	goto st67
st67:
	p++
	if p == pe { goto _test_eof67 }
	fallthrough
case 67:
// line 1501 "zparse.go"
	switch data[p] {
		case 9: goto st67
		case 32: goto st67
		case 43: goto tr128
		case 61: goto tr128
		case 92: goto tr128
	}
	if data[p] < 65 {
		if 46 <= data[p] && data[p] <= 57 { goto tr128 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr128 }
	} else {
		goto tr128
	}
	goto st0
tr128:
// line 83 "zparse.rl"
	{ mark = p }
	goto st108
st108:
	p++
	if p == pe { goto _test_eof108 }
	fallthrough
case 108:
// line 1526 "zparse.go"
	switch data[p] {
		case 9: goto tr182
		case 32: goto tr182
		case 43: goto st108
		case 61: goto st108
		case 92: goto st108
	}
	if data[p] < 65 {
		if 46 <= data[p] && data[p] <= 57 { goto st108 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st108 }
	} else {
		goto st108
	}
	goto st0
tr12:
// line 83 "zparse.rl"
	{ mark = p }
// line 86 "zparse.rl"
	{ /* ... */ }
	goto st68
tr24:
// line 83 "zparse.rl"
	{ mark = p }
	goto st68
st68:
	p++
	if p == pe { goto _test_eof68 }
	fallthrough
case 68:
// line 1557 "zparse.go"
	switch data[p] {
		case 79: goto st69
		case 111: goto st69
	}
	goto st0
st69:
	p++
	if p == pe { goto _test_eof69 }
	fallthrough
case 69:
	switch data[p] {
		case 65: goto st70
		case 97: goto st70
	}
	goto st0
st70:
	p++
	if p == pe { goto _test_eof70 }
	fallthrough
case 70:
	switch data[p] {
		case 9: goto tr131
		case 32: goto tr131
	}
	goto st0
tr131:
// line 92 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    rr = mk()
                    hdr.Rrtype = i
                }
	goto st71
st71:
	p++
	if p == pe { goto _test_eof71 }
	fallthrough
case 71:
// line 1600 "zparse.go"
	switch data[p] {
		case 9: goto st71
		case 32: goto st71
		case 43: goto tr133
		case 61: goto tr133
		case 92: goto tr133
	}
	if data[p] < 65 {
		if 46 <= data[p] && data[p] <= 57 { goto tr133 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr133 }
	} else {
		goto tr133
	}
	goto st0
tr133:
// line 83 "zparse.rl"
	{ mark = p }
	goto st72
st72:
	p++
	if p == pe { goto _test_eof72 }
	fallthrough
case 72:
// line 1625 "zparse.go"
	switch data[p] {
		case 9: goto tr134
		case 32: goto tr134
		case 43: goto st72
		case 61: goto st72
		case 92: goto st72
	}
	if data[p] < 65 {
		if 46 <= data[p] && data[p] <= 57 { goto st72 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st72 }
	} else {
		goto st72
	}
	goto st0
tr134:
// line 89 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
	goto st73
st73:
	p++
	if p == pe { goto _test_eof73 }
	fallthrough
case 73:
// line 1650 "zparse.go"
	switch data[p] {
		case 9: goto st73
		case 32: goto st73
		case 43: goto tr137
		case 61: goto tr137
		case 92: goto tr137
	}
	if data[p] < 65 {
		if 46 <= data[p] && data[p] <= 57 { goto tr137 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr137 }
	} else {
		goto tr137
	}
	goto st0
tr137:
// line 83 "zparse.rl"
	{ mark = p }
	goto st74
st74:
	p++
	if p == pe { goto _test_eof74 }
	fallthrough
case 74:
// line 1675 "zparse.go"
	switch data[p] {
		case 9: goto tr138
		case 32: goto tr138
		case 43: goto st74
		case 61: goto st74
		case 92: goto st74
	}
	if data[p] < 65 {
		if 46 <= data[p] && data[p] <= 57 { goto st74 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st74 }
	} else {
		goto st74
	}
	goto st0
tr138:
// line 89 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
	goto st75
st75:
	p++
	if p == pe { goto _test_eof75 }
	fallthrough
case 75:
// line 1700 "zparse.go"
	switch data[p] {
		case 9: goto st75
		case 32: goto st75
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr141 }
	goto st0
tr141:
// line 83 "zparse.rl"
	{ mark = p }
	goto st76
st76:
	p++
	if p == pe { goto _test_eof76 }
	fallthrough
case 76:
// line 1716 "zparse.go"
	switch data[p] {
		case 9: goto tr142
		case 32: goto tr142
	}
	if 48 <= data[p] && data[p] <= 57 { goto st76 }
	goto st0
tr142:
// line 88 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st77
st77:
	p++
	if p == pe { goto _test_eof77 }
	fallthrough
case 77:
// line 1732 "zparse.go"
	switch data[p] {
		case 9: goto st77
		case 32: goto st77
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr145 }
	goto st0
tr145:
// line 83 "zparse.rl"
	{ mark = p }
	goto st78
st78:
	p++
	if p == pe { goto _test_eof78 }
	fallthrough
case 78:
// line 1748 "zparse.go"
	switch data[p] {
		case 9: goto tr146
		case 32: goto tr146
	}
	if 48 <= data[p] && data[p] <= 57 { goto st78 }
	goto st0
tr146:
// line 88 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st79
st79:
	p++
	if p == pe { goto _test_eof79 }
	fallthrough
case 79:
// line 1764 "zparse.go"
	switch data[p] {
		case 9: goto st79
		case 32: goto st79
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr149 }
	goto st0
tr149:
// line 83 "zparse.rl"
	{ mark = p }
	goto st80
st80:
	p++
	if p == pe { goto _test_eof80 }
	fallthrough
case 80:
// line 1780 "zparse.go"
	switch data[p] {
		case 9: goto tr150
		case 32: goto tr150
	}
	if 48 <= data[p] && data[p] <= 57 { goto st80 }
	goto st0
tr150:
// line 88 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st81
st81:
	p++
	if p == pe { goto _test_eof81 }
	fallthrough
case 81:
// line 1796 "zparse.go"
	switch data[p] {
		case 9: goto st81
		case 32: goto st81
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr153 }
	goto st0
tr153:
// line 83 "zparse.rl"
	{ mark = p }
	goto st82
st82:
	p++
	if p == pe { goto _test_eof82 }
	fallthrough
case 82:
// line 1812 "zparse.go"
	switch data[p] {
		case 9: goto tr154
		case 32: goto tr154
	}
	if 48 <= data[p] && data[p] <= 57 { goto st82 }
	goto st0
tr154:
// line 88 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st83
st83:
	p++
	if p == pe { goto _test_eof83 }
	fallthrough
case 83:
// line 1828 "zparse.go"
	switch data[p] {
		case 9: goto st83
		case 32: goto st83
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr157 }
	goto st0
tr157:
// line 83 "zparse.rl"
	{ mark = p }
	goto st109
st109:
	p++
	if p == pe { goto _test_eof109 }
	fallthrough
case 109:
// line 1844 "zparse.go"
	switch data[p] {
		case 9: goto tr184
		case 32: goto tr184
		case 46: goto tr185
		case 92: goto tr185
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st109 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr185 }
	} else {
		goto tr185
	}
	goto st0
tr185:
// line 88 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 16 "types.rl"
	{
            rr.(*RR_SOA).Hdr = *hdr
            rr.(*RR_SOA).Ns = tok.T[0]
            rr.(*RR_SOA).Mbox = tok.T[1]
            rr.(*RR_SOA).Serial = uint32(tok.N[0])
            rr.(*RR_SOA).Refresh = uint32(tok.N[1])
            rr.(*RR_SOA).Retry = uint32(tok.N[2])
            rr.(*RR_SOA).Expire = uint32(tok.N[3])
            rr.(*RR_SOA).Minttl = uint32(tok.N[4])
        }
	goto st84
st84:
	p++
	if p == pe { goto _test_eof84 }
	fallthrough
case 84:
// line 1879 "zparse.go"
	switch data[p] {
		case 9: goto tr158
		case 32: goto tr158
		case 46: goto st84
		case 92: goto st84
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st84 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st84 }
	} else {
		goto st84
	}
	goto st0
tr17:
// line 83 "zparse.rl"
	{ mark = p }
	goto st85
st85:
	p++
	if p == pe { goto _test_eof85 }
	fallthrough
case 85:
// line 1903 "zparse.go"
	switch data[p] {
		case 72: goto st8
		case 78: goto st12
		case 83: goto st8
		case 104: goto st8
		case 110: goto st12
		case 115: goto st8
	}
	goto st0
tr19:
// line 83 "zparse.rl"
	{ mark = p }
	goto st86
st86:
	p++
	if p == pe { goto _test_eof86 }
	fallthrough
case 86:
// line 1922 "zparse.go"
	switch data[p] {
		case 83: goto st8
		case 115: goto st8
	}
	goto st0
tr20:
// line 83 "zparse.rl"
	{ mark = p }
	goto st87
st87:
	p++
	if p == pe { goto _test_eof87 }
	fallthrough
case 87:
// line 1937 "zparse.go"
	switch data[p] {
		case 78: goto st8
		case 110: goto st8
	}
	goto st0
tr22:
// line 83 "zparse.rl"
	{ mark = p }
	goto st88
st88:
	p++
	if p == pe { goto _test_eof88 }
	fallthrough
case 88:
// line 1952 "zparse.go"
	switch data[p] {
		case 79: goto st89
		case 83: goto st44
		case 111: goto st89
		case 115: goto st44
	}
	goto st0
st89:
	p++
	if p == pe { goto _test_eof89 }
	fallthrough
case 89:
	switch data[p] {
		case 78: goto st90
		case 110: goto st90
	}
	goto st0
st90:
	p++
	if p == pe { goto _test_eof90 }
	fallthrough
case 90:
	switch data[p] {
		case 69: goto st8
		case 101: goto st8
	}
	goto st0
tr4:
// line 83 "zparse.rl"
	{ mark = p }
// line 86 "zparse.rl"
	{ /* ... */ }
	goto st91
st91:
	p++
	if p == pe { goto _test_eof91 }
	fallthrough
case 91:
// line 1991 "zparse.go"
	switch data[p] {
		case 9: goto tr25
		case 32: goto tr25
		case 78: goto st92
		case 110: goto st92
	}
	goto st0
st92:
	p++
	if p == pe { goto _test_eof92 }
	fallthrough
case 92:
	switch data[p] {
		case 89: goto st93
		case 121: goto st93
	}
	goto st0
st93:
	p++
	if p == pe { goto _test_eof93 }
	fallthrough
case 93:
	switch data[p] {
		case 9: goto tr163
		case 32: goto tr163
	}
	goto st0
tr163:
// line 85 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st94
st94:
	p++
	if p == pe { goto _test_eof94 }
	fallthrough
case 94:
// line 2028 "zparse.go"
	switch data[p] {
		case 9: goto st94
		case 32: goto st94
		case 65: goto tr32
		case 67: goto tr33
		case 68: goto tr18
		case 77: goto tr21
		case 78: goto tr34
		case 82: goto tr23
		case 83: goto tr24
		case 97: goto tr32
		case 99: goto tr33
		case 100: goto tr18
		case 109: goto tr21
		case 110: goto tr34
		case 114: goto tr23
		case 115: goto tr24
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr165 }
	goto st0
tr165:
// line 83 "zparse.rl"
	{ mark = p }
	goto st95
st95:
	p++
	if p == pe { goto _test_eof95 }
	fallthrough
case 95:
// line 2058 "zparse.go"
	switch data[p] {
		case 9: goto tr166
		case 32: goto tr166
	}
	if 48 <= data[p] && data[p] <= 57 { goto st95 }
	goto st0
tr5:
// line 83 "zparse.rl"
	{ mark = p }
// line 86 "zparse.rl"
	{ /* ... */ }
	goto st96
st96:
	p++
	if p == pe { goto _test_eof96 }
	fallthrough
case 96:
// line 2076 "zparse.go"
	switch data[p] {
		case 72: goto st93
		case 78: goto st12
		case 83: goto st93
		case 104: goto st93
		case 110: goto st12
		case 115: goto st93
	}
	goto st0
tr7:
// line 83 "zparse.rl"
	{ mark = p }
// line 86 "zparse.rl"
	{ /* ... */ }
	goto st97
st97:
	p++
	if p == pe { goto _test_eof97 }
	fallthrough
case 97:
// line 2097 "zparse.go"
	switch data[p] {
		case 83: goto st93
		case 115: goto st93
	}
	goto st0
tr8:
// line 83 "zparse.rl"
	{ mark = p }
// line 86 "zparse.rl"
	{ /* ... */ }
	goto st98
st98:
	p++
	if p == pe { goto _test_eof98 }
	fallthrough
case 98:
// line 2114 "zparse.go"
	switch data[p] {
		case 78: goto st93
		case 110: goto st93
	}
	goto st0
tr10:
// line 83 "zparse.rl"
	{ mark = p }
// line 86 "zparse.rl"
	{ /* ... */ }
	goto st99
st99:
	p++
	if p == pe { goto _test_eof99 }
	fallthrough
case 99:
// line 2131 "zparse.go"
	switch data[p] {
		case 79: goto st100
		case 83: goto st44
		case 111: goto st100
		case 115: goto st44
	}
	goto st0
st100:
	p++
	if p == pe { goto _test_eof100 }
	fallthrough
case 100:
	switch data[p] {
		case 78: goto st101
		case 110: goto st101
	}
	goto st0
st101:
	p++
	if p == pe { goto _test_eof101 }
	fallthrough
case 101:
	switch data[p] {
		case 69: goto st93
		case 101: goto st93
	}
	goto st0
	}
	_test_eof2: cs = 2; goto _test_eof; 
	_test_eof3: cs = 3; goto _test_eof; 
	_test_eof4: cs = 4; goto _test_eof; 
	_test_eof5: cs = 5; goto _test_eof; 
	_test_eof6: cs = 6; goto _test_eof; 
	_test_eof102: cs = 102; goto _test_eof; 
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
	_test_eof103: cs = 103; goto _test_eof; 
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
	_test_eof104: cs = 104; goto _test_eof; 
	_test_eof30: cs = 30; goto _test_eof; 
	_test_eof31: cs = 31; goto _test_eof; 
	_test_eof32: cs = 32; goto _test_eof; 
	_test_eof33: cs = 33; goto _test_eof; 
	_test_eof34: cs = 34; goto _test_eof; 
	_test_eof35: cs = 35; goto _test_eof; 
	_test_eof36: cs = 36; goto _test_eof; 
	_test_eof37: cs = 37; goto _test_eof; 
	_test_eof105: cs = 105; goto _test_eof; 
	_test_eof38: cs = 38; goto _test_eof; 
	_test_eof39: cs = 39; goto _test_eof; 
	_test_eof40: cs = 40; goto _test_eof; 
	_test_eof41: cs = 41; goto _test_eof; 
	_test_eof42: cs = 42; goto _test_eof; 
	_test_eof106: cs = 106; goto _test_eof; 
	_test_eof43: cs = 43; goto _test_eof; 
	_test_eof44: cs = 44; goto _test_eof; 
	_test_eof45: cs = 45; goto _test_eof; 
	_test_eof107: cs = 107; goto _test_eof; 
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
	_test_eof108: cs = 108; goto _test_eof; 
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
	_test_eof109: cs = 109; goto _test_eof; 
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

	_test_eof: {}
	if p == eof {
	switch cs {
	case 109:
// line 88 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 16 "types.rl"
	{
            rr.(*RR_SOA).Hdr = *hdr
            rr.(*RR_SOA).Ns = tok.T[0]
            rr.(*RR_SOA).Mbox = tok.T[1]
            rr.(*RR_SOA).Serial = uint32(tok.N[0])
            rr.(*RR_SOA).Refresh = uint32(tok.N[1])
            rr.(*RR_SOA).Retry = uint32(tok.N[2])
            rr.(*RR_SOA).Expire = uint32(tok.N[3])
            rr.(*RR_SOA).Minttl = uint32(tok.N[4])
        }
	break
	case 102:
// line 89 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr.(*RR_A).Hdr = *hdr
            rr.(*RR_A).A = net.ParseIP(data[mark:p])
        }
	break
	case 107:
// line 89 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 8 "types.rl"
	{
            rr.(*RR_NS).Hdr = *hdr
            rr.(*RR_NS).Ns = tok.T[0]
        }
	break
	case 103:
// line 89 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 12 "types.rl"
	{
            rr.(*RR_CNAME).Hdr = *hdr
            rr.(*RR_CNAME).Cname = tok.T[0]
        }
	break
	case 106:
// line 89 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 26 "types.rl"
	{
            rr.(*RR_MX).Hdr = *hdr;
            rr.(*RR_MX).Pref = uint16(tok.N[0])
            rr.(*RR_MX).Mx = tok.T[0]
        }
	break
	case 105:
// line 89 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 31 "types.rl"
	{
            rr.(*RR_DS).Hdr = *hdr;
            rr.(*RR_DS).KeyTag = uint16(tok.N[0])
            rr.(*RR_DS).Algorithm = uint8(tok.N[1])
            rr.(*RR_DS).DigestType = uint8(tok.N[2])
            rr.(*RR_DS).Digest = tok.T[0]
        }
	break
	case 104:
// line 89 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 38 "types.rl"
	{
            rr.(*RR_DNSKEY).Hdr = *hdr;
            rr.(*RR_DNSKEY).Flags = uint16(tok.N[0])
            rr.(*RR_DNSKEY).Protocol = uint8(tok.N[1])
            rr.(*RR_DNSKEY).Algorithm = uint8(tok.N[2])
            rr.(*RR_DNSKEY).PublicKey = tok.T[0]
        }
	break
	case 108:
// line 89 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr.(*RR_RRSIG).Hdr = *hdr;
            rr.(*RR_RRSIG).TypeCovered = uint16(tok.N[0])
            rr.(*RR_RRSIG).Algorithm = uint8(tok.N[1])
            rr.(*RR_RRSIG).Labels = uint8(tok.N[2])
            rr.(*RR_RRSIG).OrigTtl = uint32(tok.N[3])
            rr.(*RR_RRSIG).Expiration = uint32(tok.N[4])
            rr.(*RR_RRSIG).Inception = uint32(tok.N[5])
            rr.(*RR_RRSIG).KeyTag = uint16(tok.N[6])
            rr.(*RR_RRSIG).SignerName = tok.T[0]
            rr.(*RR_RRSIG).Signature = tok.T[1]
        }
	break
// line 2365 "zparse.go"
	}
	}

	_out: {}
	}

// line 137 "zparse.rl"


        if cs < z_first_final {
                // No clue what I'm doing what so ever
                if p == pe {
                        //return nil, os.ErrorString("unexpected eof")
                        return nil, nil
                } else {
                        //return nil, os.ErrorString(fmt.Sprintf("error at position %d", p))
                        return nil, nil
                }
        }
        return rr, nil
}
