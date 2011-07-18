
// line 1 "zparse.rl"
package dns

// Parse RRs
// With the thankful help of gdnsd and the Go examples for Ragel 

import (
    "os"
    "io"
    "net"
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


// line 63 "zparse.go"
var z_start int = 1
var z_first_final int = 106
var z_error int = 0

var z_en_main int = 1


// line 62 "zparse.rl"


// SetString
// All the NewReader stuff is expensive...
// only works for short io.Readers as we put the whole thing
// in a string -- needs to be extended for large files (sliding window).
func Zparse(q io.Reader) (rr RR, err os.Error) {
        buf := make([]byte, _IOBUF) 
        n, err := q.Read(buf)
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
		case 46: goto st88
		case 92: goto st88
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st88 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st88 }
	} else {
		goto st88
	}
	goto st0
st0:
cs = 0;
	goto _out;
tr164:
// line 85 "zparse.rl"
	{ hdr.Name = data[mark:p] }
	goto st2
tr176:
// line 90 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr.(*RR_A).Hdr = *hdr
            rr.(*RR_A).A = net.ParseIP(tok.T[0])
        }
	goto st2
tr178:
// line 90 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 8 "types.rl"
	{
            rr.(*RR_AAAA).Hdr = *hdr
            rr.(*RR_AAAA).AAAA = net.ParseIP(tok.T[0])
        }
	goto st2
tr180:
// line 90 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 16 "types.rl"
	{
            rr.(*RR_CNAME).Hdr = *hdr
            rr.(*RR_CNAME).Cname = tok.T[0]
        }
	goto st2
tr182:
// line 90 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 42 "types.rl"
	{
            rr.(*RR_DNSKEY).Hdr = *hdr;
            rr.(*RR_DNSKEY).Flags = uint16(tok.N[0])
            rr.(*RR_DNSKEY).Protocol = uint8(tok.N[1])
            rr.(*RR_DNSKEY).Algorithm = uint8(tok.N[2])
            rr.(*RR_DNSKEY).PublicKey = tok.T[0]
        }
	goto st2
tr184:
// line 90 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            rr.(*RR_DS).Hdr = *hdr;
            rr.(*RR_DS).KeyTag = uint16(tok.N[0])
            rr.(*RR_DS).Algorithm = uint8(tok.N[1])
            rr.(*RR_DS).DigestType = uint8(tok.N[2])
            rr.(*RR_DS).Digest = tok.T[0]
        }
	goto st2
tr186:
// line 90 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 30 "types.rl"
	{
            rr.(*RR_MX).Hdr = *hdr;
            rr.(*RR_MX).Pref = uint16(tok.N[0])
            rr.(*RR_MX).Mx = tok.T[0]
        }
	goto st2
tr188:
// line 90 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 12 "types.rl"
	{
            rr.(*RR_NS).Hdr = *hdr
            rr.(*RR_NS).Ns = tok.T[0]
        }
	goto st2
tr190:
// line 90 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 49 "types.rl"
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
tr192:
// line 89 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 20 "types.rl"
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
// line 231 "zparse.go"
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
// line 84 "zparse.rl"
	{ mark = p }
// line 87 "zparse.rl"
	{ /* ... */ }
	goto st3
st3:
	p++
	if p == pe { goto _test_eof3 }
	fallthrough
case 3:
// line 267 "zparse.go"
	switch data[p] {
		case 9: goto tr13
		case 32: goto tr13
	}
	if 48 <= data[p] && data[p] <= 57 { goto st3 }
	goto st0
tr13:
// line 88 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st4
st4:
	p++
	if p == pe { goto _test_eof4 }
	fallthrough
case 4:
// line 283 "zparse.go"
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
// line 84 "zparse.rl"
	{ mark = p }
	goto st5
st5:
	p++
	if p == pe { goto _test_eof5 }
	fallthrough
case 5:
// line 316 "zparse.go"
	switch data[p] {
		case 9: goto tr25
		case 32: goto tr25
		case 65: goto st7
		case 78: goto st11
		case 97: goto st7
		case 110: goto st11
	}
	goto st0
tr25:
// line 93 "zparse.rl"
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
// line 343 "zparse.go"
	switch data[p] {
		case 9: goto st6
		case 32: goto st6
		case 43: goto tr29
		case 61: goto tr29
		case 92: goto tr29
	}
	if data[p] < 65 {
		if 46 <= data[p] && data[p] <= 57 { goto tr29 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr29 }
	} else {
		goto tr29
	}
	goto st0
tr29:
// line 84 "zparse.rl"
	{ mark = p }
	goto st106
st106:
	p++
	if p == pe { goto _test_eof106 }
	fallthrough
case 106:
// line 368 "zparse.go"
	switch data[p] {
		case 9: goto tr176
		case 32: goto tr176
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
st7:
	p++
	if p == pe { goto _test_eof7 }
	fallthrough
case 7:
	switch data[p] {
		case 65: goto st8
		case 97: goto st8
	}
	goto st0
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
		case 9: goto tr32
		case 32: goto tr32
	}
	goto st0
tr32:
// line 93 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    rr = mk()
                    hdr.Rrtype = i
                }
	goto st10
st10:
	p++
	if p == pe { goto _test_eof10 }
	fallthrough
case 10:
// line 431 "zparse.go"
	switch data[p] {
		case 9: goto st10
		case 32: goto st10
		case 43: goto tr34
		case 61: goto tr34
		case 92: goto tr34
	}
	if data[p] < 65 {
		if 46 <= data[p] && data[p] <= 57 { goto tr34 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr34 }
	} else {
		goto tr34
	}
	goto st0
tr34:
// line 84 "zparse.rl"
	{ mark = p }
	goto st107
st107:
	p++
	if p == pe { goto _test_eof107 }
	fallthrough
case 107:
// line 456 "zparse.go"
	switch data[p] {
		case 9: goto tr178
		case 32: goto tr178
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
st11:
	p++
	if p == pe { goto _test_eof11 }
	fallthrough
case 11:
	switch data[p] {
		case 89: goto st12
		case 121: goto st12
	}
	goto st0
st12:
	p++
	if p == pe { goto _test_eof12 }
	fallthrough
case 12:
	switch data[p] {
		case 9: goto tr36
		case 32: goto tr36
	}
	goto st0
tr172:
// line 88 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st13
tr36:
// line 86 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st13
st13:
	p++
	if p == pe { goto _test_eof13 }
	fallthrough
case 13:
// line 505 "zparse.go"
	switch data[p] {
		case 9: goto st13
		case 32: goto st13
		case 65: goto tr38
		case 67: goto tr39
		case 68: goto tr18
		case 77: goto tr21
		case 78: goto tr40
		case 82: goto tr23
		case 83: goto tr24
		case 97: goto tr38
		case 99: goto tr39
		case 100: goto tr18
		case 109: goto tr21
		case 110: goto tr40
		case 114: goto tr23
		case 115: goto tr24
	}
	goto st0
tr38:
// line 84 "zparse.rl"
	{ mark = p }
	goto st14
st14:
	p++
	if p == pe { goto _test_eof14 }
	fallthrough
case 14:
// line 534 "zparse.go"
	switch data[p] {
		case 9: goto tr25
		case 32: goto tr25
		case 65: goto st7
		case 97: goto st7
	}
	goto st0
tr39:
// line 84 "zparse.rl"
	{ mark = p }
	goto st15
st15:
	p++
	if p == pe { goto _test_eof15 }
	fallthrough
case 15:
// line 551 "zparse.go"
	switch data[p] {
		case 78: goto st16
		case 110: goto st16
	}
	goto st0
st16:
	p++
	if p == pe { goto _test_eof16 }
	fallthrough
case 16:
	switch data[p] {
		case 65: goto st17
		case 97: goto st17
	}
	goto st0
st17:
	p++
	if p == pe { goto _test_eof17 }
	fallthrough
case 17:
	switch data[p] {
		case 77: goto st18
		case 109: goto st18
	}
	goto st0
st18:
	p++
	if p == pe { goto _test_eof18 }
	fallthrough
case 18:
	switch data[p] {
		case 69: goto st19
		case 101: goto st19
	}
	goto st0
st19:
	p++
	if p == pe { goto _test_eof19 }
	fallthrough
case 19:
	switch data[p] {
		case 9: goto tr45
		case 32: goto tr45
	}
	goto st0
tr45:
// line 93 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    rr = mk()
                    hdr.Rrtype = i
                }
	goto st20
st20:
	p++
	if p == pe { goto _test_eof20 }
	fallthrough
case 20:
// line 614 "zparse.go"
	switch data[p] {
		case 9: goto st20
		case 32: goto st20
		case 43: goto tr47
		case 61: goto tr47
		case 92: goto tr47
	}
	if data[p] < 65 {
		if 46 <= data[p] && data[p] <= 57 { goto tr47 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr47 }
	} else {
		goto tr47
	}
	goto st0
tr47:
// line 84 "zparse.rl"
	{ mark = p }
	goto st108
st108:
	p++
	if p == pe { goto _test_eof108 }
	fallthrough
case 108:
// line 639 "zparse.go"
	switch data[p] {
		case 9: goto tr180
		case 32: goto tr180
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
tr6:
// line 84 "zparse.rl"
	{ mark = p }
// line 87 "zparse.rl"
	{ /* ... */ }
	goto st21
tr18:
// line 84 "zparse.rl"
	{ mark = p }
	goto st21
st21:
	p++
	if p == pe { goto _test_eof21 }
	fallthrough
case 21:
// line 670 "zparse.go"
	switch data[p] {
		case 78: goto st22
		case 83: goto st34
		case 110: goto st22
		case 115: goto st34
	}
	goto st0
st22:
	p++
	if p == pe { goto _test_eof22 }
	fallthrough
case 22:
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
	switch data[p] {
		case 75: goto st24
		case 107: goto st24
	}
	goto st0
st24:
	p++
	if p == pe { goto _test_eof24 }
	fallthrough
case 24:
	switch data[p] {
		case 69: goto st25
		case 101: goto st25
	}
	goto st0
st25:
	p++
	if p == pe { goto _test_eof25 }
	fallthrough
case 25:
	switch data[p] {
		case 89: goto st26
		case 121: goto st26
	}
	goto st0
st26:
	p++
	if p == pe { goto _test_eof26 }
	fallthrough
case 26:
	switch data[p] {
		case 9: goto tr54
		case 32: goto tr54
	}
	goto st0
tr54:
// line 93 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    rr = mk()
                    hdr.Rrtype = i
                }
	goto st27
st27:
	p++
	if p == pe { goto _test_eof27 }
	fallthrough
case 27:
// line 745 "zparse.go"
	switch data[p] {
		case 9: goto st27
		case 32: goto st27
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr56 }
	goto st0
tr56:
// line 84 "zparse.rl"
	{ mark = p }
	goto st28
st28:
	p++
	if p == pe { goto _test_eof28 }
	fallthrough
case 28:
// line 761 "zparse.go"
	switch data[p] {
		case 9: goto tr57
		case 32: goto tr57
	}
	if 48 <= data[p] && data[p] <= 57 { goto st28 }
	goto st0
tr57:
// line 89 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st29
st29:
	p++
	if p == pe { goto _test_eof29 }
	fallthrough
case 29:
// line 777 "zparse.go"
	switch data[p] {
		case 9: goto st29
		case 32: goto st29
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr60 }
	goto st0
tr60:
// line 84 "zparse.rl"
	{ mark = p }
	goto st30
st30:
	p++
	if p == pe { goto _test_eof30 }
	fallthrough
case 30:
// line 793 "zparse.go"
	switch data[p] {
		case 9: goto tr61
		case 32: goto tr61
	}
	if 48 <= data[p] && data[p] <= 57 { goto st30 }
	goto st0
tr61:
// line 89 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st31
st31:
	p++
	if p == pe { goto _test_eof31 }
	fallthrough
case 31:
// line 809 "zparse.go"
	switch data[p] {
		case 9: goto st31
		case 32: goto st31
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr64 }
	goto st0
tr64:
// line 84 "zparse.rl"
	{ mark = p }
	goto st32
st32:
	p++
	if p == pe { goto _test_eof32 }
	fallthrough
case 32:
// line 825 "zparse.go"
	switch data[p] {
		case 9: goto tr65
		case 32: goto tr65
	}
	if 48 <= data[p] && data[p] <= 57 { goto st32 }
	goto st0
tr65:
// line 89 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st33
st33:
	p++
	if p == pe { goto _test_eof33 }
	fallthrough
case 33:
// line 841 "zparse.go"
	switch data[p] {
		case 9: goto st33
		case 32: goto st33
		case 43: goto tr68
		case 61: goto tr68
		case 92: goto tr68
	}
	if data[p] < 65 {
		if 46 <= data[p] && data[p] <= 57 { goto tr68 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr68 }
	} else {
		goto tr68
	}
	goto st0
tr68:
// line 84 "zparse.rl"
	{ mark = p }
	goto st109
st109:
	p++
	if p == pe { goto _test_eof109 }
	fallthrough
case 109:
// line 866 "zparse.go"
	switch data[p] {
		case 9: goto tr182
		case 32: goto tr182
		case 43: goto st109
		case 61: goto st109
		case 92: goto st109
	}
	if data[p] < 65 {
		if 46 <= data[p] && data[p] <= 57 { goto st109 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st109 }
	} else {
		goto st109
	}
	goto st0
st34:
	p++
	if p == pe { goto _test_eof34 }
	fallthrough
case 34:
	switch data[p] {
		case 9: goto tr69
		case 32: goto tr69
	}
	goto st0
tr69:
// line 93 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    rr = mk()
                    hdr.Rrtype = i
                }
	goto st35
st35:
	p++
	if p == pe { goto _test_eof35 }
	fallthrough
case 35:
// line 909 "zparse.go"
	switch data[p] {
		case 9: goto st35
		case 32: goto st35
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr71 }
	goto st0
tr71:
// line 84 "zparse.rl"
	{ mark = p }
	goto st36
st36:
	p++
	if p == pe { goto _test_eof36 }
	fallthrough
case 36:
// line 925 "zparse.go"
	switch data[p] {
		case 9: goto tr72
		case 32: goto tr72
	}
	if 48 <= data[p] && data[p] <= 57 { goto st36 }
	goto st0
tr72:
// line 89 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st37
st37:
	p++
	if p == pe { goto _test_eof37 }
	fallthrough
case 37:
// line 941 "zparse.go"
	switch data[p] {
		case 9: goto st37
		case 32: goto st37
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr75 }
	goto st0
tr75:
// line 84 "zparse.rl"
	{ mark = p }
	goto st38
st38:
	p++
	if p == pe { goto _test_eof38 }
	fallthrough
case 38:
// line 957 "zparse.go"
	switch data[p] {
		case 9: goto tr76
		case 32: goto tr76
	}
	if 48 <= data[p] && data[p] <= 57 { goto st38 }
	goto st0
tr76:
// line 89 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st39
st39:
	p++
	if p == pe { goto _test_eof39 }
	fallthrough
case 39:
// line 973 "zparse.go"
	switch data[p] {
		case 9: goto st39
		case 32: goto st39
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr79 }
	goto st0
tr79:
// line 84 "zparse.rl"
	{ mark = p }
	goto st40
st40:
	p++
	if p == pe { goto _test_eof40 }
	fallthrough
case 40:
// line 989 "zparse.go"
	switch data[p] {
		case 9: goto tr80
		case 32: goto tr80
	}
	if 48 <= data[p] && data[p] <= 57 { goto st40 }
	goto st0
tr80:
// line 89 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st41
st41:
	p++
	if p == pe { goto _test_eof41 }
	fallthrough
case 41:
// line 1005 "zparse.go"
	switch data[p] {
		case 9: goto st41
		case 32: goto st41
		case 43: goto tr83
		case 61: goto tr83
		case 92: goto tr83
	}
	if data[p] < 65 {
		if 46 <= data[p] && data[p] <= 57 { goto tr83 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr83 }
	} else {
		goto tr83
	}
	goto st0
tr83:
// line 84 "zparse.rl"
	{ mark = p }
	goto st110
st110:
	p++
	if p == pe { goto _test_eof110 }
	fallthrough
case 110:
// line 1030 "zparse.go"
	switch data[p] {
		case 9: goto tr184
		case 32: goto tr184
		case 43: goto st110
		case 61: goto st110
		case 92: goto st110
	}
	if data[p] < 65 {
		if 46 <= data[p] && data[p] <= 57 { goto st110 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st110 }
	} else {
		goto st110
	}
	goto st0
tr9:
// line 84 "zparse.rl"
	{ mark = p }
// line 87 "zparse.rl"
	{ /* ... */ }
	goto st42
tr21:
// line 84 "zparse.rl"
	{ mark = p }
	goto st42
st42:
	p++
	if p == pe { goto _test_eof42 }
	fallthrough
case 42:
// line 1061 "zparse.go"
	switch data[p] {
		case 88: goto st43
		case 120: goto st43
	}
	goto st0
st43:
	p++
	if p == pe { goto _test_eof43 }
	fallthrough
case 43:
	switch data[p] {
		case 9: goto tr85
		case 32: goto tr85
	}
	goto st0
tr85:
// line 93 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    rr = mk()
                    hdr.Rrtype = i
                }
	goto st44
st44:
	p++
	if p == pe { goto _test_eof44 }
	fallthrough
case 44:
// line 1094 "zparse.go"
	switch data[p] {
		case 9: goto st44
		case 32: goto st44
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr87 }
	goto st0
tr87:
// line 84 "zparse.rl"
	{ mark = p }
	goto st45
st45:
	p++
	if p == pe { goto _test_eof45 }
	fallthrough
case 45:
// line 1110 "zparse.go"
	switch data[p] {
		case 9: goto tr88
		case 32: goto tr88
	}
	if 48 <= data[p] && data[p] <= 57 { goto st45 }
	goto st0
tr88:
// line 89 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st46
st46:
	p++
	if p == pe { goto _test_eof46 }
	fallthrough
case 46:
// line 1126 "zparse.go"
	switch data[p] {
		case 9: goto st46
		case 32: goto st46
		case 43: goto tr91
		case 61: goto tr91
		case 92: goto tr91
	}
	if data[p] < 65 {
		if 46 <= data[p] && data[p] <= 57 { goto tr91 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr91 }
	} else {
		goto tr91
	}
	goto st0
tr91:
// line 84 "zparse.rl"
	{ mark = p }
	goto st111
st111:
	p++
	if p == pe { goto _test_eof111 }
	fallthrough
case 111:
// line 1151 "zparse.go"
	switch data[p] {
		case 9: goto tr186
		case 32: goto tr186
		case 43: goto st111
		case 61: goto st111
		case 92: goto st111
	}
	if data[p] < 65 {
		if 46 <= data[p] && data[p] <= 57 { goto st111 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st111 }
	} else {
		goto st111
	}
	goto st0
tr40:
// line 84 "zparse.rl"
	{ mark = p }
	goto st47
st47:
	p++
	if p == pe { goto _test_eof47 }
	fallthrough
case 47:
// line 1176 "zparse.go"
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
		case 9: goto tr93
		case 32: goto tr93
	}
	goto st0
tr93:
// line 93 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    rr = mk()
                    hdr.Rrtype = i
                }
	goto st49
st49:
	p++
	if p == pe { goto _test_eof49 }
	fallthrough
case 49:
// line 1209 "zparse.go"
	switch data[p] {
		case 9: goto st49
		case 32: goto st49
		case 43: goto tr95
		case 61: goto tr95
		case 92: goto tr95
	}
	if data[p] < 65 {
		if 46 <= data[p] && data[p] <= 57 { goto tr95 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr95 }
	} else {
		goto tr95
	}
	goto st0
tr95:
// line 84 "zparse.rl"
	{ mark = p }
	goto st112
st112:
	p++
	if p == pe { goto _test_eof112 }
	fallthrough
case 112:
// line 1234 "zparse.go"
	switch data[p] {
		case 9: goto tr188
		case 32: goto tr188
		case 43: goto st112
		case 61: goto st112
		case 92: goto st112
	}
	if data[p] < 65 {
		if 46 <= data[p] && data[p] <= 57 { goto st112 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st112 }
	} else {
		goto st112
	}
	goto st0
tr11:
// line 84 "zparse.rl"
	{ mark = p }
// line 87 "zparse.rl"
	{ /* ... */ }
	goto st50
tr23:
// line 84 "zparse.rl"
	{ mark = p }
	goto st50
st50:
	p++
	if p == pe { goto _test_eof50 }
	fallthrough
case 50:
// line 1265 "zparse.go"
	switch data[p] {
		case 82: goto st51
		case 114: goto st51
	}
	goto st0
st51:
	p++
	if p == pe { goto _test_eof51 }
	fallthrough
case 51:
	switch data[p] {
		case 83: goto st52
		case 115: goto st52
	}
	goto st0
st52:
	p++
	if p == pe { goto _test_eof52 }
	fallthrough
case 52:
	switch data[p] {
		case 73: goto st53
		case 105: goto st53
	}
	goto st0
st53:
	p++
	if p == pe { goto _test_eof53 }
	fallthrough
case 53:
	switch data[p] {
		case 71: goto st54
		case 103: goto st54
	}
	goto st0
st54:
	p++
	if p == pe { goto _test_eof54 }
	fallthrough
case 54:
	switch data[p] {
		case 9: goto tr100
		case 32: goto tr100
	}
	goto st0
tr100:
// line 93 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    rr = mk()
                    hdr.Rrtype = i
                }
	goto st55
st55:
	p++
	if p == pe { goto _test_eof55 }
	fallthrough
case 55:
// line 1328 "zparse.go"
	switch data[p] {
		case 9: goto st55
		case 32: goto st55
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr102 }
	goto st0
tr102:
// line 84 "zparse.rl"
	{ mark = p }
	goto st56
st56:
	p++
	if p == pe { goto _test_eof56 }
	fallthrough
case 56:
// line 1344 "zparse.go"
	switch data[p] {
		case 9: goto tr103
		case 32: goto tr103
	}
	if 48 <= data[p] && data[p] <= 57 { goto st56 }
	goto st0
tr103:
// line 89 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st57
st57:
	p++
	if p == pe { goto _test_eof57 }
	fallthrough
case 57:
// line 1360 "zparse.go"
	switch data[p] {
		case 9: goto st57
		case 32: goto st57
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr106 }
	goto st0
tr106:
// line 84 "zparse.rl"
	{ mark = p }
	goto st58
st58:
	p++
	if p == pe { goto _test_eof58 }
	fallthrough
case 58:
// line 1376 "zparse.go"
	switch data[p] {
		case 9: goto tr107
		case 32: goto tr107
	}
	if 48 <= data[p] && data[p] <= 57 { goto st58 }
	goto st0
tr107:
// line 89 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st59
st59:
	p++
	if p == pe { goto _test_eof59 }
	fallthrough
case 59:
// line 1392 "zparse.go"
	switch data[p] {
		case 9: goto st59
		case 32: goto st59
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr110 }
	goto st0
tr110:
// line 84 "zparse.rl"
	{ mark = p }
	goto st60
st60:
	p++
	if p == pe { goto _test_eof60 }
	fallthrough
case 60:
// line 1408 "zparse.go"
	switch data[p] {
		case 9: goto tr111
		case 32: goto tr111
	}
	if 48 <= data[p] && data[p] <= 57 { goto st60 }
	goto st0
tr111:
// line 89 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st61
st61:
	p++
	if p == pe { goto _test_eof61 }
	fallthrough
case 61:
// line 1424 "zparse.go"
	switch data[p] {
		case 9: goto st61
		case 32: goto st61
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr114 }
	goto st0
tr114:
// line 84 "zparse.rl"
	{ mark = p }
	goto st62
st62:
	p++
	if p == pe { goto _test_eof62 }
	fallthrough
case 62:
// line 1440 "zparse.go"
	switch data[p] {
		case 9: goto tr115
		case 32: goto tr115
	}
	if 48 <= data[p] && data[p] <= 57 { goto st62 }
	goto st0
tr115:
// line 89 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st63
st63:
	p++
	if p == pe { goto _test_eof63 }
	fallthrough
case 63:
// line 1456 "zparse.go"
	switch data[p] {
		case 9: goto st63
		case 32: goto st63
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr118 }
	goto st0
tr118:
// line 84 "zparse.rl"
	{ mark = p }
	goto st64
st64:
	p++
	if p == pe { goto _test_eof64 }
	fallthrough
case 64:
// line 1472 "zparse.go"
	switch data[p] {
		case 9: goto tr119
		case 32: goto tr119
	}
	if 48 <= data[p] && data[p] <= 57 { goto st64 }
	goto st0
tr119:
// line 89 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st65
st65:
	p++
	if p == pe { goto _test_eof65 }
	fallthrough
case 65:
// line 1488 "zparse.go"
	switch data[p] {
		case 9: goto st65
		case 32: goto st65
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr122 }
	goto st0
tr122:
// line 84 "zparse.rl"
	{ mark = p }
	goto st66
st66:
	p++
	if p == pe { goto _test_eof66 }
	fallthrough
case 66:
// line 1504 "zparse.go"
	switch data[p] {
		case 9: goto tr123
		case 32: goto tr123
	}
	if 48 <= data[p] && data[p] <= 57 { goto st66 }
	goto st0
tr123:
// line 89 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st67
st67:
	p++
	if p == pe { goto _test_eof67 }
	fallthrough
case 67:
// line 1520 "zparse.go"
	switch data[p] {
		case 9: goto st67
		case 32: goto st67
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr126 }
	goto st0
tr126:
// line 84 "zparse.rl"
	{ mark = p }
	goto st68
st68:
	p++
	if p == pe { goto _test_eof68 }
	fallthrough
case 68:
// line 1536 "zparse.go"
	switch data[p] {
		case 9: goto tr127
		case 32: goto tr127
	}
	if 48 <= data[p] && data[p] <= 57 { goto st68 }
	goto st0
tr127:
// line 89 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st69
st69:
	p++
	if p == pe { goto _test_eof69 }
	fallthrough
case 69:
// line 1552 "zparse.go"
	switch data[p] {
		case 9: goto st69
		case 32: goto st69
		case 43: goto tr130
		case 61: goto tr130
		case 92: goto tr130
	}
	if data[p] < 65 {
		if 46 <= data[p] && data[p] <= 57 { goto tr130 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr130 }
	} else {
		goto tr130
	}
	goto st0
tr130:
// line 84 "zparse.rl"
	{ mark = p }
	goto st70
st70:
	p++
	if p == pe { goto _test_eof70 }
	fallthrough
case 70:
// line 1577 "zparse.go"
	switch data[p] {
		case 9: goto tr131
		case 32: goto tr131
		case 43: goto st70
		case 61: goto st70
		case 92: goto st70
	}
	if data[p] < 65 {
		if 46 <= data[p] && data[p] <= 57 { goto st70 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st70 }
	} else {
		goto st70
	}
	goto st0
tr131:
// line 90 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
	goto st71
st71:
	p++
	if p == pe { goto _test_eof71 }
	fallthrough
case 71:
// line 1602 "zparse.go"
	switch data[p] {
		case 9: goto st71
		case 32: goto st71
		case 43: goto tr134
		case 61: goto tr134
		case 92: goto tr134
	}
	if data[p] < 65 {
		if 46 <= data[p] && data[p] <= 57 { goto tr134 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr134 }
	} else {
		goto tr134
	}
	goto st0
tr134:
// line 84 "zparse.rl"
	{ mark = p }
	goto st113
st113:
	p++
	if p == pe { goto _test_eof113 }
	fallthrough
case 113:
// line 1627 "zparse.go"
	switch data[p] {
		case 9: goto tr190
		case 32: goto tr190
		case 43: goto st113
		case 61: goto st113
		case 92: goto st113
	}
	if data[p] < 65 {
		if 46 <= data[p] && data[p] <= 57 { goto st113 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st113 }
	} else {
		goto st113
	}
	goto st0
tr12:
// line 84 "zparse.rl"
	{ mark = p }
// line 87 "zparse.rl"
	{ /* ... */ }
	goto st72
tr24:
// line 84 "zparse.rl"
	{ mark = p }
	goto st72
st72:
	p++
	if p == pe { goto _test_eof72 }
	fallthrough
case 72:
// line 1658 "zparse.go"
	switch data[p] {
		case 79: goto st73
		case 111: goto st73
	}
	goto st0
st73:
	p++
	if p == pe { goto _test_eof73 }
	fallthrough
case 73:
	switch data[p] {
		case 65: goto st74
		case 97: goto st74
	}
	goto st0
st74:
	p++
	if p == pe { goto _test_eof74 }
	fallthrough
case 74:
	switch data[p] {
		case 9: goto tr137
		case 32: goto tr137
	}
	goto st0
tr137:
// line 93 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    rr = mk()
                    hdr.Rrtype = i
                }
	goto st75
st75:
	p++
	if p == pe { goto _test_eof75 }
	fallthrough
case 75:
// line 1701 "zparse.go"
	switch data[p] {
		case 9: goto st75
		case 32: goto st75
		case 43: goto tr139
		case 61: goto tr139
		case 92: goto tr139
	}
	if data[p] < 65 {
		if 46 <= data[p] && data[p] <= 57 { goto tr139 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr139 }
	} else {
		goto tr139
	}
	goto st0
tr139:
// line 84 "zparse.rl"
	{ mark = p }
	goto st76
st76:
	p++
	if p == pe { goto _test_eof76 }
	fallthrough
case 76:
// line 1726 "zparse.go"
	switch data[p] {
		case 9: goto tr140
		case 32: goto tr140
		case 43: goto st76
		case 61: goto st76
		case 92: goto st76
	}
	if data[p] < 65 {
		if 46 <= data[p] && data[p] <= 57 { goto st76 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st76 }
	} else {
		goto st76
	}
	goto st0
tr140:
// line 90 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
	goto st77
st77:
	p++
	if p == pe { goto _test_eof77 }
	fallthrough
case 77:
// line 1751 "zparse.go"
	switch data[p] {
		case 9: goto st77
		case 32: goto st77
		case 43: goto tr143
		case 61: goto tr143
		case 92: goto tr143
	}
	if data[p] < 65 {
		if 46 <= data[p] && data[p] <= 57 { goto tr143 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr143 }
	} else {
		goto tr143
	}
	goto st0
tr143:
// line 84 "zparse.rl"
	{ mark = p }
	goto st78
st78:
	p++
	if p == pe { goto _test_eof78 }
	fallthrough
case 78:
// line 1776 "zparse.go"
	switch data[p] {
		case 9: goto tr144
		case 32: goto tr144
		case 43: goto st78
		case 61: goto st78
		case 92: goto st78
	}
	if data[p] < 65 {
		if 46 <= data[p] && data[p] <= 57 { goto st78 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st78 }
	} else {
		goto st78
	}
	goto st0
tr144:
// line 90 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
	goto st79
st79:
	p++
	if p == pe { goto _test_eof79 }
	fallthrough
case 79:
// line 1801 "zparse.go"
	switch data[p] {
		case 9: goto st79
		case 32: goto st79
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr147 }
	goto st0
tr147:
// line 84 "zparse.rl"
	{ mark = p }
	goto st80
st80:
	p++
	if p == pe { goto _test_eof80 }
	fallthrough
case 80:
// line 1817 "zparse.go"
	switch data[p] {
		case 9: goto tr148
		case 32: goto tr148
	}
	if 48 <= data[p] && data[p] <= 57 { goto st80 }
	goto st0
tr148:
// line 89 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st81
st81:
	p++
	if p == pe { goto _test_eof81 }
	fallthrough
case 81:
// line 1833 "zparse.go"
	switch data[p] {
		case 9: goto st81
		case 32: goto st81
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr151 }
	goto st0
tr151:
// line 84 "zparse.rl"
	{ mark = p }
	goto st82
st82:
	p++
	if p == pe { goto _test_eof82 }
	fallthrough
case 82:
// line 1849 "zparse.go"
	switch data[p] {
		case 9: goto tr152
		case 32: goto tr152
	}
	if 48 <= data[p] && data[p] <= 57 { goto st82 }
	goto st0
tr152:
// line 89 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st83
st83:
	p++
	if p == pe { goto _test_eof83 }
	fallthrough
case 83:
// line 1865 "zparse.go"
	switch data[p] {
		case 9: goto st83
		case 32: goto st83
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr155 }
	goto st0
tr155:
// line 84 "zparse.rl"
	{ mark = p }
	goto st84
st84:
	p++
	if p == pe { goto _test_eof84 }
	fallthrough
case 84:
// line 1881 "zparse.go"
	switch data[p] {
		case 9: goto tr156
		case 32: goto tr156
	}
	if 48 <= data[p] && data[p] <= 57 { goto st84 }
	goto st0
tr156:
// line 89 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st85
st85:
	p++
	if p == pe { goto _test_eof85 }
	fallthrough
case 85:
// line 1897 "zparse.go"
	switch data[p] {
		case 9: goto st85
		case 32: goto st85
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr159 }
	goto st0
tr159:
// line 84 "zparse.rl"
	{ mark = p }
	goto st86
st86:
	p++
	if p == pe { goto _test_eof86 }
	fallthrough
case 86:
// line 1913 "zparse.go"
	switch data[p] {
		case 9: goto tr160
		case 32: goto tr160
	}
	if 48 <= data[p] && data[p] <= 57 { goto st86 }
	goto st0
tr160:
// line 89 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st87
st87:
	p++
	if p == pe { goto _test_eof87 }
	fallthrough
case 87:
// line 1929 "zparse.go"
	switch data[p] {
		case 9: goto st87
		case 32: goto st87
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr163 }
	goto st0
tr163:
// line 84 "zparse.rl"
	{ mark = p }
	goto st114
st114:
	p++
	if p == pe { goto _test_eof114 }
	fallthrough
case 114:
// line 1945 "zparse.go"
	switch data[p] {
		case 9: goto tr192
		case 32: goto tr192
		case 46: goto tr193
		case 92: goto tr193
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st114 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr193 }
	} else {
		goto tr193
	}
	goto st0
tr193:
// line 89 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 20 "types.rl"
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
	goto st88
st88:
	p++
	if p == pe { goto _test_eof88 }
	fallthrough
case 88:
// line 1980 "zparse.go"
	switch data[p] {
		case 9: goto tr164
		case 32: goto tr164
		case 46: goto st88
		case 92: goto st88
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st88 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st88 }
	} else {
		goto st88
	}
	goto st0
tr17:
// line 84 "zparse.rl"
	{ mark = p }
	goto st89
st89:
	p++
	if p == pe { goto _test_eof89 }
	fallthrough
case 89:
// line 2004 "zparse.go"
	switch data[p] {
		case 72: goto st12
		case 78: goto st16
		case 83: goto st12
		case 104: goto st12
		case 110: goto st16
		case 115: goto st12
	}
	goto st0
tr19:
// line 84 "zparse.rl"
	{ mark = p }
	goto st90
st90:
	p++
	if p == pe { goto _test_eof90 }
	fallthrough
case 90:
// line 2023 "zparse.go"
	switch data[p] {
		case 83: goto st12
		case 115: goto st12
	}
	goto st0
tr20:
// line 84 "zparse.rl"
	{ mark = p }
	goto st91
st91:
	p++
	if p == pe { goto _test_eof91 }
	fallthrough
case 91:
// line 2038 "zparse.go"
	switch data[p] {
		case 78: goto st12
		case 110: goto st12
	}
	goto st0
tr22:
// line 84 "zparse.rl"
	{ mark = p }
	goto st92
st92:
	p++
	if p == pe { goto _test_eof92 }
	fallthrough
case 92:
// line 2053 "zparse.go"
	switch data[p] {
		case 79: goto st93
		case 83: goto st48
		case 111: goto st93
		case 115: goto st48
	}
	goto st0
st93:
	p++
	if p == pe { goto _test_eof93 }
	fallthrough
case 93:
	switch data[p] {
		case 78: goto st94
		case 110: goto st94
	}
	goto st0
st94:
	p++
	if p == pe { goto _test_eof94 }
	fallthrough
case 94:
	switch data[p] {
		case 69: goto st12
		case 101: goto st12
	}
	goto st0
tr4:
// line 84 "zparse.rl"
	{ mark = p }
// line 87 "zparse.rl"
	{ /* ... */ }
	goto st95
st95:
	p++
	if p == pe { goto _test_eof95 }
	fallthrough
case 95:
// line 2092 "zparse.go"
	switch data[p] {
		case 9: goto tr25
		case 32: goto tr25
		case 65: goto st7
		case 78: goto st96
		case 97: goto st7
		case 110: goto st96
	}
	goto st0
st96:
	p++
	if p == pe { goto _test_eof96 }
	fallthrough
case 96:
	switch data[p] {
		case 89: goto st97
		case 121: goto st97
	}
	goto st0
st97:
	p++
	if p == pe { goto _test_eof97 }
	fallthrough
case 97:
	switch data[p] {
		case 9: goto tr169
		case 32: goto tr169
	}
	goto st0
tr169:
// line 86 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st98
st98:
	p++
	if p == pe { goto _test_eof98 }
	fallthrough
case 98:
// line 2131 "zparse.go"
	switch data[p] {
		case 9: goto st98
		case 32: goto st98
		case 65: goto tr38
		case 67: goto tr39
		case 68: goto tr18
		case 77: goto tr21
		case 78: goto tr40
		case 82: goto tr23
		case 83: goto tr24
		case 97: goto tr38
		case 99: goto tr39
		case 100: goto tr18
		case 109: goto tr21
		case 110: goto tr40
		case 114: goto tr23
		case 115: goto tr24
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr171 }
	goto st0
tr171:
// line 84 "zparse.rl"
	{ mark = p }
	goto st99
st99:
	p++
	if p == pe { goto _test_eof99 }
	fallthrough
case 99:
// line 2161 "zparse.go"
	switch data[p] {
		case 9: goto tr172
		case 32: goto tr172
	}
	if 48 <= data[p] && data[p] <= 57 { goto st99 }
	goto st0
tr5:
// line 84 "zparse.rl"
	{ mark = p }
// line 87 "zparse.rl"
	{ /* ... */ }
	goto st100
st100:
	p++
	if p == pe { goto _test_eof100 }
	fallthrough
case 100:
// line 2179 "zparse.go"
	switch data[p] {
		case 72: goto st97
		case 78: goto st16
		case 83: goto st97
		case 104: goto st97
		case 110: goto st16
		case 115: goto st97
	}
	goto st0
tr7:
// line 84 "zparse.rl"
	{ mark = p }
// line 87 "zparse.rl"
	{ /* ... */ }
	goto st101
st101:
	p++
	if p == pe { goto _test_eof101 }
	fallthrough
case 101:
// line 2200 "zparse.go"
	switch data[p] {
		case 83: goto st97
		case 115: goto st97
	}
	goto st0
tr8:
// line 84 "zparse.rl"
	{ mark = p }
// line 87 "zparse.rl"
	{ /* ... */ }
	goto st102
st102:
	p++
	if p == pe { goto _test_eof102 }
	fallthrough
case 102:
// line 2217 "zparse.go"
	switch data[p] {
		case 78: goto st97
		case 110: goto st97
	}
	goto st0
tr10:
// line 84 "zparse.rl"
	{ mark = p }
// line 87 "zparse.rl"
	{ /* ... */ }
	goto st103
st103:
	p++
	if p == pe { goto _test_eof103 }
	fallthrough
case 103:
// line 2234 "zparse.go"
	switch data[p] {
		case 79: goto st104
		case 83: goto st48
		case 111: goto st104
		case 115: goto st48
	}
	goto st0
st104:
	p++
	if p == pe { goto _test_eof104 }
	fallthrough
case 104:
	switch data[p] {
		case 78: goto st105
		case 110: goto st105
	}
	goto st0
st105:
	p++
	if p == pe { goto _test_eof105 }
	fallthrough
case 105:
	switch data[p] {
		case 69: goto st97
		case 101: goto st97
	}
	goto st0
	}
	_test_eof2: cs = 2; goto _test_eof; 
	_test_eof3: cs = 3; goto _test_eof; 
	_test_eof4: cs = 4; goto _test_eof; 
	_test_eof5: cs = 5; goto _test_eof; 
	_test_eof6: cs = 6; goto _test_eof; 
	_test_eof106: cs = 106; goto _test_eof; 
	_test_eof7: cs = 7; goto _test_eof; 
	_test_eof8: cs = 8; goto _test_eof; 
	_test_eof9: cs = 9; goto _test_eof; 
	_test_eof10: cs = 10; goto _test_eof; 
	_test_eof107: cs = 107; goto _test_eof; 
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
	_test_eof108: cs = 108; goto _test_eof; 
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
	_test_eof109: cs = 109; goto _test_eof; 
	_test_eof34: cs = 34; goto _test_eof; 
	_test_eof35: cs = 35; goto _test_eof; 
	_test_eof36: cs = 36; goto _test_eof; 
	_test_eof37: cs = 37; goto _test_eof; 
	_test_eof38: cs = 38; goto _test_eof; 
	_test_eof39: cs = 39; goto _test_eof; 
	_test_eof40: cs = 40; goto _test_eof; 
	_test_eof41: cs = 41; goto _test_eof; 
	_test_eof110: cs = 110; goto _test_eof; 
	_test_eof42: cs = 42; goto _test_eof; 
	_test_eof43: cs = 43; goto _test_eof; 
	_test_eof44: cs = 44; goto _test_eof; 
	_test_eof45: cs = 45; goto _test_eof; 
	_test_eof46: cs = 46; goto _test_eof; 
	_test_eof111: cs = 111; goto _test_eof; 
	_test_eof47: cs = 47; goto _test_eof; 
	_test_eof48: cs = 48; goto _test_eof; 
	_test_eof49: cs = 49; goto _test_eof; 
	_test_eof112: cs = 112; goto _test_eof; 
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
	_test_eof113: cs = 113; goto _test_eof; 
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
	_test_eof114: cs = 114; goto _test_eof; 
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

	_test_eof: {}
	if p == eof {
	switch cs {
	case 114:
// line 89 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 20 "types.rl"
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
	case 106:
// line 90 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr.(*RR_A).Hdr = *hdr
            rr.(*RR_A).A = net.ParseIP(tok.T[0])
        }
	break
	case 107:
// line 90 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 8 "types.rl"
	{
            rr.(*RR_AAAA).Hdr = *hdr
            rr.(*RR_AAAA).AAAA = net.ParseIP(tok.T[0])
        }
	break
	case 112:
// line 90 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 12 "types.rl"
	{
            rr.(*RR_NS).Hdr = *hdr
            rr.(*RR_NS).Ns = tok.T[0]
        }
	break
	case 108:
// line 90 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 16 "types.rl"
	{
            rr.(*RR_CNAME).Hdr = *hdr
            rr.(*RR_CNAME).Cname = tok.T[0]
        }
	break
	case 111:
// line 90 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 30 "types.rl"
	{
            rr.(*RR_MX).Hdr = *hdr;
            rr.(*RR_MX).Pref = uint16(tok.N[0])
            rr.(*RR_MX).Mx = tok.T[0]
        }
	break
	case 110:
// line 90 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            rr.(*RR_DS).Hdr = *hdr;
            rr.(*RR_DS).KeyTag = uint16(tok.N[0])
            rr.(*RR_DS).Algorithm = uint8(tok.N[1])
            rr.(*RR_DS).DigestType = uint8(tok.N[2])
            rr.(*RR_DS).Digest = tok.T[0]
        }
	break
	case 109:
// line 90 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 42 "types.rl"
	{
            rr.(*RR_DNSKEY).Hdr = *hdr;
            rr.(*RR_DNSKEY).Flags = uint16(tok.N[0])
            rr.(*RR_DNSKEY).Protocol = uint8(tok.N[1])
            rr.(*RR_DNSKEY).Algorithm = uint8(tok.N[2])
            rr.(*RR_DNSKEY).PublicKey = tok.T[0]
        }
	break
	case 113:
// line 90 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 49 "types.rl"
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
// line 2482 "zparse.go"
	}
	}

	_out: {}
	}

// line 140 "zparse.rl"


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
