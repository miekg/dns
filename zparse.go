
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
func Zparse(q io.Reader) (z *Zone, err os.Error) {
        buf := make([]byte, _IOBUF) 
        n, err := q.Read(buf)
        if err != nil {
            return nil, err
        }
        buf = buf[:n]
        z = new(Zone)

        data := string(buf)
        cs, p, pe, eof := 0, 0, len(data), len(data)
        mark := 0
        hdr := new(RR_Header)
        tok := newToken()
        var rr RR

        
// line 95 "zparse.go"
	cs = z_start

// line 98 "zparse.go"
	{
	if p == pe { goto _test_eof }
	switch cs {
	case -666: // i am a hack D:
	fallthrough
case 1:
	switch data[p] {
		case 9: goto st2
		case 32: goto st2
		case 92: goto st7
		case 95: goto st7
	}
	if data[p] < 48 {
		if 45 <= data[p] && data[p] <= 46 { goto st7 }
	} else if data[p] > 57 {
		if data[p] > 90 {
			if 97 <= data[p] && data[p] <= 122 { goto st7 }
		} else if data[p] >= 65 {
			goto st7
		}
	} else {
		goto st7
	}
	goto st0
st0:
cs = 0;
	goto _out;
tr30:
// line 87 "zparse.rl"
	{ hdr.Name = data[mark:p] }
	goto st2
tr176:
// line 92 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 94 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("setting") }
	goto st2
tr179:
// line 92 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 94 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("setting") }
	goto st2
tr182:
// line 92 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 94 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("setting") }
	goto st2
tr185:
// line 92 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 49 "types.rl"
	{
            x := rr.(*RR_DNSKEY)
            x.Hdr = *hdr;
            x.Flags = uint16(tok.N[0])
            x.Protocol = uint8(tok.N[1])
            x.Algorithm = uint8(tok.N[2])
            x.PublicKey = tok.T[0]
        }
// line 94 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("setting") }
	goto st2
tr188:
// line 92 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 41 "types.rl"
	{
            x := rr.(*RR_DS)
            x.Hdr = *hdr;
            x.KeyTag = uint16(tok.N[0])
            x.Algorithm = uint8(tok.N[1])
            x.DigestType = uint8(tok.N[2])
            x.Digest = tok.T[0]
        }
// line 94 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("setting") }
	goto st2
tr191:
// line 92 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 94 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("setting") }
	goto st2
tr194:
// line 92 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 94 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("setting") }
	goto st2
tr197:
// line 92 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 57 "types.rl"
	{
            x := rr.(*RR_RRSIG)
            x.Hdr = *hdr;
            x.TypeCovered = uint16(tok.N[0])
            x.Algorithm = uint8(tok.N[1])
            x.Labels = uint8(tok.N[2])
            x.OrigTtl = uint32(tok.N[3])
            x.Expiration = uint32(tok.N[4])
            x.Inception = uint32(tok.N[5])
            x.KeyTag = uint16(tok.N[6])
            x.SignerName = tok.T[0]
            x.Signature = tok.T[1]
        }
// line 94 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("setting") }
	goto st2
tr200:
// line 91 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 24 "types.rl"
	{
            x := rr.(*RR_SOA)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
            x.Mbox = tok.T[1]
            x.Serial = uint32(tok.N[0])
            x.Refresh = uint32(tok.N[1])
            x.Retry = uint32(tok.N[2])
            x.Expire = uint32(tok.N[3])
            x.Minttl = uint32(tok.N[4])
        }
// line 94 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("setting") }
	goto st2
st2:
	p++
	if p == pe { goto _test_eof2 }
	fallthrough
case 2:
// line 264 "zparse.go"
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
// line 86 "zparse.rl"
	{ mark = p }
// line 89 "zparse.rl"
	{ /* ... */ }
	goto st3
st3:
	p++
	if p == pe { goto _test_eof3 }
	fallthrough
case 3:
// line 300 "zparse.go"
	switch data[p] {
		case 9: goto tr13
		case 32: goto tr13
	}
	if 48 <= data[p] && data[p] <= 57 { goto st3 }
	goto st0
tr13:
// line 90 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st4
st4:
	p++
	if p == pe { goto _test_eof4 }
	fallthrough
case 4:
// line 316 "zparse.go"
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
// line 86 "zparse.rl"
	{ mark = p }
	goto st5
st5:
	p++
	if p == pe { goto _test_eof5 }
	fallthrough
case 5:
// line 349 "zparse.go"
	switch data[p] {
		case 9: goto tr25
		case 32: goto tr25
		case 65: goto st8
		case 78: goto st12
		case 97: goto st8
		case 110: goto st12
	}
	goto st0
tr25:
// line 96 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        println("Unknown type seen: " + data[mark:p])
                        // panic?
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
// line 377 "zparse.go"
	switch data[p] {
		case 9: goto st6
		case 32: goto st6
		case 43: goto tr29
		case 61: goto tr29
		case 92: goto tr29
	}
	if data[p] < 65 {
		if 45 <= data[p] && data[p] <= 58 { goto tr29 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr29 }
	} else {
		goto tr29
	}
	goto st0
tr29:
// line 86 "zparse.rl"
	{ mark = p }
	goto st106
st106:
	p++
	if p == pe { goto _test_eof106 }
	fallthrough
case 106:
// line 402 "zparse.go"
	switch data[p] {
		case 9: goto tr176
		case 32: goto tr176
		case 43: goto st106
		case 61: goto st106
		case 92: goto st106
		case 95: goto tr178
	}
	if data[p] < 65 {
		if 45 <= data[p] && data[p] <= 58 { goto st106 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st106 }
	} else {
		goto st106
	}
	goto st0
tr178:
// line 92 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 94 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("setting") }
	goto st7
tr181:
// line 92 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 94 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("setting") }
	goto st7
tr184:
// line 92 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 94 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("setting") }
	goto st7
tr187:
// line 92 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 49 "types.rl"
	{
            x := rr.(*RR_DNSKEY)
            x.Hdr = *hdr;
            x.Flags = uint16(tok.N[0])
            x.Protocol = uint8(tok.N[1])
            x.Algorithm = uint8(tok.N[2])
            x.PublicKey = tok.T[0]
        }
// line 94 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("setting") }
	goto st7
tr190:
// line 92 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 41 "types.rl"
	{
            x := rr.(*RR_DS)
            x.Hdr = *hdr;
            x.KeyTag = uint16(tok.N[0])
            x.Algorithm = uint8(tok.N[1])
            x.DigestType = uint8(tok.N[2])
            x.Digest = tok.T[0]
        }
// line 94 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("setting") }
	goto st7
tr193:
// line 92 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 94 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("setting") }
	goto st7
tr196:
// line 92 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 94 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("setting") }
	goto st7
tr199:
// line 92 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 57 "types.rl"
	{
            x := rr.(*RR_RRSIG)
            x.Hdr = *hdr;
            x.TypeCovered = uint16(tok.N[0])
            x.Algorithm = uint8(tok.N[1])
            x.Labels = uint8(tok.N[2])
            x.OrigTtl = uint32(tok.N[3])
            x.Expiration = uint32(tok.N[4])
            x.Inception = uint32(tok.N[5])
            x.KeyTag = uint16(tok.N[6])
            x.SignerName = tok.T[0]
            x.Signature = tok.T[1]
        }
// line 94 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("setting") }
	goto st7
tr201:
// line 91 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 24 "types.rl"
	{
            x := rr.(*RR_SOA)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
            x.Mbox = tok.T[1]
            x.Serial = uint32(tok.N[0])
            x.Refresh = uint32(tok.N[1])
            x.Retry = uint32(tok.N[2])
            x.Expire = uint32(tok.N[3])
            x.Minttl = uint32(tok.N[4])
        }
// line 94 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("setting") }
	goto st7
st7:
	p++
	if p == pe { goto _test_eof7 }
	fallthrough
case 7:
// line 553 "zparse.go"
	switch data[p] {
		case 9: goto tr30
		case 32: goto tr30
		case 92: goto st7
		case 95: goto st7
	}
	if data[p] < 48 {
		if 45 <= data[p] && data[p] <= 46 { goto st7 }
	} else if data[p] > 57 {
		if data[p] > 90 {
			if 97 <= data[p] && data[p] <= 122 { goto st7 }
		} else if data[p] >= 65 {
			goto st7
		}
	} else {
		goto st7
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
		case 9: goto tr33
		case 32: goto tr33
	}
	goto st0
tr33:
// line 96 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        println("Unknown type seen: " + data[mark:p])
                        // panic?
                    }
                    rr = mk()
                    hdr.Rrtype = i
                }
	goto st11
st11:
	p++
	if p == pe { goto _test_eof11 }
	fallthrough
case 11:
// line 620 "zparse.go"
	switch data[p] {
		case 9: goto st11
		case 32: goto st11
		case 43: goto tr35
		case 61: goto tr35
		case 92: goto tr35
	}
	if data[p] < 65 {
		if 45 <= data[p] && data[p] <= 58 { goto tr35 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr35 }
	} else {
		goto tr35
	}
	goto st0
tr35:
// line 86 "zparse.rl"
	{ mark = p }
	goto st107
st107:
	p++
	if p == pe { goto _test_eof107 }
	fallthrough
case 107:
// line 645 "zparse.go"
	switch data[p] {
		case 9: goto tr179
		case 32: goto tr179
		case 43: goto st107
		case 61: goto st107
		case 92: goto st107
		case 95: goto tr181
	}
	if data[p] < 65 {
		if 45 <= data[p] && data[p] <= 58 { goto st107 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st107 }
	} else {
		goto st107
	}
	goto st0
st12:
	p++
	if p == pe { goto _test_eof12 }
	fallthrough
case 12:
	switch data[p] {
		case 89: goto st13
		case 121: goto st13
	}
	goto st0
st13:
	p++
	if p == pe { goto _test_eof13 }
	fallthrough
case 13:
	switch data[p] {
		case 9: goto tr37
		case 32: goto tr37
	}
	goto st0
tr172:
// line 90 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st14
tr37:
// line 88 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st14
st14:
	p++
	if p == pe { goto _test_eof14 }
	fallthrough
case 14:
// line 695 "zparse.go"
	switch data[p] {
		case 9: goto st14
		case 32: goto st14
		case 65: goto tr39
		case 67: goto tr40
		case 68: goto tr18
		case 77: goto tr21
		case 78: goto tr41
		case 82: goto tr23
		case 83: goto tr24
		case 97: goto tr39
		case 99: goto tr40
		case 100: goto tr18
		case 109: goto tr21
		case 110: goto tr41
		case 114: goto tr23
		case 115: goto tr24
	}
	goto st0
tr39:
// line 86 "zparse.rl"
	{ mark = p }
	goto st15
st15:
	p++
	if p == pe { goto _test_eof15 }
	fallthrough
case 15:
// line 724 "zparse.go"
	switch data[p] {
		case 9: goto tr25
		case 32: goto tr25
		case 65: goto st8
		case 97: goto st8
	}
	goto st0
tr40:
// line 86 "zparse.rl"
	{ mark = p }
	goto st16
st16:
	p++
	if p == pe { goto _test_eof16 }
	fallthrough
case 16:
// line 741 "zparse.go"
	switch data[p] {
		case 78: goto st17
		case 110: goto st17
	}
	goto st0
st17:
	p++
	if p == pe { goto _test_eof17 }
	fallthrough
case 17:
	switch data[p] {
		case 65: goto st18
		case 97: goto st18
	}
	goto st0
st18:
	p++
	if p == pe { goto _test_eof18 }
	fallthrough
case 18:
	switch data[p] {
		case 77: goto st19
		case 109: goto st19
	}
	goto st0
st19:
	p++
	if p == pe { goto _test_eof19 }
	fallthrough
case 19:
	switch data[p] {
		case 69: goto st20
		case 101: goto st20
	}
	goto st0
st20:
	p++
	if p == pe { goto _test_eof20 }
	fallthrough
case 20:
	switch data[p] {
		case 9: goto tr46
		case 32: goto tr46
	}
	goto st0
tr46:
// line 96 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        println("Unknown type seen: " + data[mark:p])
                        // panic?
                    }
                    rr = mk()
                    hdr.Rrtype = i
                }
	goto st21
st21:
	p++
	if p == pe { goto _test_eof21 }
	fallthrough
case 21:
// line 805 "zparse.go"
	switch data[p] {
		case 9: goto st21
		case 32: goto st21
		case 43: goto tr48
		case 61: goto tr48
		case 92: goto tr48
	}
	if data[p] < 65 {
		if 45 <= data[p] && data[p] <= 58 { goto tr48 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr48 }
	} else {
		goto tr48
	}
	goto st0
tr48:
// line 86 "zparse.rl"
	{ mark = p }
	goto st108
st108:
	p++
	if p == pe { goto _test_eof108 }
	fallthrough
case 108:
// line 830 "zparse.go"
	switch data[p] {
		case 9: goto tr182
		case 32: goto tr182
		case 43: goto st108
		case 61: goto st108
		case 92: goto st108
		case 95: goto tr184
	}
	if data[p] < 65 {
		if 45 <= data[p] && data[p] <= 58 { goto st108 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st108 }
	} else {
		goto st108
	}
	goto st0
tr6:
// line 86 "zparse.rl"
	{ mark = p }
// line 89 "zparse.rl"
	{ /* ... */ }
	goto st22
tr18:
// line 86 "zparse.rl"
	{ mark = p }
	goto st22
st22:
	p++
	if p == pe { goto _test_eof22 }
	fallthrough
case 22:
// line 862 "zparse.go"
	switch data[p] {
		case 78: goto st23
		case 83: goto st35
		case 110: goto st23
		case 115: goto st35
	}
	goto st0
st23:
	p++
	if p == pe { goto _test_eof23 }
	fallthrough
case 23:
	switch data[p] {
		case 83: goto st24
		case 115: goto st24
	}
	goto st0
st24:
	p++
	if p == pe { goto _test_eof24 }
	fallthrough
case 24:
	switch data[p] {
		case 75: goto st25
		case 107: goto st25
	}
	goto st0
st25:
	p++
	if p == pe { goto _test_eof25 }
	fallthrough
case 25:
	switch data[p] {
		case 69: goto st26
		case 101: goto st26
	}
	goto st0
st26:
	p++
	if p == pe { goto _test_eof26 }
	fallthrough
case 26:
	switch data[p] {
		case 89: goto st27
		case 121: goto st27
	}
	goto st0
st27:
	p++
	if p == pe { goto _test_eof27 }
	fallthrough
case 27:
	switch data[p] {
		case 9: goto tr55
		case 32: goto tr55
	}
	goto st0
tr55:
// line 96 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        println("Unknown type seen: " + data[mark:p])
                        // panic?
                    }
                    rr = mk()
                    hdr.Rrtype = i
                }
	goto st28
st28:
	p++
	if p == pe { goto _test_eof28 }
	fallthrough
case 28:
// line 938 "zparse.go"
	switch data[p] {
		case 9: goto st28
		case 32: goto st28
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr57 }
	goto st0
tr57:
// line 86 "zparse.rl"
	{ mark = p }
	goto st29
st29:
	p++
	if p == pe { goto _test_eof29 }
	fallthrough
case 29:
// line 954 "zparse.go"
	switch data[p] {
		case 9: goto tr58
		case 32: goto tr58
	}
	if 48 <= data[p] && data[p] <= 57 { goto st29 }
	goto st0
tr58:
// line 91 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st30
st30:
	p++
	if p == pe { goto _test_eof30 }
	fallthrough
case 30:
// line 970 "zparse.go"
	switch data[p] {
		case 9: goto st30
		case 32: goto st30
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr61 }
	goto st0
tr61:
// line 86 "zparse.rl"
	{ mark = p }
	goto st31
st31:
	p++
	if p == pe { goto _test_eof31 }
	fallthrough
case 31:
// line 986 "zparse.go"
	switch data[p] {
		case 9: goto tr62
		case 32: goto tr62
	}
	if 48 <= data[p] && data[p] <= 57 { goto st31 }
	goto st0
tr62:
// line 91 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st32
st32:
	p++
	if p == pe { goto _test_eof32 }
	fallthrough
case 32:
// line 1002 "zparse.go"
	switch data[p] {
		case 9: goto st32
		case 32: goto st32
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr65 }
	goto st0
tr65:
// line 86 "zparse.rl"
	{ mark = p }
	goto st33
st33:
	p++
	if p == pe { goto _test_eof33 }
	fallthrough
case 33:
// line 1018 "zparse.go"
	switch data[p] {
		case 9: goto tr66
		case 32: goto tr66
	}
	if 48 <= data[p] && data[p] <= 57 { goto st33 }
	goto st0
tr66:
// line 91 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st34
st34:
	p++
	if p == pe { goto _test_eof34 }
	fallthrough
case 34:
// line 1034 "zparse.go"
	switch data[p] {
		case 9: goto st34
		case 32: goto st34
		case 43: goto tr69
		case 61: goto tr69
		case 92: goto tr69
	}
	if data[p] < 65 {
		if 45 <= data[p] && data[p] <= 58 { goto tr69 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr69 }
	} else {
		goto tr69
	}
	goto st0
tr69:
// line 86 "zparse.rl"
	{ mark = p }
	goto st109
st109:
	p++
	if p == pe { goto _test_eof109 }
	fallthrough
case 109:
// line 1059 "zparse.go"
	switch data[p] {
		case 9: goto tr185
		case 32: goto tr185
		case 43: goto st109
		case 61: goto st109
		case 92: goto st109
		case 95: goto tr187
	}
	if data[p] < 65 {
		if 45 <= data[p] && data[p] <= 58 { goto st109 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st109 }
	} else {
		goto st109
	}
	goto st0
st35:
	p++
	if p == pe { goto _test_eof35 }
	fallthrough
case 35:
	switch data[p] {
		case 9: goto tr70
		case 32: goto tr70
	}
	goto st0
tr70:
// line 96 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        println("Unknown type seen: " + data[mark:p])
                        // panic?
                    }
                    rr = mk()
                    hdr.Rrtype = i
                }
	goto st36
st36:
	p++
	if p == pe { goto _test_eof36 }
	fallthrough
case 36:
// line 1104 "zparse.go"
	switch data[p] {
		case 9: goto st36
		case 32: goto st36
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr72 }
	goto st0
tr72:
// line 86 "zparse.rl"
	{ mark = p }
	goto st37
st37:
	p++
	if p == pe { goto _test_eof37 }
	fallthrough
case 37:
// line 1120 "zparse.go"
	switch data[p] {
		case 9: goto tr73
		case 32: goto tr73
	}
	if 48 <= data[p] && data[p] <= 57 { goto st37 }
	goto st0
tr73:
// line 91 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st38
st38:
	p++
	if p == pe { goto _test_eof38 }
	fallthrough
case 38:
// line 1136 "zparse.go"
	switch data[p] {
		case 9: goto st38
		case 32: goto st38
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr76 }
	goto st0
tr76:
// line 86 "zparse.rl"
	{ mark = p }
	goto st39
st39:
	p++
	if p == pe { goto _test_eof39 }
	fallthrough
case 39:
// line 1152 "zparse.go"
	switch data[p] {
		case 9: goto tr77
		case 32: goto tr77
	}
	if 48 <= data[p] && data[p] <= 57 { goto st39 }
	goto st0
tr77:
// line 91 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st40
st40:
	p++
	if p == pe { goto _test_eof40 }
	fallthrough
case 40:
// line 1168 "zparse.go"
	switch data[p] {
		case 9: goto st40
		case 32: goto st40
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr80 }
	goto st0
tr80:
// line 86 "zparse.rl"
	{ mark = p }
	goto st41
st41:
	p++
	if p == pe { goto _test_eof41 }
	fallthrough
case 41:
// line 1184 "zparse.go"
	switch data[p] {
		case 9: goto tr81
		case 32: goto tr81
	}
	if 48 <= data[p] && data[p] <= 57 { goto st41 }
	goto st0
tr81:
// line 91 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st42
st42:
	p++
	if p == pe { goto _test_eof42 }
	fallthrough
case 42:
// line 1200 "zparse.go"
	switch data[p] {
		case 9: goto st42
		case 32: goto st42
		case 43: goto tr84
		case 61: goto tr84
		case 92: goto tr84
	}
	if data[p] < 65 {
		if 45 <= data[p] && data[p] <= 58 { goto tr84 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr84 }
	} else {
		goto tr84
	}
	goto st0
tr84:
// line 86 "zparse.rl"
	{ mark = p }
	goto st110
st110:
	p++
	if p == pe { goto _test_eof110 }
	fallthrough
case 110:
// line 1225 "zparse.go"
	switch data[p] {
		case 9: goto tr188
		case 32: goto tr188
		case 43: goto st110
		case 61: goto st110
		case 92: goto st110
		case 95: goto tr190
	}
	if data[p] < 65 {
		if 45 <= data[p] && data[p] <= 58 { goto st110 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st110 }
	} else {
		goto st110
	}
	goto st0
tr9:
// line 86 "zparse.rl"
	{ mark = p }
// line 89 "zparse.rl"
	{ /* ... */ }
	goto st43
tr21:
// line 86 "zparse.rl"
	{ mark = p }
	goto st43
st43:
	p++
	if p == pe { goto _test_eof43 }
	fallthrough
case 43:
// line 1257 "zparse.go"
	switch data[p] {
		case 88: goto st44
		case 120: goto st44
	}
	goto st0
st44:
	p++
	if p == pe { goto _test_eof44 }
	fallthrough
case 44:
	switch data[p] {
		case 9: goto tr86
		case 32: goto tr86
	}
	goto st0
tr86:
// line 96 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        println("Unknown type seen: " + data[mark:p])
                        // panic?
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
// line 1291 "zparse.go"
	switch data[p] {
		case 9: goto st45
		case 32: goto st45
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr88 }
	goto st0
tr88:
// line 86 "zparse.rl"
	{ mark = p }
	goto st46
st46:
	p++
	if p == pe { goto _test_eof46 }
	fallthrough
case 46:
// line 1307 "zparse.go"
	switch data[p] {
		case 9: goto tr89
		case 32: goto tr89
	}
	if 48 <= data[p] && data[p] <= 57 { goto st46 }
	goto st0
tr89:
// line 91 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st47
st47:
	p++
	if p == pe { goto _test_eof47 }
	fallthrough
case 47:
// line 1323 "zparse.go"
	switch data[p] {
		case 9: goto st47
		case 32: goto st47
		case 43: goto tr92
		case 61: goto tr92
		case 92: goto tr92
	}
	if data[p] < 65 {
		if 45 <= data[p] && data[p] <= 58 { goto tr92 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr92 }
	} else {
		goto tr92
	}
	goto st0
tr92:
// line 86 "zparse.rl"
	{ mark = p }
	goto st111
st111:
	p++
	if p == pe { goto _test_eof111 }
	fallthrough
case 111:
// line 1348 "zparse.go"
	switch data[p] {
		case 9: goto tr191
		case 32: goto tr191
		case 43: goto st111
		case 61: goto st111
		case 92: goto st111
		case 95: goto tr193
	}
	if data[p] < 65 {
		if 45 <= data[p] && data[p] <= 58 { goto st111 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st111 }
	} else {
		goto st111
	}
	goto st0
tr41:
// line 86 "zparse.rl"
	{ mark = p }
	goto st48
st48:
	p++
	if p == pe { goto _test_eof48 }
	fallthrough
case 48:
// line 1374 "zparse.go"
	switch data[p] {
		case 83: goto st49
		case 115: goto st49
	}
	goto st0
st49:
	p++
	if p == pe { goto _test_eof49 }
	fallthrough
case 49:
	switch data[p] {
		case 9: goto tr94
		case 32: goto tr94
	}
	goto st0
tr94:
// line 96 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        println("Unknown type seen: " + data[mark:p])
                        // panic?
                    }
                    rr = mk()
                    hdr.Rrtype = i
                }
	goto st50
st50:
	p++
	if p == pe { goto _test_eof50 }
	fallthrough
case 50:
// line 1408 "zparse.go"
	switch data[p] {
		case 9: goto st50
		case 32: goto st50
		case 43: goto tr96
		case 61: goto tr96
		case 92: goto tr96
	}
	if data[p] < 65 {
		if 45 <= data[p] && data[p] <= 58 { goto tr96 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr96 }
	} else {
		goto tr96
	}
	goto st0
tr96:
// line 86 "zparse.rl"
	{ mark = p }
	goto st112
st112:
	p++
	if p == pe { goto _test_eof112 }
	fallthrough
case 112:
// line 1433 "zparse.go"
	switch data[p] {
		case 9: goto tr194
		case 32: goto tr194
		case 43: goto st112
		case 61: goto st112
		case 92: goto st112
		case 95: goto tr196
	}
	if data[p] < 65 {
		if 45 <= data[p] && data[p] <= 58 { goto st112 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st112 }
	} else {
		goto st112
	}
	goto st0
tr11:
// line 86 "zparse.rl"
	{ mark = p }
// line 89 "zparse.rl"
	{ /* ... */ }
	goto st51
tr23:
// line 86 "zparse.rl"
	{ mark = p }
	goto st51
st51:
	p++
	if p == pe { goto _test_eof51 }
	fallthrough
case 51:
// line 1465 "zparse.go"
	switch data[p] {
		case 82: goto st52
		case 114: goto st52
	}
	goto st0
st52:
	p++
	if p == pe { goto _test_eof52 }
	fallthrough
case 52:
	switch data[p] {
		case 83: goto st53
		case 115: goto st53
	}
	goto st0
st53:
	p++
	if p == pe { goto _test_eof53 }
	fallthrough
case 53:
	switch data[p] {
		case 73: goto st54
		case 105: goto st54
	}
	goto st0
st54:
	p++
	if p == pe { goto _test_eof54 }
	fallthrough
case 54:
	switch data[p] {
		case 71: goto st55
		case 103: goto st55
	}
	goto st0
st55:
	p++
	if p == pe { goto _test_eof55 }
	fallthrough
case 55:
	switch data[p] {
		case 9: goto tr101
		case 32: goto tr101
	}
	goto st0
tr101:
// line 96 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        println("Unknown type seen: " + data[mark:p])
                        // panic?
                    }
                    rr = mk()
                    hdr.Rrtype = i
                }
	goto st56
st56:
	p++
	if p == pe { goto _test_eof56 }
	fallthrough
case 56:
// line 1529 "zparse.go"
	switch data[p] {
		case 9: goto st56
		case 32: goto st56
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr103 }
	goto st0
tr103:
// line 86 "zparse.rl"
	{ mark = p }
	goto st57
st57:
	p++
	if p == pe { goto _test_eof57 }
	fallthrough
case 57:
// line 1545 "zparse.go"
	switch data[p] {
		case 9: goto tr104
		case 32: goto tr104
	}
	if 48 <= data[p] && data[p] <= 57 { goto st57 }
	goto st0
tr104:
// line 91 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st58
st58:
	p++
	if p == pe { goto _test_eof58 }
	fallthrough
case 58:
// line 1561 "zparse.go"
	switch data[p] {
		case 9: goto st58
		case 32: goto st58
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr107 }
	goto st0
tr107:
// line 86 "zparse.rl"
	{ mark = p }
	goto st59
st59:
	p++
	if p == pe { goto _test_eof59 }
	fallthrough
case 59:
// line 1577 "zparse.go"
	switch data[p] {
		case 9: goto tr108
		case 32: goto tr108
	}
	if 48 <= data[p] && data[p] <= 57 { goto st59 }
	goto st0
tr108:
// line 91 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st60
st60:
	p++
	if p == pe { goto _test_eof60 }
	fallthrough
case 60:
// line 1593 "zparse.go"
	switch data[p] {
		case 9: goto st60
		case 32: goto st60
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr111 }
	goto st0
tr111:
// line 86 "zparse.rl"
	{ mark = p }
	goto st61
st61:
	p++
	if p == pe { goto _test_eof61 }
	fallthrough
case 61:
// line 1609 "zparse.go"
	switch data[p] {
		case 9: goto tr112
		case 32: goto tr112
	}
	if 48 <= data[p] && data[p] <= 57 { goto st61 }
	goto st0
tr112:
// line 91 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st62
st62:
	p++
	if p == pe { goto _test_eof62 }
	fallthrough
case 62:
// line 1625 "zparse.go"
	switch data[p] {
		case 9: goto st62
		case 32: goto st62
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr115 }
	goto st0
tr115:
// line 86 "zparse.rl"
	{ mark = p }
	goto st63
st63:
	p++
	if p == pe { goto _test_eof63 }
	fallthrough
case 63:
// line 1641 "zparse.go"
	switch data[p] {
		case 9: goto tr116
		case 32: goto tr116
	}
	if 48 <= data[p] && data[p] <= 57 { goto st63 }
	goto st0
tr116:
// line 91 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st64
st64:
	p++
	if p == pe { goto _test_eof64 }
	fallthrough
case 64:
// line 1657 "zparse.go"
	switch data[p] {
		case 9: goto st64
		case 32: goto st64
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr119 }
	goto st0
tr119:
// line 86 "zparse.rl"
	{ mark = p }
	goto st65
st65:
	p++
	if p == pe { goto _test_eof65 }
	fallthrough
case 65:
// line 1673 "zparse.go"
	switch data[p] {
		case 9: goto tr120
		case 32: goto tr120
	}
	if 48 <= data[p] && data[p] <= 57 { goto st65 }
	goto st0
tr120:
// line 91 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st66
st66:
	p++
	if p == pe { goto _test_eof66 }
	fallthrough
case 66:
// line 1689 "zparse.go"
	switch data[p] {
		case 9: goto st66
		case 32: goto st66
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr123 }
	goto st0
tr123:
// line 86 "zparse.rl"
	{ mark = p }
	goto st67
st67:
	p++
	if p == pe { goto _test_eof67 }
	fallthrough
case 67:
// line 1705 "zparse.go"
	switch data[p] {
		case 9: goto tr124
		case 32: goto tr124
	}
	if 48 <= data[p] && data[p] <= 57 { goto st67 }
	goto st0
tr124:
// line 91 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st68
st68:
	p++
	if p == pe { goto _test_eof68 }
	fallthrough
case 68:
// line 1721 "zparse.go"
	switch data[p] {
		case 9: goto st68
		case 32: goto st68
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr127 }
	goto st0
tr127:
// line 86 "zparse.rl"
	{ mark = p }
	goto st69
st69:
	p++
	if p == pe { goto _test_eof69 }
	fallthrough
case 69:
// line 1737 "zparse.go"
	switch data[p] {
		case 9: goto tr128
		case 32: goto tr128
	}
	if 48 <= data[p] && data[p] <= 57 { goto st69 }
	goto st0
tr128:
// line 91 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st70
st70:
	p++
	if p == pe { goto _test_eof70 }
	fallthrough
case 70:
// line 1753 "zparse.go"
	switch data[p] {
		case 9: goto st70
		case 32: goto st70
		case 43: goto tr131
		case 61: goto tr131
		case 92: goto tr131
	}
	if data[p] < 65 {
		if 45 <= data[p] && data[p] <= 58 { goto tr131 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr131 }
	} else {
		goto tr131
	}
	goto st0
tr131:
// line 86 "zparse.rl"
	{ mark = p }
	goto st71
st71:
	p++
	if p == pe { goto _test_eof71 }
	fallthrough
case 71:
// line 1778 "zparse.go"
	switch data[p] {
		case 9: goto tr132
		case 32: goto tr132
		case 43: goto st71
		case 61: goto st71
		case 92: goto st71
	}
	if data[p] < 65 {
		if 45 <= data[p] && data[p] <= 58 { goto st71 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st71 }
	} else {
		goto st71
	}
	goto st0
tr132:
// line 92 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
	goto st72
st72:
	p++
	if p == pe { goto _test_eof72 }
	fallthrough
case 72:
// line 1803 "zparse.go"
	switch data[p] {
		case 9: goto st72
		case 32: goto st72
		case 43: goto tr135
		case 61: goto tr135
		case 92: goto tr135
	}
	if data[p] < 65 {
		if 45 <= data[p] && data[p] <= 58 { goto tr135 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr135 }
	} else {
		goto tr135
	}
	goto st0
tr135:
// line 86 "zparse.rl"
	{ mark = p }
	goto st113
st113:
	p++
	if p == pe { goto _test_eof113 }
	fallthrough
case 113:
// line 1828 "zparse.go"
	switch data[p] {
		case 9: goto tr197
		case 32: goto tr197
		case 43: goto st113
		case 61: goto st113
		case 92: goto st113
		case 95: goto tr199
	}
	if data[p] < 65 {
		if 45 <= data[p] && data[p] <= 58 { goto st113 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st113 }
	} else {
		goto st113
	}
	goto st0
tr12:
// line 86 "zparse.rl"
	{ mark = p }
// line 89 "zparse.rl"
	{ /* ... */ }
	goto st73
tr24:
// line 86 "zparse.rl"
	{ mark = p }
	goto st73
st73:
	p++
	if p == pe { goto _test_eof73 }
	fallthrough
case 73:
// line 1860 "zparse.go"
	switch data[p] {
		case 79: goto st74
		case 111: goto st74
	}
	goto st0
st74:
	p++
	if p == pe { goto _test_eof74 }
	fallthrough
case 74:
	switch data[p] {
		case 65: goto st75
		case 97: goto st75
	}
	goto st0
st75:
	p++
	if p == pe { goto _test_eof75 }
	fallthrough
case 75:
	switch data[p] {
		case 9: goto tr138
		case 32: goto tr138
	}
	goto st0
tr138:
// line 96 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        println("Unknown type seen: " + data[mark:p])
                        // panic?
                    }
                    rr = mk()
                    hdr.Rrtype = i
                }
	goto st76
st76:
	p++
	if p == pe { goto _test_eof76 }
	fallthrough
case 76:
// line 1904 "zparse.go"
	switch data[p] {
		case 9: goto st76
		case 32: goto st76
		case 43: goto tr140
		case 61: goto tr140
		case 92: goto tr140
	}
	if data[p] < 65 {
		if 45 <= data[p] && data[p] <= 58 { goto tr140 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr140 }
	} else {
		goto tr140
	}
	goto st0
tr140:
// line 86 "zparse.rl"
	{ mark = p }
	goto st77
st77:
	p++
	if p == pe { goto _test_eof77 }
	fallthrough
case 77:
// line 1929 "zparse.go"
	switch data[p] {
		case 9: goto tr141
		case 32: goto tr141
		case 43: goto st77
		case 61: goto st77
		case 92: goto st77
	}
	if data[p] < 65 {
		if 45 <= data[p] && data[p] <= 58 { goto st77 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st77 }
	} else {
		goto st77
	}
	goto st0
tr141:
// line 92 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
	goto st78
st78:
	p++
	if p == pe { goto _test_eof78 }
	fallthrough
case 78:
// line 1954 "zparse.go"
	switch data[p] {
		case 9: goto st78
		case 32: goto st78
		case 43: goto tr144
		case 61: goto tr144
		case 92: goto tr144
	}
	if data[p] < 65 {
		if 45 <= data[p] && data[p] <= 58 { goto tr144 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr144 }
	} else {
		goto tr144
	}
	goto st0
tr144:
// line 86 "zparse.rl"
	{ mark = p }
	goto st79
st79:
	p++
	if p == pe { goto _test_eof79 }
	fallthrough
case 79:
// line 1979 "zparse.go"
	switch data[p] {
		case 9: goto tr145
		case 32: goto tr145
		case 43: goto st79
		case 61: goto st79
		case 92: goto st79
	}
	if data[p] < 65 {
		if 45 <= data[p] && data[p] <= 58 { goto st79 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr145:
// line 92 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
	goto st80
st80:
	p++
	if p == pe { goto _test_eof80 }
	fallthrough
case 80:
// line 2004 "zparse.go"
	switch data[p] {
		case 9: goto st80
		case 32: goto st80
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr148 }
	goto st0
tr148:
// line 86 "zparse.rl"
	{ mark = p }
	goto st81
st81:
	p++
	if p == pe { goto _test_eof81 }
	fallthrough
case 81:
// line 2020 "zparse.go"
	switch data[p] {
		case 9: goto tr149
		case 32: goto tr149
	}
	if 48 <= data[p] && data[p] <= 57 { goto st81 }
	goto st0
tr149:
// line 91 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st82
st82:
	p++
	if p == pe { goto _test_eof82 }
	fallthrough
case 82:
// line 2036 "zparse.go"
	switch data[p] {
		case 9: goto st82
		case 32: goto st82
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr152 }
	goto st0
tr152:
// line 86 "zparse.rl"
	{ mark = p }
	goto st83
st83:
	p++
	if p == pe { goto _test_eof83 }
	fallthrough
case 83:
// line 2052 "zparse.go"
	switch data[p] {
		case 9: goto tr153
		case 32: goto tr153
	}
	if 48 <= data[p] && data[p] <= 57 { goto st83 }
	goto st0
tr153:
// line 91 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st84
st84:
	p++
	if p == pe { goto _test_eof84 }
	fallthrough
case 84:
// line 2068 "zparse.go"
	switch data[p] {
		case 9: goto st84
		case 32: goto st84
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr156 }
	goto st0
tr156:
// line 86 "zparse.rl"
	{ mark = p }
	goto st85
st85:
	p++
	if p == pe { goto _test_eof85 }
	fallthrough
case 85:
// line 2084 "zparse.go"
	switch data[p] {
		case 9: goto tr157
		case 32: goto tr157
	}
	if 48 <= data[p] && data[p] <= 57 { goto st85 }
	goto st0
tr157:
// line 91 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st86
st86:
	p++
	if p == pe { goto _test_eof86 }
	fallthrough
case 86:
// line 2100 "zparse.go"
	switch data[p] {
		case 9: goto st86
		case 32: goto st86
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr160 }
	goto st0
tr160:
// line 86 "zparse.rl"
	{ mark = p }
	goto st87
st87:
	p++
	if p == pe { goto _test_eof87 }
	fallthrough
case 87:
// line 2116 "zparse.go"
	switch data[p] {
		case 9: goto tr161
		case 32: goto tr161
	}
	if 48 <= data[p] && data[p] <= 57 { goto st87 }
	goto st0
tr161:
// line 91 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st88
st88:
	p++
	if p == pe { goto _test_eof88 }
	fallthrough
case 88:
// line 2132 "zparse.go"
	switch data[p] {
		case 9: goto st88
		case 32: goto st88
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr164 }
	goto st0
tr164:
// line 86 "zparse.rl"
	{ mark = p }
	goto st114
st114:
	p++
	if p == pe { goto _test_eof114 }
	fallthrough
case 114:
// line 2148 "zparse.go"
	switch data[p] {
		case 9: goto tr200
		case 32: goto tr200
		case 92: goto tr201
		case 95: goto tr201
	}
	if data[p] < 48 {
		if 45 <= data[p] && data[p] <= 46 { goto tr201 }
	} else if data[p] > 57 {
		if data[p] > 90 {
			if 97 <= data[p] && data[p] <= 122 { goto tr201 }
		} else if data[p] >= 65 {
			goto tr201
		}
	} else {
		goto st114
	}
	goto st0
tr17:
// line 86 "zparse.rl"
	{ mark = p }
	goto st89
st89:
	p++
	if p == pe { goto _test_eof89 }
	fallthrough
case 89:
// line 2176 "zparse.go"
	switch data[p] {
		case 72: goto st13
		case 78: goto st17
		case 83: goto st13
		case 104: goto st13
		case 110: goto st17
		case 115: goto st13
	}
	goto st0
tr19:
// line 86 "zparse.rl"
	{ mark = p }
	goto st90
st90:
	p++
	if p == pe { goto _test_eof90 }
	fallthrough
case 90:
// line 2195 "zparse.go"
	switch data[p] {
		case 83: goto st13
		case 115: goto st13
	}
	goto st0
tr20:
// line 86 "zparse.rl"
	{ mark = p }
	goto st91
st91:
	p++
	if p == pe { goto _test_eof91 }
	fallthrough
case 91:
// line 2210 "zparse.go"
	switch data[p] {
		case 78: goto st13
		case 110: goto st13
	}
	goto st0
tr22:
// line 86 "zparse.rl"
	{ mark = p }
	goto st92
st92:
	p++
	if p == pe { goto _test_eof92 }
	fallthrough
case 92:
// line 2225 "zparse.go"
	switch data[p] {
		case 79: goto st93
		case 83: goto st49
		case 111: goto st93
		case 115: goto st49
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
		case 69: goto st13
		case 101: goto st13
	}
	goto st0
tr4:
// line 86 "zparse.rl"
	{ mark = p }
// line 89 "zparse.rl"
	{ /* ... */ }
	goto st95
st95:
	p++
	if p == pe { goto _test_eof95 }
	fallthrough
case 95:
// line 2264 "zparse.go"
	switch data[p] {
		case 9: goto tr25
		case 32: goto tr25
		case 65: goto st8
		case 78: goto st96
		case 97: goto st8
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
// line 88 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st98
st98:
	p++
	if p == pe { goto _test_eof98 }
	fallthrough
case 98:
// line 2303 "zparse.go"
	switch data[p] {
		case 9: goto st98
		case 32: goto st98
		case 65: goto tr39
		case 67: goto tr40
		case 68: goto tr18
		case 77: goto tr21
		case 78: goto tr41
		case 82: goto tr23
		case 83: goto tr24
		case 97: goto tr39
		case 99: goto tr40
		case 100: goto tr18
		case 109: goto tr21
		case 110: goto tr41
		case 114: goto tr23
		case 115: goto tr24
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr171 }
	goto st0
tr171:
// line 86 "zparse.rl"
	{ mark = p }
	goto st99
st99:
	p++
	if p == pe { goto _test_eof99 }
	fallthrough
case 99:
// line 2333 "zparse.go"
	switch data[p] {
		case 9: goto tr172
		case 32: goto tr172
	}
	if 48 <= data[p] && data[p] <= 57 { goto st99 }
	goto st0
tr5:
// line 86 "zparse.rl"
	{ mark = p }
// line 89 "zparse.rl"
	{ /* ... */ }
	goto st100
st100:
	p++
	if p == pe { goto _test_eof100 }
	fallthrough
case 100:
// line 2351 "zparse.go"
	switch data[p] {
		case 72: goto st97
		case 78: goto st17
		case 83: goto st97
		case 104: goto st97
		case 110: goto st17
		case 115: goto st97
	}
	goto st0
tr7:
// line 86 "zparse.rl"
	{ mark = p }
// line 89 "zparse.rl"
	{ /* ... */ }
	goto st101
st101:
	p++
	if p == pe { goto _test_eof101 }
	fallthrough
case 101:
// line 2372 "zparse.go"
	switch data[p] {
		case 83: goto st97
		case 115: goto st97
	}
	goto st0
tr8:
// line 86 "zparse.rl"
	{ mark = p }
// line 89 "zparse.rl"
	{ /* ... */ }
	goto st102
st102:
	p++
	if p == pe { goto _test_eof102 }
	fallthrough
case 102:
// line 2389 "zparse.go"
	switch data[p] {
		case 78: goto st97
		case 110: goto st97
	}
	goto st0
tr10:
// line 86 "zparse.rl"
	{ mark = p }
// line 89 "zparse.rl"
	{ /* ... */ }
	goto st103
st103:
	p++
	if p == pe { goto _test_eof103 }
	fallthrough
case 103:
// line 2406 "zparse.go"
	switch data[p] {
		case 79: goto st104
		case 83: goto st49
		case 111: goto st104
		case 115: goto st49
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
	_test_eof11: cs = 11; goto _test_eof; 
	_test_eof107: cs = 107; goto _test_eof; 
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
	_test_eof108: cs = 108; goto _test_eof; 
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
	_test_eof109: cs = 109; goto _test_eof; 
	_test_eof35: cs = 35; goto _test_eof; 
	_test_eof36: cs = 36; goto _test_eof; 
	_test_eof37: cs = 37; goto _test_eof; 
	_test_eof38: cs = 38; goto _test_eof; 
	_test_eof39: cs = 39; goto _test_eof; 
	_test_eof40: cs = 40; goto _test_eof; 
	_test_eof41: cs = 41; goto _test_eof; 
	_test_eof42: cs = 42; goto _test_eof; 
	_test_eof110: cs = 110; goto _test_eof; 
	_test_eof43: cs = 43; goto _test_eof; 
	_test_eof44: cs = 44; goto _test_eof; 
	_test_eof45: cs = 45; goto _test_eof; 
	_test_eof46: cs = 46; goto _test_eof; 
	_test_eof47: cs = 47; goto _test_eof; 
	_test_eof111: cs = 111; goto _test_eof; 
	_test_eof48: cs = 48; goto _test_eof; 
	_test_eof49: cs = 49; goto _test_eof; 
	_test_eof50: cs = 50; goto _test_eof; 
	_test_eof112: cs = 112; goto _test_eof; 
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
	_test_eof113: cs = 113; goto _test_eof; 
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
	_test_eof114: cs = 114; goto _test_eof; 
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
// line 91 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 24 "types.rl"
	{
            x := rr.(*RR_SOA)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
            x.Mbox = tok.T[1]
            x.Serial = uint32(tok.N[0])
            x.Refresh = uint32(tok.N[1])
            x.Retry = uint32(tok.N[2])
            x.Expire = uint32(tok.N[3])
            x.Minttl = uint32(tok.N[4])
        }
// line 94 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("setting") }
	break
	case 106:
// line 92 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 94 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("setting") }
	break
	case 107:
// line 92 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 94 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("setting") }
	break
	case 112:
// line 92 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 94 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("setting") }
	break
	case 108:
// line 92 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 94 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("setting") }
	break
	case 111:
// line 92 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 94 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("setting") }
	break
	case 110:
// line 92 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 41 "types.rl"
	{
            x := rr.(*RR_DS)
            x.Hdr = *hdr;
            x.KeyTag = uint16(tok.N[0])
            x.Algorithm = uint8(tok.N[1])
            x.DigestType = uint8(tok.N[2])
            x.Digest = tok.T[0]
        }
// line 94 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("setting") }
	break
	case 109:
// line 92 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 49 "types.rl"
	{
            x := rr.(*RR_DNSKEY)
            x.Hdr = *hdr;
            x.Flags = uint16(tok.N[0])
            x.Protocol = uint8(tok.N[1])
            x.Algorithm = uint8(tok.N[2])
            x.PublicKey = tok.T[0]
        }
// line 94 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("setting") }
	break
	case 113:
// line 92 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 57 "types.rl"
	{
            x := rr.(*RR_RRSIG)
            x.Hdr = *hdr;
            x.TypeCovered = uint16(tok.N[0])
            x.Algorithm = uint8(tok.N[1])
            x.Labels = uint8(tok.N[2])
            x.OrigTtl = uint32(tok.N[3])
            x.Expiration = uint32(tok.N[4])
            x.Inception = uint32(tok.N[5])
            x.KeyTag = uint16(tok.N[6])
            x.SignerName = tok.T[0]
            x.Signature = tok.T[1]
        }
// line 94 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("setting") }
	break
// line 2681 "zparse.go"
	}
	}

	_out: {}
	}

// line 145 "zparse.rl"


        if cs < z_first_final {
                // No clue what I'm doing what so ever
                if p == pe {
                        println("unexpected eof")
                        return z, nil
                } else {
                        println("error at position ", p)
                        return z, nil
                }
        }
        return z, nil
}
