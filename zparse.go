
// line 1 "zparse.rl"
package dns

// Parse RRs
// With the thankful help of gdnsd and the Go examples for Ragel.
// 

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

func rdata_aaaa(hdr RR_Header, tok *token) RR {
        rr := new(RR_AAAA)
        rr.Hdr = hdr
        rr.Hdr.Rrtype = TypeAAAA
        rr.AAAA = net.ParseIP(tok.T[0])
        return rr
}

func rdata_a(hdr RR_Header, tok *token) RR {
        rr := new(RR_A)
        rr.Hdr = hdr
        rr.Hdr.Rrtype = TypeA
        rr.A = net.ParseIP(tok.T[0])
        return rr
}

func rdata_ns(hdr RR_Header, tok *token) RR {
        rr := new(RR_NS)
        rr.Hdr = hdr
        rr.Hdr.Rrtype = TypeNS
        rr.Ns = tok.T[0]
        return rr
}

func rdata_cname(hdr RR_Header, tok *token) RR {
        rr := new(RR_CNAME)
        rr.Hdr = hdr
        rr.Hdr.Rrtype = TypeCNAME
        rr.Cname = tok.T[0]
        return rr
}

func rdata_soa(hdr RR_Header, tok *token) RR {
        rr := new(RR_SOA)
        rr.Hdr = hdr
        rr.Hdr.Rrtype = TypeSOA
        rr.Ns = tok.T[0]
        rr.Mbox = tok.T[1]
        rr.Serial = uint32(tok.N[0])
        rr.Refresh = uint32(tok.N[1])
        rr.Retry = uint32(tok.N[2])
        rr.Expire = uint32(tok.N[3])
        rr.Minttl = uint32(tok.N[4])
        return rr
}

func rdata_mx(hdr RR_Header, tok *token) RR {
        rr := new(RR_MX)
        rr.Hdr = hdr;
        rr.Hdr.Rrtype = TypeMX
        rr.Pref = uint16(tok.N[0])
        rr.Mx = tok.T[0]
        return rr
}

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

func set(r RR, z *Zone, tok *token) {
        z.Push(r)
        tok.reset()
}


// line 162 "zparse.go"
var z_start int = 85
var z_first_final int = 85
var z_error int = 0

var z_en_main int = 85


// line 161 "zparse.rl"


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
        ts, te, act := 0, 0, 0
//        top := 0
//        stack := make([]int, 100)
        eof := len(data)
        // keep Go happy - need to fix this ofcourse
        ts = ts; te = te; act = act

        brace := false
        lines := 0
        mark := 0
        hdr := new(RR_Header)
        tok := newToken()
        var rr RR
        rr = rr

        
// line 204 "zparse.go"
	cs = z_start
	ts = 0
	te = 0
	act = 0

// line 210 "zparse.go"
	{
	if p == pe { goto _test_eof }
	switch cs {
	case -666: // i am a hack D:
tr219:
// line 235 "zparse.rl"
	{te = p;p--;{ rr = rdata_a(*hdr, tok); set(rr, z, tok); }}
	goto st85
tr221:
// line 238 "zparse.rl"
	{te = p;p--;{ rr = rdata_aaaa(*hdr, tok); set(rr, z, tok); }}
	goto st85
tr223:
// line 237 "zparse.rl"
	{te = p;p--;{ rr = rdata_cname(*hdr, tok); set(rr, z, tok); }}
	goto st85
tr225:
// line 239 "zparse.rl"
	{te = p;p--;{ rr = rdata_mx(*hdr, tok); set(rr, z, tok); }}
	goto st85
tr227:
// line 236 "zparse.rl"
	{te = p;p--;{ rr = rdata_ns(*hdr, tok); set(rr, z, tok); }}
	goto st85
tr229:
// line 240 "zparse.rl"
	{te = p;p--;{ rr = rdata_soa(*hdr, tok); set(rr, z, tok); }}
	goto st85
st85:
// line 1 "NONE"
	{ts = 0;}
	p++
	if p == pe { goto _test_eof85 }
	fallthrough
case 85:
// line 1 "NONE"
	{ts = p;}
// line 248 "zparse.go"
	switch data[p] {
		case 9: goto st1
		case 10: goto tr2
		case 32: goto st1
		case 40: goto tr3
		case 41: goto tr4
		case 59: goto st71
		case 95: goto st84
	}
	if data[p] < 48 {
		if 45 <= data[p] && data[p] <= 46 { goto st84 }
	} else if data[p] > 57 {
		if data[p] > 90 {
			if 97 <= data[p] && data[p] <= 122 { goto st84 }
		} else if data[p] >= 65 {
			goto st84
		}
	} else {
		goto st84
	}
	goto st0
st0:
cs = 0;
	goto _out;
tr2:
// line 204 "zparse.rl"
	{ lines++ }
	goto st1
tr3:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st1
tr4:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st1
tr213:
// line 195 "zparse.rl"
	{ hdr.Name = data[mark:p] }
	goto st1
tr214:
// line 195 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 204 "zparse.rl"
	{ lines++ }
	goto st1
tr215:
// line 195 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st1
tr216:
// line 195 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st1
st1:
	p++
	if p == pe { goto _test_eof1 }
	fallthrough
case 1:
// line 312 "zparse.go"
	switch data[p] {
		case 9: goto st1
		case 10: goto tr2
		case 32: goto st1
		case 40: goto tr3
		case 41: goto tr4
		case 59: goto st71
		case 65: goto tr7
		case 67: goto tr8
		case 72: goto tr9
		case 73: goto tr10
		case 77: goto tr11
		case 78: goto tr12
		case 83: goto tr13
		case 97: goto tr7
		case 99: goto tr8
		case 104: goto tr9
		case 105: goto tr10
		case 109: goto tr11
		case 110: goto tr12
		case 115: goto tr13
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr5 }
	goto st0
tr5:
// line 194 "zparse.rl"
	{ mark = p }
// line 197 "zparse.rl"
	{ /* ... */ }
	goto st2
st2:
	p++
	if p == pe { goto _test_eof2 }
	fallthrough
case 2:
// line 348 "zparse.go"
	switch data[p] {
		case 9: goto tr14
		case 10: goto tr15
		case 32: goto tr14
		case 40: goto tr16
		case 41: goto tr17
		case 59: goto tr19
	}
	if 48 <= data[p] && data[p] <= 57 { goto st2 }
	goto st0
tr21:
// line 204 "zparse.rl"
	{ lines++ }
	goto st3
tr22:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st3
tr23:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st3
tr14:
// line 198 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st3
tr15:
// line 198 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st3
tr16:
// line 198 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st3
tr17:
// line 198 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st3
st3:
	p++
	if p == pe { goto _test_eof3 }
	fallthrough
case 3:
// line 398 "zparse.go"
	switch data[p] {
		case 9: goto st3
		case 10: goto tr21
		case 32: goto st3
		case 40: goto tr22
		case 41: goto tr23
		case 59: goto st4
		case 65: goto tr25
		case 67: goto tr26
		case 72: goto tr27
		case 73: goto tr28
		case 77: goto tr29
		case 78: goto tr30
		case 83: goto tr31
		case 97: goto tr25
		case 99: goto tr26
		case 104: goto tr27
		case 105: goto tr28
		case 109: goto tr29
		case 110: goto tr30
		case 115: goto tr31
	}
	goto st0
tr19:
// line 198 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st4
st4:
	p++
	if p == pe { goto _test_eof4 }
	fallthrough
case 4:
// line 431 "zparse.go"
	if data[p] == 10 { goto tr21 }
	goto st4
tr25:
// line 194 "zparse.rl"
	{ mark = p }
	goto st5
st5:
	p++
	if p == pe { goto _test_eof5 }
	fallthrough
case 5:
// line 443 "zparse.go"
	switch data[p] {
		case 9: goto st6
		case 10: goto tr33
		case 32: goto st6
		case 40: goto tr34
		case 41: goto tr35
		case 59: goto st8
		case 65: goto st9
		case 78: goto st15
		case 97: goto st9
		case 110: goto st15
	}
	goto st0
tr33:
// line 204 "zparse.rl"
	{ lines++ }
	goto st6
tr34:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st6
tr35:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st6
st6:
	p++
	if p == pe { goto _test_eof6 }
	fallthrough
case 6:
// line 474 "zparse.go"
	switch data[p] {
		case 9: goto st6
		case 10: goto tr33
		case 32: goto st6
		case 40: goto tr34
		case 41: goto tr35
		case 59: goto st8
		case 95: goto tr39
	}
	if data[p] < 48 {
		if 45 <= data[p] && data[p] <= 46 { goto tr39 }
	} else if data[p] > 58 {
		if data[p] > 90 {
			if 97 <= data[p] && data[p] <= 122 { goto tr39 }
		} else if data[p] >= 65 {
			goto tr39
		}
	} else {
		goto tr39
	}
	goto st0
tr39:
// line 194 "zparse.rl"
	{ mark = p }
	goto st7
st7:
	p++
	if p == pe { goto _test_eof7 }
	fallthrough
case 7:
// line 505 "zparse.go"
	switch data[p] {
		case 10: goto tr40
		case 95: goto st7
	}
	if data[p] < 48 {
		if 45 <= data[p] && data[p] <= 46 { goto st7 }
	} else if data[p] > 58 {
		if data[p] > 90 {
			if 97 <= data[p] && data[p] <= 122 { goto st7 }
		} else if data[p] >= 65 {
			goto st7
		}
	} else {
		goto st7
	}
	goto st0
tr220:
// line 204 "zparse.rl"
	{ lines++ }
	goto st86
tr40:
// line 200 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st86
st86:
	p++
	if p == pe { goto _test_eof86 }
	fallthrough
case 86:
// line 537 "zparse.go"
	if data[p] == 10 { goto tr220 }
	goto tr219
st8:
	p++
	if p == pe { goto _test_eof8 }
	fallthrough
case 8:
	if data[p] == 10 { goto tr33 }
	goto st8
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
		case 65: goto st11
		case 97: goto st11
	}
	goto st0
st11:
	p++
	if p == pe { goto _test_eof11 }
	fallthrough
case 11:
	switch data[p] {
		case 9: goto st12
		case 10: goto tr45
		case 32: goto st12
		case 40: goto tr46
		case 41: goto tr47
		case 59: goto st14
	}
	goto st0
tr45:
// line 204 "zparse.rl"
	{ lines++ }
	goto st12
tr46:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st12
tr47:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st12
st12:
	p++
	if p == pe { goto _test_eof12 }
	fallthrough
case 12:
// line 598 "zparse.go"
	switch data[p] {
		case 9: goto st12
		case 10: goto tr45
		case 32: goto st12
		case 40: goto tr46
		case 41: goto tr47
		case 59: goto st14
		case 95: goto tr49
	}
	if data[p] < 48 {
		if 45 <= data[p] && data[p] <= 46 { goto tr49 }
	} else if data[p] > 58 {
		if data[p] > 90 {
			if 97 <= data[p] && data[p] <= 122 { goto tr49 }
		} else if data[p] >= 65 {
			goto tr49
		}
	} else {
		goto tr49
	}
	goto st0
tr49:
// line 194 "zparse.rl"
	{ mark = p }
	goto st13
st13:
	p++
	if p == pe { goto _test_eof13 }
	fallthrough
case 13:
// line 629 "zparse.go"
	switch data[p] {
		case 10: goto tr50
		case 95: goto st13
	}
	if data[p] < 48 {
		if 45 <= data[p] && data[p] <= 46 { goto st13 }
	} else if data[p] > 58 {
		if data[p] > 90 {
			if 97 <= data[p] && data[p] <= 122 { goto st13 }
		} else if data[p] >= 65 {
			goto st13
		}
	} else {
		goto st13
	}
	goto st0
tr222:
// line 204 "zparse.rl"
	{ lines++ }
	goto st87
tr50:
// line 200 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st87
st87:
	p++
	if p == pe { goto _test_eof87 }
	fallthrough
case 87:
// line 661 "zparse.go"
	if data[p] == 10 { goto tr222 }
	goto tr221
st14:
	p++
	if p == pe { goto _test_eof14 }
	fallthrough
case 14:
	if data[p] == 10 { goto tr45 }
	goto st14
st15:
	p++
	if p == pe { goto _test_eof15 }
	fallthrough
case 15:
	switch data[p] {
		case 89: goto st16
		case 121: goto st16
	}
	goto st0
st16:
	p++
	if p == pe { goto _test_eof16 }
	fallthrough
case 16:
	switch data[p] {
		case 9: goto tr53
		case 10: goto tr54
		case 32: goto tr53
		case 40: goto tr55
		case 41: goto tr56
		case 59: goto tr57
	}
	goto st0
tr59:
// line 204 "zparse.rl"
	{ lines++ }
	goto st17
tr60:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st17
tr61:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st17
tr205:
// line 198 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st17
tr206:
// line 198 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st17
tr207:
// line 198 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st17
tr208:
// line 198 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st17
tr53:
// line 196 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st17
tr54:
// line 196 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 204 "zparse.rl"
	{ lines++ }
	goto st17
tr55:
// line 196 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st17
tr56:
// line 196 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st17
st17:
	p++
	if p == pe { goto _test_eof17 }
	fallthrough
case 17:
// line 756 "zparse.go"
	switch data[p] {
		case 9: goto st17
		case 10: goto tr59
		case 32: goto st17
		case 40: goto tr60
		case 41: goto tr61
		case 59: goto st18
		case 65: goto tr63
		case 67: goto tr64
		case 77: goto tr29
		case 78: goto tr65
		case 83: goto tr31
		case 97: goto tr63
		case 99: goto tr64
		case 109: goto tr29
		case 110: goto tr65
		case 115: goto tr31
	}
	goto st0
tr210:
// line 198 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st18
tr57:
// line 196 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st18
st18:
	p++
	if p == pe { goto _test_eof18 }
	fallthrough
case 18:
// line 789 "zparse.go"
	if data[p] == 10 { goto tr59 }
	goto st18
tr63:
// line 194 "zparse.rl"
	{ mark = p }
	goto st19
st19:
	p++
	if p == pe { goto _test_eof19 }
	fallthrough
case 19:
// line 801 "zparse.go"
	switch data[p] {
		case 9: goto st6
		case 10: goto tr33
		case 32: goto st6
		case 40: goto tr34
		case 41: goto tr35
		case 59: goto st8
		case 65: goto st9
		case 97: goto st9
	}
	goto st0
tr64:
// line 194 "zparse.rl"
	{ mark = p }
	goto st20
st20:
	p++
	if p == pe { goto _test_eof20 }
	fallthrough
case 20:
// line 822 "zparse.go"
	switch data[p] {
		case 78: goto st21
		case 110: goto st21
	}
	goto st0
st21:
	p++
	if p == pe { goto _test_eof21 }
	fallthrough
case 21:
	switch data[p] {
		case 65: goto st22
		case 97: goto st22
	}
	goto st0
st22:
	p++
	if p == pe { goto _test_eof22 }
	fallthrough
case 22:
	switch data[p] {
		case 77: goto st23
		case 109: goto st23
	}
	goto st0
st23:
	p++
	if p == pe { goto _test_eof23 }
	fallthrough
case 23:
	switch data[p] {
		case 69: goto st24
		case 101: goto st24
	}
	goto st0
st24:
	p++
	if p == pe { goto _test_eof24 }
	fallthrough
case 24:
	switch data[p] {
		case 9: goto st25
		case 10: goto tr71
		case 32: goto st25
		case 40: goto tr72
		case 41: goto tr73
		case 59: goto st27
	}
	goto st0
tr71:
// line 204 "zparse.rl"
	{ lines++ }
	goto st25
tr72:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st25
tr73:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st25
st25:
	p++
	if p == pe { goto _test_eof25 }
	fallthrough
case 25:
// line 889 "zparse.go"
	switch data[p] {
		case 9: goto st25
		case 10: goto tr71
		case 32: goto st25
		case 40: goto tr72
		case 41: goto tr73
		case 59: goto st27
		case 95: goto tr75
	}
	if data[p] < 48 {
		if 45 <= data[p] && data[p] <= 46 { goto tr75 }
	} else if data[p] > 58 {
		if data[p] > 90 {
			if 97 <= data[p] && data[p] <= 122 { goto tr75 }
		} else if data[p] >= 65 {
			goto tr75
		}
	} else {
		goto tr75
	}
	goto st0
tr75:
// line 194 "zparse.rl"
	{ mark = p }
	goto st26
st26:
	p++
	if p == pe { goto _test_eof26 }
	fallthrough
case 26:
// line 920 "zparse.go"
	switch data[p] {
		case 10: goto tr76
		case 95: goto st26
	}
	if data[p] < 48 {
		if 45 <= data[p] && data[p] <= 46 { goto st26 }
	} else if data[p] > 58 {
		if data[p] > 90 {
			if 97 <= data[p] && data[p] <= 122 { goto st26 }
		} else if data[p] >= 65 {
			goto st26
		}
	} else {
		goto st26
	}
	goto st0
tr224:
// line 204 "zparse.rl"
	{ lines++ }
	goto st88
tr76:
// line 200 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st88
st88:
	p++
	if p == pe { goto _test_eof88 }
	fallthrough
case 88:
// line 952 "zparse.go"
	if data[p] == 10 { goto tr224 }
	goto tr223
st27:
	p++
	if p == pe { goto _test_eof27 }
	fallthrough
case 27:
	if data[p] == 10 { goto tr71 }
	goto st27
tr11:
// line 194 "zparse.rl"
	{ mark = p }
// line 197 "zparse.rl"
	{ /* ... */ }
	goto st28
tr29:
// line 194 "zparse.rl"
	{ mark = p }
	goto st28
st28:
	p++
	if p == pe { goto _test_eof28 }
	fallthrough
case 28:
// line 977 "zparse.go"
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
	switch data[p] {
		case 9: goto st30
		case 10: goto tr80
		case 32: goto st30
		case 40: goto tr81
		case 41: goto tr82
		case 59: goto st35
	}
	goto st0
tr80:
// line 204 "zparse.rl"
	{ lines++ }
	goto st30
tr81:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st30
tr82:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st30
st30:
	p++
	if p == pe { goto _test_eof30 }
	fallthrough
case 30:
// line 1014 "zparse.go"
	switch data[p] {
		case 9: goto st30
		case 10: goto tr80
		case 32: goto st30
		case 40: goto tr81
		case 41: goto tr82
		case 59: goto st35
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr84 }
	goto st0
tr84:
// line 194 "zparse.rl"
	{ mark = p }
	goto st31
st31:
	p++
	if p == pe { goto _test_eof31 }
	fallthrough
case 31:
// line 1034 "zparse.go"
	switch data[p] {
		case 9: goto tr85
		case 10: goto tr86
		case 32: goto tr85
		case 40: goto tr87
		case 41: goto tr88
		case 59: goto tr90
	}
	if 48 <= data[p] && data[p] <= 57 { goto st31 }
	goto st0
tr92:
// line 204 "zparse.rl"
	{ lines++ }
	goto st32
tr93:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st32
tr94:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st32
tr85:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st32
tr86:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st32
tr87:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st32
tr88:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st32
st32:
	p++
	if p == pe { goto _test_eof32 }
	fallthrough
case 32:
// line 1084 "zparse.go"
	switch data[p] {
		case 9: goto st32
		case 10: goto tr92
		case 32: goto st32
		case 40: goto tr93
		case 41: goto tr94
		case 59: goto st34
		case 95: goto tr95
	}
	if data[p] < 48 {
		if 45 <= data[p] && data[p] <= 46 { goto tr95 }
	} else if data[p] > 58 {
		if data[p] > 90 {
			if 97 <= data[p] && data[p] <= 122 { goto tr95 }
		} else if data[p] >= 65 {
			goto tr95
		}
	} else {
		goto tr95
	}
	goto st0
tr95:
// line 194 "zparse.rl"
	{ mark = p }
	goto st33
st33:
	p++
	if p == pe { goto _test_eof33 }
	fallthrough
case 33:
// line 1115 "zparse.go"
	switch data[p] {
		case 10: goto tr97
		case 95: goto st33
	}
	if data[p] < 48 {
		if 45 <= data[p] && data[p] <= 46 { goto st33 }
	} else if data[p] > 58 {
		if data[p] > 90 {
			if 97 <= data[p] && data[p] <= 122 { goto st33 }
		} else if data[p] >= 65 {
			goto st33
		}
	} else {
		goto st33
	}
	goto st0
tr226:
// line 204 "zparse.rl"
	{ lines++ }
	goto st89
tr97:
// line 200 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st89
st89:
	p++
	if p == pe { goto _test_eof89 }
	fallthrough
case 89:
// line 1147 "zparse.go"
	if data[p] == 10 { goto tr226 }
	goto tr225
tr90:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st34
st34:
	p++
	if p == pe { goto _test_eof34 }
	fallthrough
case 34:
// line 1159 "zparse.go"
	if data[p] == 10 { goto tr92 }
	goto st34
st35:
	p++
	if p == pe { goto _test_eof35 }
	fallthrough
case 35:
	if data[p] == 10 { goto tr80 }
	goto st35
tr65:
// line 194 "zparse.rl"
	{ mark = p }
	goto st36
st36:
	p++
	if p == pe { goto _test_eof36 }
	fallthrough
case 36:
// line 1178 "zparse.go"
	switch data[p] {
		case 83: goto st37
		case 115: goto st37
	}
	goto st0
st37:
	p++
	if p == pe { goto _test_eof37 }
	fallthrough
case 37:
	switch data[p] {
		case 9: goto st38
		case 10: goto tr101
		case 32: goto st38
		case 40: goto tr102
		case 41: goto tr103
		case 59: goto st40
	}
	goto st0
tr101:
// line 204 "zparse.rl"
	{ lines++ }
	goto st38
tr102:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st38
tr103:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st38
st38:
	p++
	if p == pe { goto _test_eof38 }
	fallthrough
case 38:
// line 1215 "zparse.go"
	switch data[p] {
		case 9: goto st38
		case 10: goto tr101
		case 32: goto st38
		case 40: goto tr102
		case 41: goto tr103
		case 59: goto st40
		case 95: goto tr105
	}
	if data[p] < 48 {
		if 45 <= data[p] && data[p] <= 46 { goto tr105 }
	} else if data[p] > 58 {
		if data[p] > 90 {
			if 97 <= data[p] && data[p] <= 122 { goto tr105 }
		} else if data[p] >= 65 {
			goto tr105
		}
	} else {
		goto tr105
	}
	goto st0
tr105:
// line 194 "zparse.rl"
	{ mark = p }
	goto st39
st39:
	p++
	if p == pe { goto _test_eof39 }
	fallthrough
case 39:
// line 1246 "zparse.go"
	switch data[p] {
		case 10: goto tr106
		case 95: goto st39
	}
	if data[p] < 48 {
		if 45 <= data[p] && data[p] <= 46 { goto st39 }
	} else if data[p] > 58 {
		if data[p] > 90 {
			if 97 <= data[p] && data[p] <= 122 { goto st39 }
		} else if data[p] >= 65 {
			goto st39
		}
	} else {
		goto st39
	}
	goto st0
tr228:
// line 204 "zparse.rl"
	{ lines++ }
	goto st90
tr106:
// line 200 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st90
st90:
	p++
	if p == pe { goto _test_eof90 }
	fallthrough
case 90:
// line 1278 "zparse.go"
	if data[p] == 10 { goto tr228 }
	goto tr227
st40:
	p++
	if p == pe { goto _test_eof40 }
	fallthrough
case 40:
	if data[p] == 10 { goto tr101 }
	goto st40
tr13:
// line 194 "zparse.rl"
	{ mark = p }
// line 197 "zparse.rl"
	{ /* ... */ }
	goto st41
tr31:
// line 194 "zparse.rl"
	{ mark = p }
	goto st41
st41:
	p++
	if p == pe { goto _test_eof41 }
	fallthrough
case 41:
// line 1303 "zparse.go"
	switch data[p] {
		case 79: goto st42
		case 111: goto st42
	}
	goto st0
st42:
	p++
	if p == pe { goto _test_eof42 }
	fallthrough
case 42:
	switch data[p] {
		case 65: goto st43
		case 97: goto st43
	}
	goto st0
st43:
	p++
	if p == pe { goto _test_eof43 }
	fallthrough
case 43:
	switch data[p] {
		case 9: goto st44
		case 10: goto tr111
		case 32: goto st44
		case 40: goto tr112
		case 41: goto tr113
		case 59: goto st64
	}
	goto st0
tr111:
// line 204 "zparse.rl"
	{ lines++ }
	goto st44
tr112:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st44
tr113:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st44
st44:
	p++
	if p == pe { goto _test_eof44 }
	fallthrough
case 44:
// line 1350 "zparse.go"
	switch data[p] {
		case 9: goto st44
		case 10: goto tr111
		case 32: goto st44
		case 40: goto tr112
		case 41: goto tr113
		case 59: goto st64
		case 95: goto tr115
	}
	if data[p] < 48 {
		if 45 <= data[p] && data[p] <= 46 { goto tr115 }
	} else if data[p] > 58 {
		if data[p] > 90 {
			if 97 <= data[p] && data[p] <= 122 { goto tr115 }
		} else if data[p] >= 65 {
			goto tr115
		}
	} else {
		goto tr115
	}
	goto st0
tr115:
// line 194 "zparse.rl"
	{ mark = p }
	goto st45
st45:
	p++
	if p == pe { goto _test_eof45 }
	fallthrough
case 45:
// line 1381 "zparse.go"
	switch data[p] {
		case 9: goto tr116
		case 10: goto tr117
		case 32: goto tr116
		case 40: goto tr118
		case 41: goto tr119
		case 59: goto tr121
		case 95: goto st45
	}
	if data[p] < 48 {
		if 45 <= data[p] && data[p] <= 46 { goto st45 }
	} else if data[p] > 58 {
		if data[p] > 90 {
			if 97 <= data[p] && data[p] <= 122 { goto st45 }
		} else if data[p] >= 65 {
			goto st45
		}
	} else {
		goto st45
	}
	goto st0
tr123:
// line 204 "zparse.rl"
	{ lines++ }
	goto st46
tr124:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st46
tr125:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st46
tr117:
// line 200 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st46
tr116:
// line 200 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
	goto st46
tr118:
// line 200 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st46
tr119:
// line 200 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st46
st46:
	p++
	if p == pe { goto _test_eof46 }
	fallthrough
case 46:
// line 1442 "zparse.go"
	switch data[p] {
		case 9: goto st46
		case 10: goto tr123
		case 32: goto st46
		case 40: goto tr124
		case 41: goto tr125
		case 59: goto st63
		case 95: goto tr126
	}
	if data[p] < 48 {
		if 45 <= data[p] && data[p] <= 46 { goto tr126 }
	} else if data[p] > 58 {
		if data[p] > 90 {
			if 97 <= data[p] && data[p] <= 122 { goto tr126 }
		} else if data[p] >= 65 {
			goto tr126
		}
	} else {
		goto tr126
	}
	goto st0
tr126:
// line 194 "zparse.rl"
	{ mark = p }
	goto st47
st47:
	p++
	if p == pe { goto _test_eof47 }
	fallthrough
case 47:
// line 1473 "zparse.go"
	switch data[p] {
		case 9: goto tr128
		case 10: goto tr129
		case 32: goto tr128
		case 40: goto tr130
		case 41: goto tr131
		case 59: goto tr133
		case 95: goto st47
	}
	if data[p] < 48 {
		if 45 <= data[p] && data[p] <= 46 { goto st47 }
	} else if data[p] > 58 {
		if data[p] > 90 {
			if 97 <= data[p] && data[p] <= 122 { goto st47 }
		} else if data[p] >= 65 {
			goto st47
		}
	} else {
		goto st47
	}
	goto st0
tr135:
// line 204 "zparse.rl"
	{ lines++ }
	goto st48
tr136:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st48
tr137:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st48
tr129:
// line 200 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st48
tr128:
// line 200 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
	goto st48
tr130:
// line 200 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st48
tr131:
// line 200 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st48
st48:
	p++
	if p == pe { goto _test_eof48 }
	fallthrough
case 48:
// line 1534 "zparse.go"
	switch data[p] {
		case 9: goto st48
		case 10: goto tr135
		case 32: goto st48
		case 40: goto tr136
		case 41: goto tr137
		case 59: goto st62
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr138 }
	goto st0
tr138:
// line 194 "zparse.rl"
	{ mark = p }
	goto st49
st49:
	p++
	if p == pe { goto _test_eof49 }
	fallthrough
case 49:
// line 1554 "zparse.go"
	switch data[p] {
		case 9: goto tr140
		case 10: goto tr141
		case 32: goto tr140
		case 40: goto tr142
		case 41: goto tr143
		case 59: goto tr145
	}
	if 48 <= data[p] && data[p] <= 57 { goto st49 }
	goto st0
tr147:
// line 204 "zparse.rl"
	{ lines++ }
	goto st50
tr148:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st50
tr149:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st50
tr140:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st50
tr141:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st50
tr142:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st50
tr143:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st50
st50:
	p++
	if p == pe { goto _test_eof50 }
	fallthrough
case 50:
// line 1604 "zparse.go"
	switch data[p] {
		case 9: goto st50
		case 10: goto tr147
		case 32: goto st50
		case 40: goto tr148
		case 41: goto tr149
		case 59: goto st61
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr150 }
	goto st0
tr150:
// line 194 "zparse.rl"
	{ mark = p }
	goto st51
st51:
	p++
	if p == pe { goto _test_eof51 }
	fallthrough
case 51:
// line 1624 "zparse.go"
	switch data[p] {
		case 9: goto tr152
		case 10: goto tr153
		case 32: goto tr152
		case 40: goto tr154
		case 41: goto tr155
		case 59: goto tr157
	}
	if 48 <= data[p] && data[p] <= 57 { goto st51 }
	goto st0
tr159:
// line 204 "zparse.rl"
	{ lines++ }
	goto st52
tr160:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st52
tr161:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st52
tr152:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st52
tr153:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st52
tr154:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st52
tr155:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st52
st52:
	p++
	if p == pe { goto _test_eof52 }
	fallthrough
case 52:
// line 1674 "zparse.go"
	switch data[p] {
		case 9: goto st52
		case 10: goto tr159
		case 32: goto st52
		case 40: goto tr160
		case 41: goto tr161
		case 59: goto st60
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr162 }
	goto st0
tr162:
// line 194 "zparse.rl"
	{ mark = p }
	goto st53
st53:
	p++
	if p == pe { goto _test_eof53 }
	fallthrough
case 53:
// line 1694 "zparse.go"
	switch data[p] {
		case 9: goto tr164
		case 10: goto tr165
		case 32: goto tr164
		case 40: goto tr166
		case 41: goto tr167
		case 59: goto tr169
	}
	if 48 <= data[p] && data[p] <= 57 { goto st53 }
	goto st0
tr171:
// line 204 "zparse.rl"
	{ lines++ }
	goto st54
tr172:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st54
tr173:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st54
tr164:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st54
tr165:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st54
tr166:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st54
tr167:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st54
st54:
	p++
	if p == pe { goto _test_eof54 }
	fallthrough
case 54:
// line 1744 "zparse.go"
	switch data[p] {
		case 9: goto st54
		case 10: goto tr171
		case 32: goto st54
		case 40: goto tr172
		case 41: goto tr173
		case 59: goto st59
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr174 }
	goto st0
tr174:
// line 194 "zparse.rl"
	{ mark = p }
	goto st55
st55:
	p++
	if p == pe { goto _test_eof55 }
	fallthrough
case 55:
// line 1764 "zparse.go"
	switch data[p] {
		case 9: goto tr176
		case 10: goto tr177
		case 32: goto tr176
		case 40: goto tr178
		case 41: goto tr179
		case 59: goto tr181
	}
	if 48 <= data[p] && data[p] <= 57 { goto st55 }
	goto st0
tr183:
// line 204 "zparse.rl"
	{ lines++ }
	goto st56
tr184:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st56
tr185:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st56
tr176:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st56
tr177:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st56
tr178:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st56
tr179:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st56
st56:
	p++
	if p == pe { goto _test_eof56 }
	fallthrough
case 56:
// line 1814 "zparse.go"
	switch data[p] {
		case 9: goto st56
		case 10: goto tr183
		case 32: goto st56
		case 40: goto tr184
		case 41: goto tr185
		case 59: goto st58
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr186 }
	goto st0
tr186:
// line 194 "zparse.rl"
	{ mark = p }
	goto st57
st57:
	p++
	if p == pe { goto _test_eof57 }
	fallthrough
case 57:
// line 1834 "zparse.go"
	if data[p] == 10 { goto tr188 }
	if 48 <= data[p] && data[p] <= 57 { goto st57 }
	goto st0
tr230:
// line 204 "zparse.rl"
	{ lines++ }
	goto st91
tr188:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st91
st91:
	p++
	if p == pe { goto _test_eof91 }
	fallthrough
case 91:
// line 1853 "zparse.go"
	if data[p] == 10 { goto tr230 }
	goto tr229
tr181:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st58
st58:
	p++
	if p == pe { goto _test_eof58 }
	fallthrough
case 58:
// line 1865 "zparse.go"
	if data[p] == 10 { goto tr183 }
	goto st58
tr169:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st59
st59:
	p++
	if p == pe { goto _test_eof59 }
	fallthrough
case 59:
// line 1877 "zparse.go"
	if data[p] == 10 { goto tr171 }
	goto st59
tr157:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st60
st60:
	p++
	if p == pe { goto _test_eof60 }
	fallthrough
case 60:
// line 1889 "zparse.go"
	if data[p] == 10 { goto tr159 }
	goto st60
tr145:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st61
st61:
	p++
	if p == pe { goto _test_eof61 }
	fallthrough
case 61:
// line 1901 "zparse.go"
	if data[p] == 10 { goto tr147 }
	goto st61
tr133:
// line 200 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
	goto st62
st62:
	p++
	if p == pe { goto _test_eof62 }
	fallthrough
case 62:
// line 1913 "zparse.go"
	if data[p] == 10 { goto tr135 }
	goto st62
tr121:
// line 200 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
	goto st63
st63:
	p++
	if p == pe { goto _test_eof63 }
	fallthrough
case 63:
// line 1925 "zparse.go"
	if data[p] == 10 { goto tr123 }
	goto st63
st64:
	p++
	if p == pe { goto _test_eof64 }
	fallthrough
case 64:
	if data[p] == 10 { goto tr111 }
	goto st64
tr26:
// line 194 "zparse.rl"
	{ mark = p }
	goto st65
st65:
	p++
	if p == pe { goto _test_eof65 }
	fallthrough
case 65:
// line 1944 "zparse.go"
	switch data[p] {
		case 72: goto st16
		case 78: goto st21
		case 83: goto st16
		case 104: goto st16
		case 110: goto st21
		case 115: goto st16
	}
	goto st0
tr27:
// line 194 "zparse.rl"
	{ mark = p }
	goto st66
st66:
	p++
	if p == pe { goto _test_eof66 }
	fallthrough
case 66:
// line 1963 "zparse.go"
	switch data[p] {
		case 83: goto st16
		case 115: goto st16
	}
	goto st0
tr28:
// line 194 "zparse.rl"
	{ mark = p }
	goto st67
st67:
	p++
	if p == pe { goto _test_eof67 }
	fallthrough
case 67:
// line 1978 "zparse.go"
	switch data[p] {
		case 78: goto st16
		case 110: goto st16
	}
	goto st0
tr30:
// line 194 "zparse.rl"
	{ mark = p }
	goto st68
st68:
	p++
	if p == pe { goto _test_eof68 }
	fallthrough
case 68:
// line 1993 "zparse.go"
	switch data[p] {
		case 79: goto st69
		case 83: goto st37
		case 111: goto st69
		case 115: goto st37
	}
	goto st0
st69:
	p++
	if p == pe { goto _test_eof69 }
	fallthrough
case 69:
	switch data[p] {
		case 78: goto st70
		case 110: goto st70
	}
	goto st0
st70:
	p++
	if p == pe { goto _test_eof70 }
	fallthrough
case 70:
	switch data[p] {
		case 69: goto st16
		case 101: goto st16
	}
	goto st0
tr218:
// line 195 "zparse.rl"
	{ hdr.Name = data[mark:p] }
	goto st71
st71:
	p++
	if p == pe { goto _test_eof71 }
	fallthrough
case 71:
// line 2030 "zparse.go"
	if data[p] == 10 { goto tr2 }
	goto st71
tr7:
// line 194 "zparse.rl"
	{ mark = p }
// line 197 "zparse.rl"
	{ /* ... */ }
	goto st72
st72:
	p++
	if p == pe { goto _test_eof72 }
	fallthrough
case 72:
// line 2044 "zparse.go"
	switch data[p] {
		case 9: goto st6
		case 10: goto tr33
		case 32: goto st6
		case 40: goto tr34
		case 41: goto tr35
		case 59: goto st8
		case 65: goto st9
		case 78: goto st73
		case 97: goto st9
		case 110: goto st73
	}
	goto st0
st73:
	p++
	if p == pe { goto _test_eof73 }
	fallthrough
case 73:
	switch data[p] {
		case 89: goto st74
		case 121: goto st74
	}
	goto st0
st74:
	p++
	if p == pe { goto _test_eof74 }
	fallthrough
case 74:
	switch data[p] {
		case 9: goto tr194
		case 10: goto tr195
		case 32: goto tr194
		case 40: goto tr196
		case 41: goto tr197
		case 59: goto tr198
	}
	goto st0
tr200:
// line 204 "zparse.rl"
	{ lines++ }
	goto st75
tr201:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st75
tr202:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st75
tr194:
// line 196 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st75
tr195:
// line 196 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 204 "zparse.rl"
	{ lines++ }
	goto st75
tr196:
// line 196 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st75
tr197:
// line 196 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st75
st75:
	p++
	if p == pe { goto _test_eof75 }
	fallthrough
case 75:
// line 2121 "zparse.go"
	switch data[p] {
		case 9: goto st75
		case 10: goto tr200
		case 32: goto st75
		case 40: goto tr201
		case 41: goto tr202
		case 59: goto st77
		case 65: goto tr63
		case 67: goto tr64
		case 77: goto tr29
		case 78: goto tr65
		case 83: goto tr31
		case 97: goto tr63
		case 99: goto tr64
		case 109: goto tr29
		case 110: goto tr65
		case 115: goto tr31
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr203 }
	goto st0
tr203:
// line 194 "zparse.rl"
	{ mark = p }
	goto st76
st76:
	p++
	if p == pe { goto _test_eof76 }
	fallthrough
case 76:
// line 2151 "zparse.go"
	switch data[p] {
		case 9: goto tr205
		case 10: goto tr206
		case 32: goto tr205
		case 40: goto tr207
		case 41: goto tr208
		case 59: goto tr210
	}
	if 48 <= data[p] && data[p] <= 57 { goto st76 }
	goto st0
tr198:
// line 196 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st77
st77:
	p++
	if p == pe { goto _test_eof77 }
	fallthrough
case 77:
// line 2171 "zparse.go"
	if data[p] == 10 { goto tr200 }
	goto st77
tr8:
// line 194 "zparse.rl"
	{ mark = p }
// line 197 "zparse.rl"
	{ /* ... */ }
	goto st78
st78:
	p++
	if p == pe { goto _test_eof78 }
	fallthrough
case 78:
// line 2185 "zparse.go"
	switch data[p] {
		case 72: goto st74
		case 78: goto st21
		case 83: goto st74
		case 104: goto st74
		case 110: goto st21
		case 115: goto st74
	}
	goto st0
tr9:
// line 194 "zparse.rl"
	{ mark = p }
// line 197 "zparse.rl"
	{ /* ... */ }
	goto st79
st79:
	p++
	if p == pe { goto _test_eof79 }
	fallthrough
case 79:
// line 2206 "zparse.go"
	switch data[p] {
		case 83: goto st74
		case 115: goto st74
	}
	goto st0
tr10:
// line 194 "zparse.rl"
	{ mark = p }
// line 197 "zparse.rl"
	{ /* ... */ }
	goto st80
st80:
	p++
	if p == pe { goto _test_eof80 }
	fallthrough
case 80:
// line 2223 "zparse.go"
	switch data[p] {
		case 78: goto st74
		case 110: goto st74
	}
	goto st0
tr12:
// line 194 "zparse.rl"
	{ mark = p }
// line 197 "zparse.rl"
	{ /* ... */ }
	goto st81
st81:
	p++
	if p == pe { goto _test_eof81 }
	fallthrough
case 81:
// line 2240 "zparse.go"
	switch data[p] {
		case 79: goto st82
		case 83: goto st37
		case 111: goto st82
		case 115: goto st37
	}
	goto st0
st82:
	p++
	if p == pe { goto _test_eof82 }
	fallthrough
case 82:
	switch data[p] {
		case 78: goto st83
		case 110: goto st83
	}
	goto st0
st83:
	p++
	if p == pe { goto _test_eof83 }
	fallthrough
case 83:
	switch data[p] {
		case 69: goto st74
		case 101: goto st74
	}
	goto st0
st84:
	p++
	if p == pe { goto _test_eof84 }
	fallthrough
case 84:
	switch data[p] {
		case 9: goto tr213
		case 10: goto tr214
		case 32: goto tr213
		case 40: goto tr215
		case 41: goto tr216
		case 59: goto tr218
		case 95: goto st84
	}
	if data[p] < 48 {
		if 45 <= data[p] && data[p] <= 46 { goto st84 }
	} else if data[p] > 57 {
		if data[p] > 90 {
			if 97 <= data[p] && data[p] <= 122 { goto st84 }
		} else if data[p] >= 65 {
			goto st84
		}
	} else {
		goto st84
	}
	goto st0
	}
	_test_eof85: cs = 85; goto _test_eof; 
	_test_eof1: cs = 1; goto _test_eof; 
	_test_eof2: cs = 2; goto _test_eof; 
	_test_eof3: cs = 3; goto _test_eof; 
	_test_eof4: cs = 4; goto _test_eof; 
	_test_eof5: cs = 5; goto _test_eof; 
	_test_eof6: cs = 6; goto _test_eof; 
	_test_eof7: cs = 7; goto _test_eof; 
	_test_eof86: cs = 86; goto _test_eof; 
	_test_eof8: cs = 8; goto _test_eof; 
	_test_eof9: cs = 9; goto _test_eof; 
	_test_eof10: cs = 10; goto _test_eof; 
	_test_eof11: cs = 11; goto _test_eof; 
	_test_eof12: cs = 12; goto _test_eof; 
	_test_eof13: cs = 13; goto _test_eof; 
	_test_eof87: cs = 87; goto _test_eof; 
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
	_test_eof88: cs = 88; goto _test_eof; 
	_test_eof27: cs = 27; goto _test_eof; 
	_test_eof28: cs = 28; goto _test_eof; 
	_test_eof29: cs = 29; goto _test_eof; 
	_test_eof30: cs = 30; goto _test_eof; 
	_test_eof31: cs = 31; goto _test_eof; 
	_test_eof32: cs = 32; goto _test_eof; 
	_test_eof33: cs = 33; goto _test_eof; 
	_test_eof89: cs = 89; goto _test_eof; 
	_test_eof34: cs = 34; goto _test_eof; 
	_test_eof35: cs = 35; goto _test_eof; 
	_test_eof36: cs = 36; goto _test_eof; 
	_test_eof37: cs = 37; goto _test_eof; 
	_test_eof38: cs = 38; goto _test_eof; 
	_test_eof39: cs = 39; goto _test_eof; 
	_test_eof90: cs = 90; goto _test_eof; 
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
	_test_eof91: cs = 91; goto _test_eof; 
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

	_test_eof: {}
	if p == eof {
	switch cs {
	case 86: goto tr219
	case 87: goto tr221
	case 88: goto tr223
	case 89: goto tr225
	case 90: goto tr227
	case 91: goto tr229
	}
	}

	_out: {}
	}

// line 246 "zparse.rl"

        
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
