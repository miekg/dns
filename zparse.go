
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
var z_start int = 148
var z_first_final int = 148
var z_error int = 0

var z_en_main int = 148


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
tr425:
// line 236 "zparse.rl"
	{te = p;p--;{ rr = rdata_a(*hdr, tok); set(rr, z, tok); }}
	goto st148
tr427:
// line 239 "zparse.rl"
	{te = p;p--;{ rr = rdata_aaaa(*hdr, tok); set(rr, z, tok); }}
	goto st148
tr429:
// line 238 "zparse.rl"
	{te = p;p--;{ rr = rdata_cname(*hdr, tok); set(rr, z, tok); }}
	goto st148
tr431:
// line 243 "zparse.rl"
	{te = p;p--;{ rr = rdata_dnskey(*hdr, tok); set(rr, z, tok); }}
	goto st148
tr433:
// line 242 "zparse.rl"
	{te = p;p--;{ rr = rdata_ds(*hdr, tok); set(rr, z, tok); }}
	goto st148
tr435:
// line 240 "zparse.rl"
	{te = p;p--;{ rr = rdata_mx(*hdr, tok); set(rr, z, tok); }}
	goto st148
tr437:
// line 237 "zparse.rl"
	{te = p;p--;{ rr = rdata_ns(*hdr, tok); set(rr, z, tok); }}
	goto st148
tr439:
// line 244 "zparse.rl"
	{te = p;p--;{ rr = rdata_rrsig(*hdr, tok); set(rr, z, tok); }}
	goto st148
tr441:
// line 241 "zparse.rl"
	{te = p;p--;{ rr = rdata_soa(*hdr, tok); set(rr, z, tok); }}
	goto st148
st148:
// line 1 "NONE"
	{ts = 0;}
	p++
	if p == pe { goto _test_eof148 }
	fallthrough
case 148:
// line 1 "NONE"
	{ts = p;}
// line 260 "zparse.go"
	switch data[p] {
		case 9: goto st1
		case 10: goto tr2
		case 32: goto st1
		case 40: goto tr3
		case 41: goto tr4
		case 43: goto st147
		case 59: goto st134
		case 61: goto st147
		case 95: goto st147
	}
	if data[p] < 65 {
		if 45 <= data[p] && data[p] <= 57 { goto st147 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st147 }
	} else {
		goto st147
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
tr419:
// line 195 "zparse.rl"
	{ hdr.Name = data[mark:p] }
	goto st1
tr420:
// line 195 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 204 "zparse.rl"
	{ lines++ }
	goto st1
tr421:
// line 195 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st1
tr422:
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
// line 322 "zparse.go"
	switch data[p] {
		case 9: goto st1
		case 10: goto tr2
		case 32: goto st1
		case 40: goto tr3
		case 41: goto tr4
		case 59: goto st134
		case 65: goto tr7
		case 67: goto tr8
		case 68: goto tr9
		case 72: goto tr10
		case 73: goto tr11
		case 77: goto tr12
		case 78: goto tr13
		case 82: goto tr14
		case 83: goto tr15
		case 97: goto tr7
		case 99: goto tr8
		case 100: goto tr9
		case 104: goto tr10
		case 105: goto tr11
		case 109: goto tr12
		case 110: goto tr13
		case 114: goto tr14
		case 115: goto tr15
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
// line 362 "zparse.go"
	switch data[p] {
		case 9: goto tr16
		case 10: goto tr17
		case 32: goto tr16
		case 40: goto tr18
		case 41: goto tr19
		case 59: goto tr21
	}
	if 48 <= data[p] && data[p] <= 57 { goto st2 }
	goto st0
tr23:
// line 204 "zparse.rl"
	{ lines++ }
	goto st3
tr24:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st3
tr25:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st3
tr16:
// line 198 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st3
tr17:
// line 198 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st3
tr18:
// line 198 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st3
tr19:
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
// line 412 "zparse.go"
	switch data[p] {
		case 9: goto st3
		case 10: goto tr23
		case 32: goto st3
		case 40: goto tr24
		case 41: goto tr25
		case 59: goto st4
		case 65: goto tr27
		case 67: goto tr28
		case 68: goto tr29
		case 72: goto tr30
		case 73: goto tr31
		case 77: goto tr32
		case 78: goto tr33
		case 82: goto tr34
		case 83: goto tr35
		case 97: goto tr27
		case 99: goto tr28
		case 100: goto tr29
		case 104: goto tr30
		case 105: goto tr31
		case 109: goto tr32
		case 110: goto tr33
		case 114: goto tr34
		case 115: goto tr35
	}
	goto st0
tr21:
// line 198 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st4
st4:
	p++
	if p == pe { goto _test_eof4 }
	fallthrough
case 4:
// line 449 "zparse.go"
	if data[p] == 10 { goto tr23 }
	goto st4
tr27:
// line 194 "zparse.rl"
	{ mark = p }
	goto st5
st5:
	p++
	if p == pe { goto _test_eof5 }
	fallthrough
case 5:
// line 461 "zparse.go"
	switch data[p] {
		case 9: goto st6
		case 10: goto tr37
		case 32: goto st6
		case 40: goto tr38
		case 41: goto tr39
		case 59: goto st8
		case 65: goto st9
		case 78: goto st15
		case 97: goto st9
		case 110: goto st15
	}
	goto st0
tr37:
// line 204 "zparse.rl"
	{ lines++ }
	goto st6
tr38:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st6
tr39:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st6
st6:
	p++
	if p == pe { goto _test_eof6 }
	fallthrough
case 6:
// line 492 "zparse.go"
	switch data[p] {
		case 9: goto st6
		case 10: goto tr37
		case 32: goto st6
		case 40: goto tr38
		case 41: goto tr39
		case 43: goto tr43
		case 59: goto st8
		case 61: goto tr43
		case 95: goto tr43
	}
	if data[p] < 65 {
		if 45 <= data[p] && data[p] <= 58 { goto tr43 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr43 }
	} else {
		goto tr43
	}
	goto st0
tr43:
// line 194 "zparse.rl"
	{ mark = p }
	goto st7
st7:
	p++
	if p == pe { goto _test_eof7 }
	fallthrough
case 7:
// line 521 "zparse.go"
	switch data[p] {
		case 10: goto tr44
		case 43: goto st7
		case 61: goto st7
		case 95: goto st7
	}
	if data[p] < 65 {
		if 45 <= data[p] && data[p] <= 58 { goto st7 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st7 }
	} else {
		goto st7
	}
	goto st0
tr426:
// line 204 "zparse.rl"
	{ lines++ }
	goto st149
tr44:
// line 200 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st149
st149:
	p++
	if p == pe { goto _test_eof149 }
	fallthrough
case 149:
// line 551 "zparse.go"
	if data[p] == 10 { goto tr426 }
	goto tr425
st8:
	p++
	if p == pe { goto _test_eof8 }
	fallthrough
case 8:
	if data[p] == 10 { goto tr37 }
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
		case 10: goto tr49
		case 32: goto st12
		case 40: goto tr50
		case 41: goto tr51
		case 59: goto st14
	}
	goto st0
tr49:
// line 204 "zparse.rl"
	{ lines++ }
	goto st12
tr50:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st12
tr51:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st12
st12:
	p++
	if p == pe { goto _test_eof12 }
	fallthrough
case 12:
// line 612 "zparse.go"
	switch data[p] {
		case 9: goto st12
		case 10: goto tr49
		case 32: goto st12
		case 40: goto tr50
		case 41: goto tr51
		case 43: goto tr53
		case 59: goto st14
		case 61: goto tr53
		case 95: goto tr53
	}
	if data[p] < 65 {
		if 45 <= data[p] && data[p] <= 58 { goto tr53 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr53 }
	} else {
		goto tr53
	}
	goto st0
tr53:
// line 194 "zparse.rl"
	{ mark = p }
	goto st13
st13:
	p++
	if p == pe { goto _test_eof13 }
	fallthrough
case 13:
// line 641 "zparse.go"
	switch data[p] {
		case 10: goto tr54
		case 43: goto st13
		case 61: goto st13
		case 95: goto st13
	}
	if data[p] < 65 {
		if 45 <= data[p] && data[p] <= 58 { goto st13 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st13 }
	} else {
		goto st13
	}
	goto st0
tr428:
// line 204 "zparse.rl"
	{ lines++ }
	goto st150
tr54:
// line 200 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st150
st150:
	p++
	if p == pe { goto _test_eof150 }
	fallthrough
case 150:
// line 671 "zparse.go"
	if data[p] == 10 { goto tr428 }
	goto tr427
st14:
	p++
	if p == pe { goto _test_eof14 }
	fallthrough
case 14:
	if data[p] == 10 { goto tr49 }
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
		case 9: goto tr57
		case 10: goto tr58
		case 32: goto tr57
		case 40: goto tr59
		case 41: goto tr60
		case 59: goto tr61
	}
	goto st0
tr63:
// line 204 "zparse.rl"
	{ lines++ }
	goto st17
tr64:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st17
tr65:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st17
tr411:
// line 198 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st17
tr412:
// line 198 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st17
tr413:
// line 198 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st17
tr414:
// line 198 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st17
tr57:
// line 196 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st17
tr58:
// line 196 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 204 "zparse.rl"
	{ lines++ }
	goto st17
tr59:
// line 196 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st17
tr60:
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
// line 766 "zparse.go"
	switch data[p] {
		case 9: goto st17
		case 10: goto tr63
		case 32: goto st17
		case 40: goto tr64
		case 41: goto tr65
		case 59: goto st18
		case 65: goto tr67
		case 67: goto tr68
		case 68: goto tr29
		case 77: goto tr32
		case 78: goto tr69
		case 82: goto tr34
		case 83: goto tr35
		case 97: goto tr67
		case 99: goto tr68
		case 100: goto tr29
		case 109: goto tr32
		case 110: goto tr69
		case 114: goto tr34
		case 115: goto tr35
	}
	goto st0
tr416:
// line 198 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st18
tr61:
// line 196 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st18
st18:
	p++
	if p == pe { goto _test_eof18 }
	fallthrough
case 18:
// line 803 "zparse.go"
	if data[p] == 10 { goto tr63 }
	goto st18
tr67:
// line 194 "zparse.rl"
	{ mark = p }
	goto st19
st19:
	p++
	if p == pe { goto _test_eof19 }
	fallthrough
case 19:
// line 815 "zparse.go"
	switch data[p] {
		case 9: goto st6
		case 10: goto tr37
		case 32: goto st6
		case 40: goto tr38
		case 41: goto tr39
		case 59: goto st8
		case 65: goto st9
		case 97: goto st9
	}
	goto st0
tr68:
// line 194 "zparse.rl"
	{ mark = p }
	goto st20
st20:
	p++
	if p == pe { goto _test_eof20 }
	fallthrough
case 20:
// line 836 "zparse.go"
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
		case 10: goto tr75
		case 32: goto st25
		case 40: goto tr76
		case 41: goto tr77
		case 59: goto st27
	}
	goto st0
tr75:
// line 204 "zparse.rl"
	{ lines++ }
	goto st25
tr76:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st25
tr77:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st25
st25:
	p++
	if p == pe { goto _test_eof25 }
	fallthrough
case 25:
// line 903 "zparse.go"
	switch data[p] {
		case 9: goto st25
		case 10: goto tr75
		case 32: goto st25
		case 40: goto tr76
		case 41: goto tr77
		case 43: goto tr79
		case 59: goto st27
		case 61: goto tr79
		case 95: goto tr79
	}
	if data[p] < 65 {
		if 45 <= data[p] && data[p] <= 58 { goto tr79 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr79 }
	} else {
		goto tr79
	}
	goto st0
tr79:
// line 194 "zparse.rl"
	{ mark = p }
	goto st26
st26:
	p++
	if p == pe { goto _test_eof26 }
	fallthrough
case 26:
// line 932 "zparse.go"
	switch data[p] {
		case 10: goto tr80
		case 43: goto st26
		case 61: goto st26
		case 95: goto st26
	}
	if data[p] < 65 {
		if 45 <= data[p] && data[p] <= 58 { goto st26 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st26 }
	} else {
		goto st26
	}
	goto st0
tr430:
// line 204 "zparse.rl"
	{ lines++ }
	goto st151
tr80:
// line 200 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st151
st151:
	p++
	if p == pe { goto _test_eof151 }
	fallthrough
case 151:
// line 962 "zparse.go"
	if data[p] == 10 { goto tr430 }
	goto tr429
st27:
	p++
	if p == pe { goto _test_eof27 }
	fallthrough
case 27:
	if data[p] == 10 { goto tr75 }
	goto st27
tr9:
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
// line 987 "zparse.go"
	switch data[p] {
		case 78: goto st29
		case 83: goto st46
		case 110: goto st29
		case 115: goto st46
	}
	goto st0
st29:
	p++
	if p == pe { goto _test_eof29 }
	fallthrough
case 29:
	switch data[p] {
		case 83: goto st30
		case 115: goto st30
	}
	goto st0
st30:
	p++
	if p == pe { goto _test_eof30 }
	fallthrough
case 30:
	switch data[p] {
		case 75: goto st31
		case 107: goto st31
	}
	goto st0
st31:
	p++
	if p == pe { goto _test_eof31 }
	fallthrough
case 31:
	switch data[p] {
		case 69: goto st32
		case 101: goto st32
	}
	goto st0
st32:
	p++
	if p == pe { goto _test_eof32 }
	fallthrough
case 32:
	switch data[p] {
		case 89: goto st33
		case 121: goto st33
	}
	goto st0
st33:
	p++
	if p == pe { goto _test_eof33 }
	fallthrough
case 33:
	switch data[p] {
		case 9: goto st34
		case 10: goto tr89
		case 32: goto st34
		case 40: goto tr90
		case 41: goto tr91
		case 59: goto st45
	}
	goto st0
tr89:
// line 204 "zparse.rl"
	{ lines++ }
	goto st34
tr90:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st34
tr91:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st34
st34:
	p++
	if p == pe { goto _test_eof34 }
	fallthrough
case 34:
// line 1066 "zparse.go"
	switch data[p] {
		case 9: goto st34
		case 10: goto tr89
		case 32: goto st34
		case 40: goto tr90
		case 41: goto tr91
		case 59: goto st45
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr93 }
	goto st0
tr93:
// line 194 "zparse.rl"
	{ mark = p }
	goto st35
st35:
	p++
	if p == pe { goto _test_eof35 }
	fallthrough
case 35:
// line 1086 "zparse.go"
	switch data[p] {
		case 9: goto tr94
		case 10: goto tr95
		case 32: goto tr94
		case 40: goto tr96
		case 41: goto tr97
		case 59: goto tr99
	}
	if 48 <= data[p] && data[p] <= 57 { goto st35 }
	goto st0
tr101:
// line 204 "zparse.rl"
	{ lines++ }
	goto st36
tr102:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st36
tr103:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st36
tr94:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st36
tr95:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st36
tr96:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st36
tr97:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st36
st36:
	p++
	if p == pe { goto _test_eof36 }
	fallthrough
case 36:
// line 1136 "zparse.go"
	switch data[p] {
		case 9: goto st36
		case 10: goto tr101
		case 32: goto st36
		case 40: goto tr102
		case 41: goto tr103
		case 59: goto st44
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr104 }
	goto st0
tr104:
// line 194 "zparse.rl"
	{ mark = p }
	goto st37
st37:
	p++
	if p == pe { goto _test_eof37 }
	fallthrough
case 37:
// line 1156 "zparse.go"
	switch data[p] {
		case 9: goto tr106
		case 10: goto tr107
		case 32: goto tr106
		case 40: goto tr108
		case 41: goto tr109
		case 59: goto tr111
	}
	if 48 <= data[p] && data[p] <= 57 { goto st37 }
	goto st0
tr113:
// line 204 "zparse.rl"
	{ lines++ }
	goto st38
tr114:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st38
tr115:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st38
tr106:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st38
tr107:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st38
tr108:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st38
tr109:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st38
st38:
	p++
	if p == pe { goto _test_eof38 }
	fallthrough
case 38:
// line 1206 "zparse.go"
	switch data[p] {
		case 9: goto st38
		case 10: goto tr113
		case 32: goto st38
		case 40: goto tr114
		case 41: goto tr115
		case 59: goto st43
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr116 }
	goto st0
tr116:
// line 194 "zparse.rl"
	{ mark = p }
	goto st39
st39:
	p++
	if p == pe { goto _test_eof39 }
	fallthrough
case 39:
// line 1226 "zparse.go"
	switch data[p] {
		case 9: goto tr118
		case 10: goto tr119
		case 32: goto tr118
		case 40: goto tr120
		case 41: goto tr121
		case 59: goto tr123
	}
	if 48 <= data[p] && data[p] <= 57 { goto st39 }
	goto st0
tr125:
// line 204 "zparse.rl"
	{ lines++ }
	goto st40
tr126:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st40
tr127:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st40
tr118:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st40
tr119:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st40
tr120:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st40
tr121:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st40
st40:
	p++
	if p == pe { goto _test_eof40 }
	fallthrough
case 40:
// line 1276 "zparse.go"
	switch data[p] {
		case 9: goto st40
		case 10: goto tr125
		case 32: goto st40
		case 40: goto tr126
		case 41: goto tr127
		case 43: goto tr128
		case 59: goto st42
		case 61: goto tr128
		case 95: goto tr128
	}
	if data[p] < 65 {
		if 45 <= data[p] && data[p] <= 58 { goto tr128 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr128 }
	} else {
		goto tr128
	}
	goto st0
tr128:
// line 194 "zparse.rl"
	{ mark = p }
	goto st41
st41:
	p++
	if p == pe { goto _test_eof41 }
	fallthrough
case 41:
// line 1305 "zparse.go"
	switch data[p] {
		case 10: goto tr130
		case 43: goto st41
		case 61: goto st41
		case 95: goto st41
	}
	if data[p] < 65 {
		if 45 <= data[p] && data[p] <= 58 { goto st41 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st41 }
	} else {
		goto st41
	}
	goto st0
tr432:
// line 204 "zparse.rl"
	{ lines++ }
	goto st152
tr130:
// line 200 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st152
st152:
	p++
	if p == pe { goto _test_eof152 }
	fallthrough
case 152:
// line 1335 "zparse.go"
	if data[p] == 10 { goto tr432 }
	goto tr431
tr123:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st42
st42:
	p++
	if p == pe { goto _test_eof42 }
	fallthrough
case 42:
// line 1347 "zparse.go"
	if data[p] == 10 { goto tr125 }
	goto st42
tr111:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st43
st43:
	p++
	if p == pe { goto _test_eof43 }
	fallthrough
case 43:
// line 1359 "zparse.go"
	if data[p] == 10 { goto tr113 }
	goto st43
tr99:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st44
st44:
	p++
	if p == pe { goto _test_eof44 }
	fallthrough
case 44:
// line 1371 "zparse.go"
	if data[p] == 10 { goto tr101 }
	goto st44
st45:
	p++
	if p == pe { goto _test_eof45 }
	fallthrough
case 45:
	if data[p] == 10 { goto tr89 }
	goto st45
st46:
	p++
	if p == pe { goto _test_eof46 }
	fallthrough
case 46:
	switch data[p] {
		case 9: goto st47
		case 10: goto tr133
		case 32: goto st47
		case 40: goto tr134
		case 41: goto tr135
		case 59: goto st58
	}
	goto st0
tr133:
// line 204 "zparse.rl"
	{ lines++ }
	goto st47
tr134:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st47
tr135:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st47
st47:
	p++
	if p == pe { goto _test_eof47 }
	fallthrough
case 47:
// line 1412 "zparse.go"
	switch data[p] {
		case 9: goto st47
		case 10: goto tr133
		case 32: goto st47
		case 40: goto tr134
		case 41: goto tr135
		case 59: goto st58
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr137 }
	goto st0
tr137:
// line 194 "zparse.rl"
	{ mark = p }
	goto st48
st48:
	p++
	if p == pe { goto _test_eof48 }
	fallthrough
case 48:
// line 1432 "zparse.go"
	switch data[p] {
		case 9: goto tr138
		case 10: goto tr139
		case 32: goto tr138
		case 40: goto tr140
		case 41: goto tr141
		case 59: goto tr143
	}
	if 48 <= data[p] && data[p] <= 57 { goto st48 }
	goto st0
tr145:
// line 204 "zparse.rl"
	{ lines++ }
	goto st49
tr146:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st49
tr147:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st49
tr138:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st49
tr139:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st49
tr140:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st49
tr141:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st49
st49:
	p++
	if p == pe { goto _test_eof49 }
	fallthrough
case 49:
// line 1482 "zparse.go"
	switch data[p] {
		case 9: goto st49
		case 10: goto tr145
		case 32: goto st49
		case 40: goto tr146
		case 41: goto tr147
		case 59: goto st57
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr148 }
	goto st0
tr148:
// line 194 "zparse.rl"
	{ mark = p }
	goto st50
st50:
	p++
	if p == pe { goto _test_eof50 }
	fallthrough
case 50:
// line 1502 "zparse.go"
	switch data[p] {
		case 9: goto tr150
		case 10: goto tr151
		case 32: goto tr150
		case 40: goto tr152
		case 41: goto tr153
		case 59: goto tr155
	}
	if 48 <= data[p] && data[p] <= 57 { goto st50 }
	goto st0
tr157:
// line 204 "zparse.rl"
	{ lines++ }
	goto st51
tr158:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st51
tr159:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st51
tr150:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st51
tr151:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st51
tr152:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st51
tr153:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st51
st51:
	p++
	if p == pe { goto _test_eof51 }
	fallthrough
case 51:
// line 1552 "zparse.go"
	switch data[p] {
		case 9: goto st51
		case 10: goto tr157
		case 32: goto st51
		case 40: goto tr158
		case 41: goto tr159
		case 59: goto st56
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr160 }
	goto st0
tr160:
// line 194 "zparse.rl"
	{ mark = p }
	goto st52
st52:
	p++
	if p == pe { goto _test_eof52 }
	fallthrough
case 52:
// line 1572 "zparse.go"
	switch data[p] {
		case 9: goto tr162
		case 10: goto tr163
		case 32: goto tr162
		case 40: goto tr164
		case 41: goto tr165
		case 59: goto tr167
	}
	if 48 <= data[p] && data[p] <= 57 { goto st52 }
	goto st0
tr169:
// line 204 "zparse.rl"
	{ lines++ }
	goto st53
tr170:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st53
tr171:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st53
tr162:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st53
tr163:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st53
tr164:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st53
tr165:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st53
st53:
	p++
	if p == pe { goto _test_eof53 }
	fallthrough
case 53:
// line 1622 "zparse.go"
	switch data[p] {
		case 9: goto st53
		case 10: goto tr169
		case 32: goto st53
		case 40: goto tr170
		case 41: goto tr171
		case 43: goto tr172
		case 59: goto st55
		case 61: goto tr172
		case 95: goto tr172
	}
	if data[p] < 65 {
		if 45 <= data[p] && data[p] <= 58 { goto tr172 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr172 }
	} else {
		goto tr172
	}
	goto st0
tr172:
// line 194 "zparse.rl"
	{ mark = p }
	goto st54
st54:
	p++
	if p == pe { goto _test_eof54 }
	fallthrough
case 54:
// line 1651 "zparse.go"
	switch data[p] {
		case 10: goto tr174
		case 43: goto st54
		case 61: goto st54
		case 95: goto st54
	}
	if data[p] < 65 {
		if 45 <= data[p] && data[p] <= 58 { goto st54 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st54 }
	} else {
		goto st54
	}
	goto st0
tr434:
// line 204 "zparse.rl"
	{ lines++ }
	goto st153
tr174:
// line 200 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st153
st153:
	p++
	if p == pe { goto _test_eof153 }
	fallthrough
case 153:
// line 1681 "zparse.go"
	if data[p] == 10 { goto tr434 }
	goto tr433
tr167:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st55
st55:
	p++
	if p == pe { goto _test_eof55 }
	fallthrough
case 55:
// line 1693 "zparse.go"
	if data[p] == 10 { goto tr169 }
	goto st55
tr155:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st56
st56:
	p++
	if p == pe { goto _test_eof56 }
	fallthrough
case 56:
// line 1705 "zparse.go"
	if data[p] == 10 { goto tr157 }
	goto st56
tr143:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st57
st57:
	p++
	if p == pe { goto _test_eof57 }
	fallthrough
case 57:
// line 1717 "zparse.go"
	if data[p] == 10 { goto tr145 }
	goto st57
st58:
	p++
	if p == pe { goto _test_eof58 }
	fallthrough
case 58:
	if data[p] == 10 { goto tr133 }
	goto st58
tr12:
// line 194 "zparse.rl"
	{ mark = p }
// line 197 "zparse.rl"
	{ /* ... */ }
	goto st59
tr32:
// line 194 "zparse.rl"
	{ mark = p }
	goto st59
st59:
	p++
	if p == pe { goto _test_eof59 }
	fallthrough
case 59:
// line 1742 "zparse.go"
	switch data[p] {
		case 88: goto st60
		case 120: goto st60
	}
	goto st0
st60:
	p++
	if p == pe { goto _test_eof60 }
	fallthrough
case 60:
	switch data[p] {
		case 9: goto st61
		case 10: goto tr178
		case 32: goto st61
		case 40: goto tr179
		case 41: goto tr180
		case 59: goto st66
	}
	goto st0
tr178:
// line 204 "zparse.rl"
	{ lines++ }
	goto st61
tr179:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st61
tr180:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st61
st61:
	p++
	if p == pe { goto _test_eof61 }
	fallthrough
case 61:
// line 1779 "zparse.go"
	switch data[p] {
		case 9: goto st61
		case 10: goto tr178
		case 32: goto st61
		case 40: goto tr179
		case 41: goto tr180
		case 59: goto st66
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr182 }
	goto st0
tr182:
// line 194 "zparse.rl"
	{ mark = p }
	goto st62
st62:
	p++
	if p == pe { goto _test_eof62 }
	fallthrough
case 62:
// line 1799 "zparse.go"
	switch data[p] {
		case 9: goto tr183
		case 10: goto tr184
		case 32: goto tr183
		case 40: goto tr185
		case 41: goto tr186
		case 59: goto tr188
	}
	if 48 <= data[p] && data[p] <= 57 { goto st62 }
	goto st0
tr190:
// line 204 "zparse.rl"
	{ lines++ }
	goto st63
tr191:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st63
tr192:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st63
tr183:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st63
tr184:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st63
tr185:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st63
tr186:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st63
st63:
	p++
	if p == pe { goto _test_eof63 }
	fallthrough
case 63:
// line 1849 "zparse.go"
	switch data[p] {
		case 9: goto st63
		case 10: goto tr190
		case 32: goto st63
		case 40: goto tr191
		case 41: goto tr192
		case 43: goto tr193
		case 59: goto st65
		case 61: goto tr193
		case 95: goto tr193
	}
	if data[p] < 65 {
		if 45 <= data[p] && data[p] <= 58 { goto tr193 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr193 }
	} else {
		goto tr193
	}
	goto st0
tr193:
// line 194 "zparse.rl"
	{ mark = p }
	goto st64
st64:
	p++
	if p == pe { goto _test_eof64 }
	fallthrough
case 64:
// line 1878 "zparse.go"
	switch data[p] {
		case 10: goto tr195
		case 43: goto st64
		case 61: goto st64
		case 95: goto st64
	}
	if data[p] < 65 {
		if 45 <= data[p] && data[p] <= 58 { goto st64 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st64 }
	} else {
		goto st64
	}
	goto st0
tr436:
// line 204 "zparse.rl"
	{ lines++ }
	goto st154
tr195:
// line 200 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st154
st154:
	p++
	if p == pe { goto _test_eof154 }
	fallthrough
case 154:
// line 1908 "zparse.go"
	if data[p] == 10 { goto tr436 }
	goto tr435
tr188:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st65
st65:
	p++
	if p == pe { goto _test_eof65 }
	fallthrough
case 65:
// line 1920 "zparse.go"
	if data[p] == 10 { goto tr190 }
	goto st65
st66:
	p++
	if p == pe { goto _test_eof66 }
	fallthrough
case 66:
	if data[p] == 10 { goto tr178 }
	goto st66
tr69:
// line 194 "zparse.rl"
	{ mark = p }
	goto st67
st67:
	p++
	if p == pe { goto _test_eof67 }
	fallthrough
case 67:
// line 1939 "zparse.go"
	switch data[p] {
		case 83: goto st68
		case 115: goto st68
	}
	goto st0
st68:
	p++
	if p == pe { goto _test_eof68 }
	fallthrough
case 68:
	switch data[p] {
		case 9: goto st69
		case 10: goto tr199
		case 32: goto st69
		case 40: goto tr200
		case 41: goto tr201
		case 59: goto st71
	}
	goto st0
tr199:
// line 204 "zparse.rl"
	{ lines++ }
	goto st69
tr200:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st69
tr201:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st69
st69:
	p++
	if p == pe { goto _test_eof69 }
	fallthrough
case 69:
// line 1976 "zparse.go"
	switch data[p] {
		case 9: goto st69
		case 10: goto tr199
		case 32: goto st69
		case 40: goto tr200
		case 41: goto tr201
		case 43: goto tr203
		case 59: goto st71
		case 61: goto tr203
		case 95: goto tr203
	}
	if data[p] < 65 {
		if 45 <= data[p] && data[p] <= 58 { goto tr203 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr203 }
	} else {
		goto tr203
	}
	goto st0
tr203:
// line 194 "zparse.rl"
	{ mark = p }
	goto st70
st70:
	p++
	if p == pe { goto _test_eof70 }
	fallthrough
case 70:
// line 2005 "zparse.go"
	switch data[p] {
		case 10: goto tr204
		case 43: goto st70
		case 61: goto st70
		case 95: goto st70
	}
	if data[p] < 65 {
		if 45 <= data[p] && data[p] <= 58 { goto st70 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st70 }
	} else {
		goto st70
	}
	goto st0
tr438:
// line 204 "zparse.rl"
	{ lines++ }
	goto st155
tr204:
// line 200 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st155
st155:
	p++
	if p == pe { goto _test_eof155 }
	fallthrough
case 155:
// line 2035 "zparse.go"
	if data[p] == 10 { goto tr438 }
	goto tr437
st71:
	p++
	if p == pe { goto _test_eof71 }
	fallthrough
case 71:
	if data[p] == 10 { goto tr199 }
	goto st71
tr14:
// line 194 "zparse.rl"
	{ mark = p }
// line 197 "zparse.rl"
	{ /* ... */ }
	goto st72
tr34:
// line 194 "zparse.rl"
	{ mark = p }
	goto st72
st72:
	p++
	if p == pe { goto _test_eof72 }
	fallthrough
case 72:
// line 2060 "zparse.go"
	switch data[p] {
		case 82: goto st73
		case 114: goto st73
	}
	goto st0
st73:
	p++
	if p == pe { goto _test_eof73 }
	fallthrough
case 73:
	switch data[p] {
		case 83: goto st74
		case 115: goto st74
	}
	goto st0
st74:
	p++
	if p == pe { goto _test_eof74 }
	fallthrough
case 74:
	switch data[p] {
		case 73: goto st75
		case 105: goto st75
	}
	goto st0
st75:
	p++
	if p == pe { goto _test_eof75 }
	fallthrough
case 75:
	switch data[p] {
		case 71: goto st76
		case 103: goto st76
	}
	goto st0
st76:
	p++
	if p == pe { goto _test_eof76 }
	fallthrough
case 76:
	switch data[p] {
		case 9: goto st77
		case 10: goto tr211
		case 32: goto st77
		case 40: goto tr212
		case 41: goto tr213
		case 59: goto st103
	}
	goto st0
tr211:
// line 204 "zparse.rl"
	{ lines++ }
	goto st77
tr212:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st77
tr213:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st77
st77:
	p++
	if p == pe { goto _test_eof77 }
	fallthrough
case 77:
// line 2127 "zparse.go"
	switch data[p] {
		case 9: goto st77
		case 10: goto tr211
		case 32: goto st77
		case 40: goto tr212
		case 41: goto tr213
		case 59: goto st103
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr215 }
	goto st0
tr215:
// line 194 "zparse.rl"
	{ mark = p }
	goto st78
st78:
	p++
	if p == pe { goto _test_eof78 }
	fallthrough
case 78:
// line 2147 "zparse.go"
	switch data[p] {
		case 9: goto tr216
		case 10: goto tr217
		case 32: goto tr216
		case 40: goto tr218
		case 41: goto tr219
		case 59: goto tr221
	}
	if 48 <= data[p] && data[p] <= 57 { goto st78 }
	goto st0
tr223:
// line 204 "zparse.rl"
	{ lines++ }
	goto st79
tr224:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st79
tr225:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st79
tr216:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st79
tr217:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st79
tr218:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st79
tr219:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st79
st79:
	p++
	if p == pe { goto _test_eof79 }
	fallthrough
case 79:
// line 2197 "zparse.go"
	switch data[p] {
		case 9: goto st79
		case 10: goto tr223
		case 32: goto st79
		case 40: goto tr224
		case 41: goto tr225
		case 59: goto st102
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr226 }
	goto st0
tr226:
// line 194 "zparse.rl"
	{ mark = p }
	goto st80
st80:
	p++
	if p == pe { goto _test_eof80 }
	fallthrough
case 80:
// line 2217 "zparse.go"
	switch data[p] {
		case 9: goto tr228
		case 10: goto tr229
		case 32: goto tr228
		case 40: goto tr230
		case 41: goto tr231
		case 59: goto tr233
	}
	if 48 <= data[p] && data[p] <= 57 { goto st80 }
	goto st0
tr235:
// line 204 "zparse.rl"
	{ lines++ }
	goto st81
tr236:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st81
tr237:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st81
tr228:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st81
tr229:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st81
tr230:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st81
tr231:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st81
st81:
	p++
	if p == pe { goto _test_eof81 }
	fallthrough
case 81:
// line 2267 "zparse.go"
	switch data[p] {
		case 9: goto st81
		case 10: goto tr235
		case 32: goto st81
		case 40: goto tr236
		case 41: goto tr237
		case 59: goto st101
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr238 }
	goto st0
tr238:
// line 194 "zparse.rl"
	{ mark = p }
	goto st82
st82:
	p++
	if p == pe { goto _test_eof82 }
	fallthrough
case 82:
// line 2287 "zparse.go"
	switch data[p] {
		case 9: goto tr240
		case 10: goto tr241
		case 32: goto tr240
		case 40: goto tr242
		case 41: goto tr243
		case 59: goto tr245
	}
	if 48 <= data[p] && data[p] <= 57 { goto st82 }
	goto st0
tr247:
// line 204 "zparse.rl"
	{ lines++ }
	goto st83
tr248:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st83
tr249:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st83
tr240:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st83
tr241:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st83
tr242:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st83
tr243:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st83
st83:
	p++
	if p == pe { goto _test_eof83 }
	fallthrough
case 83:
// line 2337 "zparse.go"
	switch data[p] {
		case 9: goto st83
		case 10: goto tr247
		case 32: goto st83
		case 40: goto tr248
		case 41: goto tr249
		case 59: goto st100
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr250 }
	goto st0
tr250:
// line 194 "zparse.rl"
	{ mark = p }
	goto st84
st84:
	p++
	if p == pe { goto _test_eof84 }
	fallthrough
case 84:
// line 2357 "zparse.go"
	switch data[p] {
		case 9: goto tr252
		case 10: goto tr253
		case 32: goto tr252
		case 40: goto tr254
		case 41: goto tr255
		case 59: goto tr257
	}
	if 48 <= data[p] && data[p] <= 57 { goto st84 }
	goto st0
tr259:
// line 204 "zparse.rl"
	{ lines++ }
	goto st85
tr260:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st85
tr261:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st85
tr252:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st85
tr253:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st85
tr254:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st85
tr255:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st85
st85:
	p++
	if p == pe { goto _test_eof85 }
	fallthrough
case 85:
// line 2407 "zparse.go"
	switch data[p] {
		case 9: goto st85
		case 10: goto tr259
		case 32: goto st85
		case 40: goto tr260
		case 41: goto tr261
		case 59: goto st99
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr262 }
	goto st0
tr262:
// line 194 "zparse.rl"
	{ mark = p }
	goto st86
st86:
	p++
	if p == pe { goto _test_eof86 }
	fallthrough
case 86:
// line 2427 "zparse.go"
	switch data[p] {
		case 9: goto tr264
		case 10: goto tr265
		case 32: goto tr264
		case 40: goto tr266
		case 41: goto tr267
		case 59: goto tr269
	}
	if 48 <= data[p] && data[p] <= 57 { goto st86 }
	goto st0
tr271:
// line 204 "zparse.rl"
	{ lines++ }
	goto st87
tr272:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st87
tr273:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st87
tr264:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st87
tr265:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st87
tr266:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st87
tr267:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st87
st87:
	p++
	if p == pe { goto _test_eof87 }
	fallthrough
case 87:
// line 2477 "zparse.go"
	switch data[p] {
		case 9: goto st87
		case 10: goto tr271
		case 32: goto st87
		case 40: goto tr272
		case 41: goto tr273
		case 59: goto st98
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr274 }
	goto st0
tr274:
// line 194 "zparse.rl"
	{ mark = p }
	goto st88
st88:
	p++
	if p == pe { goto _test_eof88 }
	fallthrough
case 88:
// line 2497 "zparse.go"
	switch data[p] {
		case 9: goto tr276
		case 10: goto tr277
		case 32: goto tr276
		case 40: goto tr278
		case 41: goto tr279
		case 59: goto tr281
	}
	if 48 <= data[p] && data[p] <= 57 { goto st88 }
	goto st0
tr283:
// line 204 "zparse.rl"
	{ lines++ }
	goto st89
tr284:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st89
tr285:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st89
tr276:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st89
tr277:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st89
tr278:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st89
tr279:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st89
st89:
	p++
	if p == pe { goto _test_eof89 }
	fallthrough
case 89:
// line 2547 "zparse.go"
	switch data[p] {
		case 9: goto st89
		case 10: goto tr283
		case 32: goto st89
		case 40: goto tr284
		case 41: goto tr285
		case 59: goto st97
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr286 }
	goto st0
tr286:
// line 194 "zparse.rl"
	{ mark = p }
	goto st90
st90:
	p++
	if p == pe { goto _test_eof90 }
	fallthrough
case 90:
// line 2567 "zparse.go"
	switch data[p] {
		case 9: goto tr288
		case 10: goto tr289
		case 32: goto tr288
		case 40: goto tr290
		case 41: goto tr291
		case 59: goto tr293
	}
	if 48 <= data[p] && data[p] <= 57 { goto st90 }
	goto st0
tr295:
// line 204 "zparse.rl"
	{ lines++ }
	goto st91
tr296:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st91
tr297:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st91
tr288:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st91
tr289:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st91
tr290:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st91
tr291:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st91
st91:
	p++
	if p == pe { goto _test_eof91 }
	fallthrough
case 91:
// line 2617 "zparse.go"
	switch data[p] {
		case 9: goto st91
		case 10: goto tr295
		case 32: goto st91
		case 40: goto tr296
		case 41: goto tr297
		case 43: goto tr298
		case 59: goto st96
		case 61: goto tr298
		case 95: goto tr298
	}
	if data[p] < 65 {
		if 45 <= data[p] && data[p] <= 58 { goto tr298 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr298 }
	} else {
		goto tr298
	}
	goto st0
tr298:
// line 194 "zparse.rl"
	{ mark = p }
	goto st92
st92:
	p++
	if p == pe { goto _test_eof92 }
	fallthrough
case 92:
// line 2646 "zparse.go"
	switch data[p] {
		case 9: goto tr300
		case 10: goto tr301
		case 32: goto tr300
		case 40: goto tr302
		case 41: goto tr303
		case 43: goto st92
		case 59: goto tr305
		case 61: goto st92
		case 95: goto st92
	}
	if data[p] < 65 {
		if 45 <= data[p] && data[p] <= 58 { goto st92 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st92 }
	} else {
		goto st92
	}
	goto st0
tr307:
// line 204 "zparse.rl"
	{ lines++ }
	goto st93
tr308:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st93
tr309:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st93
tr301:
// line 200 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st93
tr300:
// line 200 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
	goto st93
tr302:
// line 200 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st93
tr303:
// line 200 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st93
st93:
	p++
	if p == pe { goto _test_eof93 }
	fallthrough
case 93:
// line 2705 "zparse.go"
	switch data[p] {
		case 9: goto st93
		case 10: goto tr307
		case 32: goto st93
		case 40: goto tr308
		case 41: goto tr309
		case 43: goto tr310
		case 59: goto st95
		case 61: goto tr310
		case 95: goto tr310
	}
	if data[p] < 65 {
		if 45 <= data[p] && data[p] <= 58 { goto tr310 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr310 }
	} else {
		goto tr310
	}
	goto st0
tr310:
// line 194 "zparse.rl"
	{ mark = p }
	goto st94
st94:
	p++
	if p == pe { goto _test_eof94 }
	fallthrough
case 94:
// line 2734 "zparse.go"
	switch data[p] {
		case 10: goto tr312
		case 43: goto st94
		case 61: goto st94
		case 95: goto st94
	}
	if data[p] < 65 {
		if 45 <= data[p] && data[p] <= 58 { goto st94 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st94 }
	} else {
		goto st94
	}
	goto st0
tr440:
// line 204 "zparse.rl"
	{ lines++ }
	goto st156
tr312:
// line 200 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st156
st156:
	p++
	if p == pe { goto _test_eof156 }
	fallthrough
case 156:
// line 2764 "zparse.go"
	if data[p] == 10 { goto tr440 }
	goto tr439
tr305:
// line 200 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
	goto st95
st95:
	p++
	if p == pe { goto _test_eof95 }
	fallthrough
case 95:
// line 2776 "zparse.go"
	if data[p] == 10 { goto tr307 }
	goto st95
tr293:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st96
st96:
	p++
	if p == pe { goto _test_eof96 }
	fallthrough
case 96:
// line 2788 "zparse.go"
	if data[p] == 10 { goto tr295 }
	goto st96
tr281:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st97
st97:
	p++
	if p == pe { goto _test_eof97 }
	fallthrough
case 97:
// line 2800 "zparse.go"
	if data[p] == 10 { goto tr283 }
	goto st97
tr269:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st98
st98:
	p++
	if p == pe { goto _test_eof98 }
	fallthrough
case 98:
// line 2812 "zparse.go"
	if data[p] == 10 { goto tr271 }
	goto st98
tr257:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st99
st99:
	p++
	if p == pe { goto _test_eof99 }
	fallthrough
case 99:
// line 2824 "zparse.go"
	if data[p] == 10 { goto tr259 }
	goto st99
tr245:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st100
st100:
	p++
	if p == pe { goto _test_eof100 }
	fallthrough
case 100:
// line 2836 "zparse.go"
	if data[p] == 10 { goto tr247 }
	goto st100
tr233:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st101
st101:
	p++
	if p == pe { goto _test_eof101 }
	fallthrough
case 101:
// line 2848 "zparse.go"
	if data[p] == 10 { goto tr235 }
	goto st101
tr221:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st102
st102:
	p++
	if p == pe { goto _test_eof102 }
	fallthrough
case 102:
// line 2860 "zparse.go"
	if data[p] == 10 { goto tr223 }
	goto st102
st103:
	p++
	if p == pe { goto _test_eof103 }
	fallthrough
case 103:
	if data[p] == 10 { goto tr211 }
	goto st103
tr15:
// line 194 "zparse.rl"
	{ mark = p }
// line 197 "zparse.rl"
	{ /* ... */ }
	goto st104
tr35:
// line 194 "zparse.rl"
	{ mark = p }
	goto st104
st104:
	p++
	if p == pe { goto _test_eof104 }
	fallthrough
case 104:
// line 2885 "zparse.go"
	switch data[p] {
		case 79: goto st105
		case 111: goto st105
	}
	goto st0
st105:
	p++
	if p == pe { goto _test_eof105 }
	fallthrough
case 105:
	switch data[p] {
		case 65: goto st106
		case 97: goto st106
	}
	goto st0
st106:
	p++
	if p == pe { goto _test_eof106 }
	fallthrough
case 106:
	switch data[p] {
		case 9: goto st107
		case 10: goto tr317
		case 32: goto st107
		case 40: goto tr318
		case 41: goto tr319
		case 59: goto st127
	}
	goto st0
tr317:
// line 204 "zparse.rl"
	{ lines++ }
	goto st107
tr318:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st107
tr319:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st107
st107:
	p++
	if p == pe { goto _test_eof107 }
	fallthrough
case 107:
// line 2932 "zparse.go"
	switch data[p] {
		case 9: goto st107
		case 10: goto tr317
		case 32: goto st107
		case 40: goto tr318
		case 41: goto tr319
		case 43: goto tr321
		case 59: goto st127
		case 61: goto tr321
		case 95: goto tr321
	}
	if data[p] < 65 {
		if 45 <= data[p] && data[p] <= 58 { goto tr321 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr321 }
	} else {
		goto tr321
	}
	goto st0
tr321:
// line 194 "zparse.rl"
	{ mark = p }
	goto st108
st108:
	p++
	if p == pe { goto _test_eof108 }
	fallthrough
case 108:
// line 2961 "zparse.go"
	switch data[p] {
		case 9: goto tr322
		case 10: goto tr323
		case 32: goto tr322
		case 40: goto tr324
		case 41: goto tr325
		case 43: goto st108
		case 59: goto tr327
		case 61: goto st108
		case 95: goto st108
	}
	if data[p] < 65 {
		if 45 <= data[p] && data[p] <= 58 { goto st108 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st108 }
	} else {
		goto st108
	}
	goto st0
tr329:
// line 204 "zparse.rl"
	{ lines++ }
	goto st109
tr330:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st109
tr331:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st109
tr323:
// line 200 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st109
tr322:
// line 200 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
	goto st109
tr324:
// line 200 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st109
tr325:
// line 200 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st109
st109:
	p++
	if p == pe { goto _test_eof109 }
	fallthrough
case 109:
// line 3020 "zparse.go"
	switch data[p] {
		case 9: goto st109
		case 10: goto tr329
		case 32: goto st109
		case 40: goto tr330
		case 41: goto tr331
		case 43: goto tr332
		case 59: goto st126
		case 61: goto tr332
		case 95: goto tr332
	}
	if data[p] < 65 {
		if 45 <= data[p] && data[p] <= 58 { goto tr332 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr332 }
	} else {
		goto tr332
	}
	goto st0
tr332:
// line 194 "zparse.rl"
	{ mark = p }
	goto st110
st110:
	p++
	if p == pe { goto _test_eof110 }
	fallthrough
case 110:
// line 3049 "zparse.go"
	switch data[p] {
		case 9: goto tr334
		case 10: goto tr335
		case 32: goto tr334
		case 40: goto tr336
		case 41: goto tr337
		case 43: goto st110
		case 59: goto tr339
		case 61: goto st110
		case 95: goto st110
	}
	if data[p] < 65 {
		if 45 <= data[p] && data[p] <= 58 { goto st110 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st110 }
	} else {
		goto st110
	}
	goto st0
tr341:
// line 204 "zparse.rl"
	{ lines++ }
	goto st111
tr342:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st111
tr343:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st111
tr335:
// line 200 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st111
tr334:
// line 200 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
	goto st111
tr336:
// line 200 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st111
tr337:
// line 200 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st111
st111:
	p++
	if p == pe { goto _test_eof111 }
	fallthrough
case 111:
// line 3108 "zparse.go"
	switch data[p] {
		case 9: goto st111
		case 10: goto tr341
		case 32: goto st111
		case 40: goto tr342
		case 41: goto tr343
		case 59: goto st125
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr344 }
	goto st0
tr344:
// line 194 "zparse.rl"
	{ mark = p }
	goto st112
st112:
	p++
	if p == pe { goto _test_eof112 }
	fallthrough
case 112:
// line 3128 "zparse.go"
	switch data[p] {
		case 9: goto tr346
		case 10: goto tr347
		case 32: goto tr346
		case 40: goto tr348
		case 41: goto tr349
		case 59: goto tr351
	}
	if 48 <= data[p] && data[p] <= 57 { goto st112 }
	goto st0
tr353:
// line 204 "zparse.rl"
	{ lines++ }
	goto st113
tr354:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st113
tr355:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st113
tr346:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st113
tr347:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st113
tr348:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st113
tr349:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st113
st113:
	p++
	if p == pe { goto _test_eof113 }
	fallthrough
case 113:
// line 3178 "zparse.go"
	switch data[p] {
		case 9: goto st113
		case 10: goto tr353
		case 32: goto st113
		case 40: goto tr354
		case 41: goto tr355
		case 59: goto st124
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr356 }
	goto st0
tr356:
// line 194 "zparse.rl"
	{ mark = p }
	goto st114
st114:
	p++
	if p == pe { goto _test_eof114 }
	fallthrough
case 114:
// line 3198 "zparse.go"
	switch data[p] {
		case 9: goto tr358
		case 10: goto tr359
		case 32: goto tr358
		case 40: goto tr360
		case 41: goto tr361
		case 59: goto tr363
	}
	if 48 <= data[p] && data[p] <= 57 { goto st114 }
	goto st0
tr365:
// line 204 "zparse.rl"
	{ lines++ }
	goto st115
tr366:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st115
tr367:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st115
tr358:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st115
tr359:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st115
tr360:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st115
tr361:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st115
st115:
	p++
	if p == pe { goto _test_eof115 }
	fallthrough
case 115:
// line 3248 "zparse.go"
	switch data[p] {
		case 9: goto st115
		case 10: goto tr365
		case 32: goto st115
		case 40: goto tr366
		case 41: goto tr367
		case 59: goto st123
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr368 }
	goto st0
tr368:
// line 194 "zparse.rl"
	{ mark = p }
	goto st116
st116:
	p++
	if p == pe { goto _test_eof116 }
	fallthrough
case 116:
// line 3268 "zparse.go"
	switch data[p] {
		case 9: goto tr370
		case 10: goto tr371
		case 32: goto tr370
		case 40: goto tr372
		case 41: goto tr373
		case 59: goto tr375
	}
	if 48 <= data[p] && data[p] <= 57 { goto st116 }
	goto st0
tr377:
// line 204 "zparse.rl"
	{ lines++ }
	goto st117
tr378:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st117
tr379:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st117
tr370:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st117
tr371:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st117
tr372:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st117
tr373:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st117
st117:
	p++
	if p == pe { goto _test_eof117 }
	fallthrough
case 117:
// line 3318 "zparse.go"
	switch data[p] {
		case 9: goto st117
		case 10: goto tr377
		case 32: goto st117
		case 40: goto tr378
		case 41: goto tr379
		case 59: goto st122
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr380 }
	goto st0
tr380:
// line 194 "zparse.rl"
	{ mark = p }
	goto st118
st118:
	p++
	if p == pe { goto _test_eof118 }
	fallthrough
case 118:
// line 3338 "zparse.go"
	switch data[p] {
		case 9: goto tr382
		case 10: goto tr383
		case 32: goto tr382
		case 40: goto tr384
		case 41: goto tr385
		case 59: goto tr387
	}
	if 48 <= data[p] && data[p] <= 57 { goto st118 }
	goto st0
tr389:
// line 204 "zparse.rl"
	{ lines++ }
	goto st119
tr390:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st119
tr391:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st119
tr382:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st119
tr383:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st119
tr384:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st119
tr385:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st119
st119:
	p++
	if p == pe { goto _test_eof119 }
	fallthrough
case 119:
// line 3388 "zparse.go"
	switch data[p] {
		case 9: goto st119
		case 10: goto tr389
		case 32: goto st119
		case 40: goto tr390
		case 41: goto tr391
		case 59: goto st121
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr392 }
	goto st0
tr392:
// line 194 "zparse.rl"
	{ mark = p }
	goto st120
st120:
	p++
	if p == pe { goto _test_eof120 }
	fallthrough
case 120:
// line 3408 "zparse.go"
	if data[p] == 10 { goto tr394 }
	if 48 <= data[p] && data[p] <= 57 { goto st120 }
	goto st0
tr442:
// line 204 "zparse.rl"
	{ lines++ }
	goto st157
tr394:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 204 "zparse.rl"
	{ lines++ }
	goto st157
st157:
	p++
	if p == pe { goto _test_eof157 }
	fallthrough
case 157:
// line 3427 "zparse.go"
	if data[p] == 10 { goto tr442 }
	goto tr441
tr387:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st121
st121:
	p++
	if p == pe { goto _test_eof121 }
	fallthrough
case 121:
// line 3439 "zparse.go"
	if data[p] == 10 { goto tr389 }
	goto st121
tr375:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st122
st122:
	p++
	if p == pe { goto _test_eof122 }
	fallthrough
case 122:
// line 3451 "zparse.go"
	if data[p] == 10 { goto tr377 }
	goto st122
tr363:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st123
st123:
	p++
	if p == pe { goto _test_eof123 }
	fallthrough
case 123:
// line 3463 "zparse.go"
	if data[p] == 10 { goto tr365 }
	goto st123
tr351:
// line 199 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st124
st124:
	p++
	if p == pe { goto _test_eof124 }
	fallthrough
case 124:
// line 3475 "zparse.go"
	if data[p] == 10 { goto tr353 }
	goto st124
tr339:
// line 200 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
	goto st125
st125:
	p++
	if p == pe { goto _test_eof125 }
	fallthrough
case 125:
// line 3487 "zparse.go"
	if data[p] == 10 { goto tr341 }
	goto st125
tr327:
// line 200 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
	goto st126
st126:
	p++
	if p == pe { goto _test_eof126 }
	fallthrough
case 126:
// line 3499 "zparse.go"
	if data[p] == 10 { goto tr329 }
	goto st126
st127:
	p++
	if p == pe { goto _test_eof127 }
	fallthrough
case 127:
	if data[p] == 10 { goto tr317 }
	goto st127
tr28:
// line 194 "zparse.rl"
	{ mark = p }
	goto st128
st128:
	p++
	if p == pe { goto _test_eof128 }
	fallthrough
case 128:
// line 3518 "zparse.go"
	switch data[p] {
		case 72: goto st16
		case 78: goto st21
		case 83: goto st16
		case 104: goto st16
		case 110: goto st21
		case 115: goto st16
	}
	goto st0
tr30:
// line 194 "zparse.rl"
	{ mark = p }
	goto st129
st129:
	p++
	if p == pe { goto _test_eof129 }
	fallthrough
case 129:
// line 3537 "zparse.go"
	switch data[p] {
		case 83: goto st16
		case 115: goto st16
	}
	goto st0
tr31:
// line 194 "zparse.rl"
	{ mark = p }
	goto st130
st130:
	p++
	if p == pe { goto _test_eof130 }
	fallthrough
case 130:
// line 3552 "zparse.go"
	switch data[p] {
		case 78: goto st16
		case 110: goto st16
	}
	goto st0
tr33:
// line 194 "zparse.rl"
	{ mark = p }
	goto st131
st131:
	p++
	if p == pe { goto _test_eof131 }
	fallthrough
case 131:
// line 3567 "zparse.go"
	switch data[p] {
		case 79: goto st132
		case 83: goto st68
		case 111: goto st132
		case 115: goto st68
	}
	goto st0
st132:
	p++
	if p == pe { goto _test_eof132 }
	fallthrough
case 132:
	switch data[p] {
		case 78: goto st133
		case 110: goto st133
	}
	goto st0
st133:
	p++
	if p == pe { goto _test_eof133 }
	fallthrough
case 133:
	switch data[p] {
		case 69: goto st16
		case 101: goto st16
	}
	goto st0
tr424:
// line 195 "zparse.rl"
	{ hdr.Name = data[mark:p] }
	goto st134
st134:
	p++
	if p == pe { goto _test_eof134 }
	fallthrough
case 134:
// line 3604 "zparse.go"
	if data[p] == 10 { goto tr2 }
	goto st134
tr7:
// line 194 "zparse.rl"
	{ mark = p }
// line 197 "zparse.rl"
	{ /* ... */ }
	goto st135
st135:
	p++
	if p == pe { goto _test_eof135 }
	fallthrough
case 135:
// line 3618 "zparse.go"
	switch data[p] {
		case 9: goto st6
		case 10: goto tr37
		case 32: goto st6
		case 40: goto tr38
		case 41: goto tr39
		case 59: goto st8
		case 65: goto st9
		case 78: goto st136
		case 97: goto st9
		case 110: goto st136
	}
	goto st0
st136:
	p++
	if p == pe { goto _test_eof136 }
	fallthrough
case 136:
	switch data[p] {
		case 89: goto st137
		case 121: goto st137
	}
	goto st0
st137:
	p++
	if p == pe { goto _test_eof137 }
	fallthrough
case 137:
	switch data[p] {
		case 9: goto tr400
		case 10: goto tr401
		case 32: goto tr400
		case 40: goto tr402
		case 41: goto tr403
		case 59: goto tr404
	}
	goto st0
tr406:
// line 204 "zparse.rl"
	{ lines++ }
	goto st138
tr407:
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st138
tr408:
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st138
tr400:
// line 196 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st138
tr401:
// line 196 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 204 "zparse.rl"
	{ lines++ }
	goto st138
tr402:
// line 196 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 201 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st138
tr403:
// line 196 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 202 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st138
st138:
	p++
	if p == pe { goto _test_eof138 }
	fallthrough
case 138:
// line 3695 "zparse.go"
	switch data[p] {
		case 9: goto st138
		case 10: goto tr406
		case 32: goto st138
		case 40: goto tr407
		case 41: goto tr408
		case 59: goto st140
		case 65: goto tr67
		case 67: goto tr68
		case 68: goto tr29
		case 77: goto tr32
		case 78: goto tr69
		case 82: goto tr34
		case 83: goto tr35
		case 97: goto tr67
		case 99: goto tr68
		case 100: goto tr29
		case 109: goto tr32
		case 110: goto tr69
		case 114: goto tr34
		case 115: goto tr35
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr409 }
	goto st0
tr409:
// line 194 "zparse.rl"
	{ mark = p }
	goto st139
st139:
	p++
	if p == pe { goto _test_eof139 }
	fallthrough
case 139:
// line 3729 "zparse.go"
	switch data[p] {
		case 9: goto tr411
		case 10: goto tr412
		case 32: goto tr411
		case 40: goto tr413
		case 41: goto tr414
		case 59: goto tr416
	}
	if 48 <= data[p] && data[p] <= 57 { goto st139 }
	goto st0
tr404:
// line 196 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st140
st140:
	p++
	if p == pe { goto _test_eof140 }
	fallthrough
case 140:
// line 3749 "zparse.go"
	if data[p] == 10 { goto tr406 }
	goto st140
tr8:
// line 194 "zparse.rl"
	{ mark = p }
// line 197 "zparse.rl"
	{ /* ... */ }
	goto st141
st141:
	p++
	if p == pe { goto _test_eof141 }
	fallthrough
case 141:
// line 3763 "zparse.go"
	switch data[p] {
		case 72: goto st137
		case 78: goto st21
		case 83: goto st137
		case 104: goto st137
		case 110: goto st21
		case 115: goto st137
	}
	goto st0
tr10:
// line 194 "zparse.rl"
	{ mark = p }
// line 197 "zparse.rl"
	{ /* ... */ }
	goto st142
st142:
	p++
	if p == pe { goto _test_eof142 }
	fallthrough
case 142:
// line 3784 "zparse.go"
	switch data[p] {
		case 83: goto st137
		case 115: goto st137
	}
	goto st0
tr11:
// line 194 "zparse.rl"
	{ mark = p }
// line 197 "zparse.rl"
	{ /* ... */ }
	goto st143
st143:
	p++
	if p == pe { goto _test_eof143 }
	fallthrough
case 143:
// line 3801 "zparse.go"
	switch data[p] {
		case 78: goto st137
		case 110: goto st137
	}
	goto st0
tr13:
// line 194 "zparse.rl"
	{ mark = p }
// line 197 "zparse.rl"
	{ /* ... */ }
	goto st144
st144:
	p++
	if p == pe { goto _test_eof144 }
	fallthrough
case 144:
// line 3818 "zparse.go"
	switch data[p] {
		case 79: goto st145
		case 83: goto st68
		case 111: goto st145
		case 115: goto st68
	}
	goto st0
st145:
	p++
	if p == pe { goto _test_eof145 }
	fallthrough
case 145:
	switch data[p] {
		case 78: goto st146
		case 110: goto st146
	}
	goto st0
st146:
	p++
	if p == pe { goto _test_eof146 }
	fallthrough
case 146:
	switch data[p] {
		case 69: goto st137
		case 101: goto st137
	}
	goto st0
st147:
	p++
	if p == pe { goto _test_eof147 }
	fallthrough
case 147:
	switch data[p] {
		case 9: goto tr419
		case 10: goto tr420
		case 32: goto tr419
		case 40: goto tr421
		case 41: goto tr422
		case 43: goto st147
		case 59: goto tr424
		case 61: goto st147
		case 95: goto st147
	}
	if data[p] < 65 {
		if 45 <= data[p] && data[p] <= 57 { goto st147 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st147 }
	} else {
		goto st147
	}
	goto st0
	}
	_test_eof148: cs = 148; goto _test_eof; 
	_test_eof1: cs = 1; goto _test_eof; 
	_test_eof2: cs = 2; goto _test_eof; 
	_test_eof3: cs = 3; goto _test_eof; 
	_test_eof4: cs = 4; goto _test_eof; 
	_test_eof5: cs = 5; goto _test_eof; 
	_test_eof6: cs = 6; goto _test_eof; 
	_test_eof7: cs = 7; goto _test_eof; 
	_test_eof149: cs = 149; goto _test_eof; 
	_test_eof8: cs = 8; goto _test_eof; 
	_test_eof9: cs = 9; goto _test_eof; 
	_test_eof10: cs = 10; goto _test_eof; 
	_test_eof11: cs = 11; goto _test_eof; 
	_test_eof12: cs = 12; goto _test_eof; 
	_test_eof13: cs = 13; goto _test_eof; 
	_test_eof150: cs = 150; goto _test_eof; 
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
	_test_eof151: cs = 151; goto _test_eof; 
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
	_test_eof152: cs = 152; goto _test_eof; 
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
	_test_eof153: cs = 153; goto _test_eof; 
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
	_test_eof154: cs = 154; goto _test_eof; 
	_test_eof65: cs = 65; goto _test_eof; 
	_test_eof66: cs = 66; goto _test_eof; 
	_test_eof67: cs = 67; goto _test_eof; 
	_test_eof68: cs = 68; goto _test_eof; 
	_test_eof69: cs = 69; goto _test_eof; 
	_test_eof70: cs = 70; goto _test_eof; 
	_test_eof155: cs = 155; goto _test_eof; 
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
	_test_eof156: cs = 156; goto _test_eof; 
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
	_test_eof157: cs = 157; goto _test_eof; 
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
	_test_eof134: cs = 134; goto _test_eof; 
	_test_eof135: cs = 135; goto _test_eof; 
	_test_eof136: cs = 136; goto _test_eof; 
	_test_eof137: cs = 137; goto _test_eof; 
	_test_eof138: cs = 138; goto _test_eof; 
	_test_eof139: cs = 139; goto _test_eof; 
	_test_eof140: cs = 140; goto _test_eof; 
	_test_eof141: cs = 141; goto _test_eof; 
	_test_eof142: cs = 142; goto _test_eof; 
	_test_eof143: cs = 143; goto _test_eof; 
	_test_eof144: cs = 144; goto _test_eof; 
	_test_eof145: cs = 145; goto _test_eof; 
	_test_eof146: cs = 146; goto _test_eof; 
	_test_eof147: cs = 147; goto _test_eof; 

	_test_eof: {}
	if p == eof {
	switch cs {
	case 149: goto tr425
	case 150: goto tr427
	case 151: goto tr429
	case 152: goto tr431
	case 153: goto tr433
	case 154: goto tr435
	case 155: goto tr437
	case 156: goto tr439
	case 157: goto tr441
	}
	}

	_out: {}
	}

// line 250 "zparse.rl"

        
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
