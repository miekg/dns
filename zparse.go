
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


// line 64 "zparse.go"
var z_start int = 324
var z_first_final int = 324
var z_error int = 0

var z_en_main int = 324


// line 63 "zparse.rl"


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
        brace := false
        lines := 0
        mark := 0
        hdr := new(RR_Header)
        tok := newToken()
        var rr RR

        
// line 99 "zparse.go"
	cs = z_start

// line 102 "zparse.go"
	{
	if p == pe { goto _test_eof }
	switch cs {
	case -666: // i am a hack D:
	fallthrough
case 324:
	switch data[p] {
		case 9: goto st10
		case 10: goto tr72
		case 32: goto st10
		case 34: goto st0
		case 40: goto tr62
		case 41: goto tr63
		case 59: goto st13
		case 92: goto st0
	}
	goto st1
st1:
	p++
	if p == pe { goto _test_eof1 }
	fallthrough
case 1:
	switch data[p] {
		case 9: goto tr1
		case 10: goto tr2
		case 32: goto tr1
		case 34: goto st0
		case 40: goto tr4
		case 41: goto tr5
		case 59: goto tr6
		case 92: goto st0
	}
	goto st1
tr1:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
	goto st2
tr2:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 100 "zparse.rl"
	{ lines++ }
	goto st2
tr4:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st2
tr5:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st2
tr8:
// line 100 "zparse.rl"
	{ lines++ }
	goto st2
tr9:
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st2
tr10:
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st2
tr65:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st2
tr66:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 100 "zparse.rl"
	{ lines++ }
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st2
tr67:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st2
tr68:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st2
tr105:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st2
tr106:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 100 "zparse.rl"
	{ lines++ }
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st2
tr107:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st2
tr108:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st2
st2:
	p++
	if p == pe { goto _test_eof2 }
	fallthrough
case 2:
// line 235 "zparse.go"
	switch data[p] {
		case 9: goto st2
		case 10: goto tr8
		case 32: goto st2
		case 40: goto tr9
		case 41: goto tr10
		case 59: goto st12
		case 65: goto tr13
		case 67: goto tr14
		case 72: goto tr15
		case 73: goto tr16
		case 77: goto tr17
		case 78: goto tr18
		case 97: goto tr13
		case 99: goto tr14
		case 104: goto tr15
		case 105: goto tr16
		case 109: goto tr17
		case 110: goto tr18
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr11 }
	goto st0
st0:
cs = 0;
	goto _out;
tr11:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st3
st3:
	p++
	if p == pe { goto _test_eof3 }
	fallthrough
case 3:
// line 272 "zparse.go"
	switch data[p] {
		case 9: goto tr19
		case 10: goto tr20
		case 32: goto tr19
		case 40: goto tr21
		case 41: goto tr22
		case 59: goto tr24
	}
	if 48 <= data[p] && data[p] <= 57 { goto st3 }
	goto st0
tr26:
// line 100 "zparse.rl"
	{ lines++ }
	goto st4
tr27:
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st4
tr28:
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st4
tr19:
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st4
tr20:
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 100 "zparse.rl"
	{ lines++ }
	goto st4
tr21:
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st4
tr22:
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st4
st4:
	p++
	if p == pe { goto _test_eof4 }
	fallthrough
case 4:
// line 322 "zparse.go"
	switch data[p] {
		case 9: goto st4
		case 10: goto tr26
		case 32: goto st4
		case 40: goto tr27
		case 41: goto tr28
		case 59: goto st5
		case 65: goto tr30
		case 67: goto tr31
		case 72: goto tr32
		case 73: goto tr33
		case 77: goto tr34
		case 78: goto tr35
		case 97: goto tr30
		case 99: goto tr31
		case 104: goto tr32
		case 105: goto tr33
		case 109: goto tr34
		case 110: goto tr35
	}
	goto st0
tr24:
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st5
st5:
	p++
	if p == pe { goto _test_eof5 }
	fallthrough
case 5:
// line 353 "zparse.go"
	if data[p] == 10 { goto tr26 }
	goto st5
tr30:
// line 89 "zparse.rl"
	{ mark = p }
	goto st6
st6:
	p++
	if p == pe { goto _test_eof6 }
	fallthrough
case 6:
// line 365 "zparse.go"
	switch data[p] {
		case 9: goto tr36
		case 10: goto tr37
		case 32: goto tr36
		case 40: goto tr38
		case 41: goto tr39
		case 59: goto tr40
		case 65: goto st192
		case 78: goto st323
		case 97: goto st192
		case 110: goto st323
	}
	goto st0
tr45:
// line 100 "zparse.rl"
	{ lines++ }
	goto st7
tr46:
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st7
tr47:
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st7
tr36:
// line 101 "zparse.rl"
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
	goto st7
tr37:
// line 101 "zparse.rl"
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
// line 100 "zparse.rl"
	{ lines++ }
	goto st7
tr38:
// line 101 "zparse.rl"
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
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st7
tr39:
// line 101 "zparse.rl"
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
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st7
st7:
	p++
	if p == pe { goto _test_eof7 }
	fallthrough
case 7:
// line 454 "zparse.go"
	switch data[p] {
		case 9: goto st7
		case 10: goto tr45
		case 32: goto st7
		case 34: goto st0
		case 40: goto tr46
		case 41: goto tr47
		case 59: goto st191
		case 92: goto st0
	}
	goto tr43
tr43:
// line 89 "zparse.rl"
	{ mark = p }
	goto st8
st8:
	p++
	if p == pe { goto _test_eof8 }
	fallthrough
case 8:
// line 475 "zparse.go"
	switch data[p] {
		case 9: goto tr50
		case 10: goto tr51
		case 32: goto tr50
		case 34: goto st0
		case 40: goto tr52
		case 41: goto tr53
		case 59: goto tr54
		case 92: goto st0
	}
	goto st8
tr57:
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st9
tr58:
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st9
tr50:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st9
tr52:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st9
tr53:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st9
tr132:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st9
tr134:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st9
tr135:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st9
tr206:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st9
tr208:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st9
tr209:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st9
tr334:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st9
tr336:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st9
tr337:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st9
tr487:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st9
tr489:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st9
tr490:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st9
st9:
	p++
	if p == pe { goto _test_eof9 }
	fallthrough
case 9:
// line 703 "zparse.go"
	switch data[p] {
		case 9: goto st9
		case 10: goto tr56
		case 32: goto st9
		case 40: goto tr57
		case 41: goto tr58
		case 59: goto tr59
	}
	goto st0
tr138:
// line 100 "zparse.rl"
	{ lines++ }
	goto st325
tr51:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
// line 100 "zparse.rl"
	{ lines++ }
	goto st325
tr56:
// line 100 "zparse.rl"
	{ lines++ }
// line 89 "zparse.rl"
	{ mark = p }
	goto st325
tr133:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
// line 100 "zparse.rl"
	{ lines++ }
	goto st325
tr207:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
// line 100 "zparse.rl"
	{ lines++ }
	goto st325
tr335:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
// line 100 "zparse.rl"
	{ lines++ }
	goto st325
tr488:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
// line 100 "zparse.rl"
	{ lines++ }
	goto st325
st325:
	p++
	if p == pe { goto _test_eof325 }
	fallthrough
case 325:
// line 799 "zparse.go"
	switch data[p] {
		case 9: goto st10
		case 10: goto tr61
		case 32: goto st10
		case 34: goto st0
		case 40: goto tr62
		case 41: goto tr63
		case 59: goto tr64
		case 92: goto st0
	}
	goto st1
tr62:
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st10
tr63:
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st10
tr160:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st10
tr162:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st10
tr163:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st10
tr170:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st10
tr172:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st10
tr173:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st10
tr212:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st10
tr214:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st10
tr215:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st10
tr217:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st10
tr219:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st10
tr220:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st10
tr240:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st10
tr242:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st10
tr243:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st10
tr260:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st10
tr262:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st10
tr263:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st10
tr265:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st10
tr267:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st10
tr268:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st10
tr288:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st10
tr290:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st10
tr291:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st10
tr493:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st10
tr495:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st10
tr496:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st10
tr510:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st10
tr512:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st10
tr513:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st10
tr533:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st10
tr535:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st10
tr536:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st10
tr817:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st10
tr819:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st10
tr820:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st10
st10:
	p++
	if p == pe { goto _test_eof10 }
	fallthrough
case 10:
// line 1424 "zparse.go"
	switch data[p] {
		case 9: goto st10
		case 10: goto tr61
		case 32: goto st10
		case 40: goto tr62
		case 41: goto tr63
		case 59: goto tr64
		case 65: goto tr13
		case 67: goto tr14
		case 72: goto tr15
		case 73: goto tr16
		case 77: goto tr17
		case 78: goto tr18
		case 97: goto tr13
		case 99: goto tr14
		case 104: goto tr15
		case 105: goto tr16
		case 109: goto tr17
		case 110: goto tr18
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr11 }
	goto st0
tr72:
// line 100 "zparse.rl"
	{ lines++ }
	goto st326
tr61:
// line 100 "zparse.rl"
	{ lines++ }
// line 89 "zparse.rl"
	{ mark = p }
	goto st326
tr161:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 100 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st326
tr171:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 100 "zparse.rl"
	{ lines++ }
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st326
tr213:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 100 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st326
tr218:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 100 "zparse.rl"
	{ lines++ }
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st326
tr241:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 100 "zparse.rl"
	{ lines++ }
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st326
tr261:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 100 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st326
tr266:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 100 "zparse.rl"
	{ lines++ }
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st326
tr289:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 100 "zparse.rl"
	{ lines++ }
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st326
tr494:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 100 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st326
tr511:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 100 "zparse.rl"
	{ lines++ }
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st326
tr534:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 100 "zparse.rl"
	{ lines++ }
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st326
tr818:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 100 "zparse.rl"
	{ lines++ }
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st326
st326:
	p++
	if p == pe { goto _test_eof326 }
	fallthrough
case 326:
// line 1670 "zparse.go"
	switch data[p] {
		case 9: goto st10
		case 10: goto tr61
		case 32: goto st10
		case 34: goto st0
		case 40: goto tr62
		case 41: goto tr63
		case 59: goto tr64
		case 65: goto tr904
		case 67: goto tr905
		case 72: goto tr906
		case 73: goto tr907
		case 77: goto tr908
		case 78: goto tr909
		case 92: goto st0
		case 97: goto tr904
		case 99: goto tr905
		case 104: goto tr906
		case 105: goto tr907
		case 109: goto tr908
		case 110: goto tr909
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr903 }
	goto st1
tr903:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st11
tr941:
// line 89 "zparse.rl"
	{ mark = p }
	goto st11
st11:
	p++
	if p == pe { goto _test_eof11 }
	fallthrough
case 11:
// line 1710 "zparse.go"
	switch data[p] {
		case 9: goto tr65
		case 10: goto tr66
		case 32: goto tr65
		case 34: goto st0
		case 40: goto tr67
		case 41: goto tr68
		case 59: goto tr70
		case 92: goto st0
	}
	if 48 <= data[p] && data[p] <= 57 { goto st11 }
	goto st1
tr6:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
	goto st12
tr70:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st12
tr109:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st12
st12:
	p++
	if p == pe { goto _test_eof12 }
	fallthrough
case 12:
// line 1744 "zparse.go"
	if data[p] == 10 { goto tr8 }
	goto st12
tr64:
// line 89 "zparse.rl"
	{ mark = p }
	goto st13
tr164:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st13
tr175:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st13
tr216:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st13
tr222:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st13
tr244:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st13
tr264:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st13
tr270:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st13
tr292:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st13
tr497:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st13
tr515:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st13
tr537:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st13
tr821:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st13
st13:
	p++
	if p == pe { goto _test_eof13 }
	fallthrough
case 13:
// line 1940 "zparse.go"
	if data[p] == 10 { goto tr72 }
	goto st13
tr904:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st14
tr910:
// line 89 "zparse.rl"
	{ mark = p }
	goto st14
st14:
	p++
	if p == pe { goto _test_eof14 }
	fallthrough
case 14:
// line 1958 "zparse.go"
	switch data[p] {
		case 9: goto tr73
		case 10: goto tr74
		case 32: goto tr73
		case 34: goto st0
		case 40: goto tr75
		case 41: goto tr76
		case 59: goto tr77
		case 65: goto st93
		case 78: goto st322
		case 92: goto st0
		case 97: goto st93
		case 110: goto st322
	}
	goto st1
tr81:
// line 100 "zparse.rl"
	{ lines++ }
	goto st15
tr82:
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st15
tr83:
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st15
tr73:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
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
	goto st15
tr74:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 100 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
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
	goto st15
tr75:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
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
	goto st15
tr76:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
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
	goto st15
st15:
	p++
	if p == pe { goto _test_eof15 }
	fallthrough
case 15:
// line 2057 "zparse.go"
	switch data[p] {
		case 9: goto st15
		case 10: goto tr81
		case 32: goto st15
		case 34: goto st0
		case 40: goto tr82
		case 41: goto tr83
		case 59: goto st92
		case 65: goto tr86
		case 67: goto tr87
		case 72: goto tr88
		case 73: goto tr89
		case 77: goto tr90
		case 78: goto tr91
		case 92: goto st0
		case 97: goto tr86
		case 99: goto tr87
		case 104: goto tr88
		case 105: goto tr89
		case 109: goto tr90
		case 110: goto tr91
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr84 }
	goto tr43
tr84:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st16
st16:
	p++
	if p == pe { goto _test_eof16 }
	fallthrough
case 16:
// line 2093 "zparse.go"
	switch data[p] {
		case 9: goto tr92
		case 10: goto tr93
		case 32: goto tr92
		case 34: goto st0
		case 40: goto tr94
		case 41: goto tr95
		case 59: goto tr97
		case 92: goto st0
	}
	if 48 <= data[p] && data[p] <= 57 { goto st16 }
	goto st8
tr100:
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st17
tr101:
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st17
tr92:
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st17
tr94:
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st17
tr95:
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st17
tr139:
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st17
tr141:
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st17
tr142:
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st17
tr339:
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st17
tr341:
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st17
tr342:
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st17
tr395:
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st17
tr397:
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st17
tr398:
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st17
tr561:
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st17
tr563:
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st17
tr564:
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st17
st17:
	p++
	if p == pe { goto _test_eof17 }
	fallthrough
case 17:
// line 2352 "zparse.go"
	switch data[p] {
		case 9: goto st17
		case 10: goto tr99
		case 32: goto st17
		case 40: goto tr100
		case 41: goto tr101
		case 59: goto tr102
		case 65: goto tr30
		case 67: goto tr31
		case 72: goto tr32
		case 73: goto tr33
		case 77: goto tr34
		case 78: goto tr35
		case 97: goto tr30
		case 99: goto tr31
		case 104: goto tr32
		case 105: goto tr33
		case 109: goto tr34
		case 110: goto tr35
	}
	goto st0
tr146:
// line 100 "zparse.rl"
	{ lines++ }
	goto st327
tr99:
// line 100 "zparse.rl"
	{ lines++ }
// line 89 "zparse.rl"
	{ mark = p }
	goto st327
tr93:
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 100 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st327
tr140:
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 100 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st327
tr340:
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 100 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st327
tr396:
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 100 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st327
tr562:
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 100 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st327
st327:
	p++
	if p == pe { goto _test_eof327 }
	fallthrough
case 327:
// line 2470 "zparse.go"
	switch data[p] {
		case 9: goto st10
		case 10: goto tr61
		case 32: goto st10
		case 34: goto st0
		case 40: goto tr62
		case 41: goto tr63
		case 59: goto tr64
		case 65: goto tr910
		case 67: goto tr911
		case 72: goto tr912
		case 73: goto tr913
		case 77: goto tr914
		case 78: goto tr915
		case 92: goto st0
		case 97: goto tr910
		case 99: goto tr911
		case 104: goto tr912
		case 105: goto tr913
		case 109: goto tr914
		case 110: goto tr915
	}
	goto st1
tr905:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st18
tr911:
// line 89 "zparse.rl"
	{ mark = p }
	goto st18
st18:
	p++
	if p == pe { goto _test_eof18 }
	fallthrough
case 18:
// line 2509 "zparse.go"
	switch data[p] {
		case 9: goto tr1
		case 10: goto tr2
		case 32: goto tr1
		case 34: goto st0
		case 40: goto tr4
		case 41: goto tr5
		case 59: goto tr6
		case 72: goto st19
		case 78: goto st20
		case 83: goto st19
		case 92: goto st0
		case 104: goto st19
		case 110: goto st20
		case 115: goto st19
	}
	goto st1
st19:
	p++
	if p == pe { goto _test_eof19 }
	fallthrough
case 19:
	switch data[p] {
		case 9: goto tr105
		case 10: goto tr106
		case 32: goto tr105
		case 34: goto st0
		case 40: goto tr107
		case 41: goto tr108
		case 59: goto tr109
		case 92: goto st0
	}
	goto st1
st20:
	p++
	if p == pe { goto _test_eof20 }
	fallthrough
case 20:
	switch data[p] {
		case 9: goto tr1
		case 10: goto tr2
		case 32: goto tr1
		case 34: goto st0
		case 40: goto tr4
		case 41: goto tr5
		case 59: goto tr6
		case 65: goto st21
		case 92: goto st0
		case 97: goto st21
	}
	goto st1
st21:
	p++
	if p == pe { goto _test_eof21 }
	fallthrough
case 21:
	switch data[p] {
		case 9: goto tr1
		case 10: goto tr2
		case 32: goto tr1
		case 34: goto st0
		case 40: goto tr4
		case 41: goto tr5
		case 59: goto tr6
		case 77: goto st22
		case 92: goto st0
		case 109: goto st22
	}
	goto st1
st22:
	p++
	if p == pe { goto _test_eof22 }
	fallthrough
case 22:
	switch data[p] {
		case 9: goto tr1
		case 10: goto tr2
		case 32: goto tr1
		case 34: goto st0
		case 40: goto tr4
		case 41: goto tr5
		case 59: goto tr6
		case 69: goto st23
		case 92: goto st0
		case 101: goto st23
	}
	goto st1
st23:
	p++
	if p == pe { goto _test_eof23 }
	fallthrough
case 23:
	switch data[p] {
		case 9: goto tr113
		case 10: goto tr114
		case 32: goto tr113
		case 34: goto st0
		case 40: goto tr115
		case 41: goto tr116
		case 59: goto tr117
		case 92: goto st0
	}
	goto st1
tr120:
// line 100 "zparse.rl"
	{ lines++ }
	goto st24
tr121:
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st24
tr122:
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st24
tr113:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
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
	goto st24
tr114:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 100 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
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
	goto st24
tr115:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
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
	goto st24
tr116:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
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
	goto st24
st24:
	p++
	if p == pe { goto _test_eof24 }
	fallthrough
case 24:
// line 2696 "zparse.go"
	switch data[p] {
		case 9: goto st24
		case 10: goto tr120
		case 32: goto st24
		case 34: goto st0
		case 40: goto tr121
		case 41: goto tr122
		case 59: goto st29
		case 65: goto tr125
		case 67: goto tr126
		case 72: goto tr127
		case 73: goto tr128
		case 77: goto tr129
		case 78: goto tr130
		case 92: goto st0
		case 97: goto tr125
		case 99: goto tr126
		case 104: goto tr127
		case 105: goto tr128
		case 109: goto tr129
		case 110: goto tr130
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr123 }
	goto tr118
tr118:
// line 89 "zparse.rl"
	{ mark = p }
	goto st25
st25:
	p++
	if p == pe { goto _test_eof25 }
	fallthrough
case 25:
// line 2730 "zparse.go"
	switch data[p] {
		case 9: goto tr132
		case 10: goto tr133
		case 32: goto tr132
		case 34: goto st0
		case 40: goto tr134
		case 41: goto tr135
		case 59: goto tr136
		case 92: goto st0
	}
	goto st25
tr59:
// line 89 "zparse.rl"
	{ mark = p }
	goto st26
tr54:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st26
tr136:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st26
tr210:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st26
tr338:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st26
tr491:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st26
st26:
	p++
	if p == pe { goto _test_eof26 }
	fallthrough
case 26:
// line 2812 "zparse.go"
	if data[p] == 10 { goto tr138 }
	goto st26
tr123:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st27
st27:
	p++
	if p == pe { goto _test_eof27 }
	fallthrough
case 27:
// line 2826 "zparse.go"
	switch data[p] {
		case 9: goto tr139
		case 10: goto tr140
		case 32: goto tr139
		case 34: goto st0
		case 40: goto tr141
		case 41: goto tr142
		case 59: goto tr144
		case 92: goto st0
	}
	if 48 <= data[p] && data[p] <= 57 { goto st27 }
	goto st25
tr102:
// line 89 "zparse.rl"
	{ mark = p }
	goto st28
tr97:
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st28
tr144:
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st28
tr344:
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st28
tr400:
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st28
tr566:
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st28
st28:
	p++
	if p == pe { goto _test_eof28 }
	fallthrough
case 28:
// line 2919 "zparse.go"
	if data[p] == 10 { goto tr146 }
	goto st28
tr117:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
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
	goto st29
st29:
	p++
	if p == pe { goto _test_eof29 }
	fallthrough
case 29:
// line 2942 "zparse.go"
	if data[p] == 10 { goto tr120 }
	goto st29
tr125:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st30
st30:
	p++
	if p == pe { goto _test_eof30 }
	fallthrough
case 30:
// line 2956 "zparse.go"
	switch data[p] {
		case 9: goto tr147
		case 10: goto tr148
		case 32: goto tr147
		case 34: goto st0
		case 40: goto tr149
		case 41: goto tr150
		case 59: goto tr151
		case 65: goto st311
		case 78: goto st314
		case 92: goto st0
		case 97: goto st311
		case 110: goto st314
	}
	goto st25
tr156:
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st31
tr157:
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st31
tr147:
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st31
tr149:
// line 101 "zparse.rl"
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
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st31
tr150:
// line 101 "zparse.rl"
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
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st31
tr345:
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st31
tr347:
// line 101 "zparse.rl"
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
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st31
tr348:
// line 101 "zparse.rl"
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
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st31
tr401:
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st31
tr403:
// line 101 "zparse.rl"
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
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st31
tr404:
// line 101 "zparse.rl"
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
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st31
tr567:
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st31
tr569:
// line 101 "zparse.rl"
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
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st31
tr570:
// line 101 "zparse.rl"
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
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st31
tr845:
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st31
tr847:
// line 101 "zparse.rl"
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
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st31
tr848:
// line 101 "zparse.rl"
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
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st31
st31:
	p++
	if p == pe { goto _test_eof31 }
	fallthrough
case 31:
// line 3353 "zparse.go"
	switch data[p] {
		case 9: goto st31
		case 10: goto tr155
		case 32: goto st31
		case 34: goto st0
		case 40: goto tr156
		case 41: goto tr157
		case 59: goto tr158
		case 92: goto st0
	}
	goto tr43
tr353:
// line 100 "zparse.rl"
	{ lines++ }
	goto st328
tr155:
// line 100 "zparse.rl"
	{ lines++ }
// line 89 "zparse.rl"
	{ mark = p }
	goto st328
tr148:
// line 101 "zparse.rl"
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
// line 100 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st328
tr346:
// line 101 "zparse.rl"
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
// line 100 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st328
tr402:
// line 101 "zparse.rl"
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
// line 100 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st328
tr568:
// line 101 "zparse.rl"
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
// line 100 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st328
tr846:
// line 101 "zparse.rl"
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
// line 100 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st328
st328:
	p++
	if p == pe { goto _test_eof328 }
	fallthrough
case 328:
// line 3506 "zparse.go"
	switch data[p] {
		case 9: goto st33
		case 10: goto tr166
		case 32: goto st33
		case 34: goto st0
		case 40: goto tr167
		case 41: goto tr168
		case 59: goto tr169
		case 92: goto st0
	}
	goto tr916
tr916:
// line 89 "zparse.rl"
	{ mark = p }
	goto st32
st32:
	p++
	if p == pe { goto _test_eof32 }
	fallthrough
case 32:
// line 3527 "zparse.go"
	switch data[p] {
		case 9: goto tr160
		case 10: goto tr161
		case 32: goto tr160
		case 34: goto st0
		case 40: goto tr162
		case 41: goto tr163
		case 59: goto tr164
		case 92: goto st0
	}
	goto st32
tr167:
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st33
tr168:
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st33
tr178:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st33
tr180:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st33
tr181:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st33
tr225:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st33
tr227:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st33
tr228:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st33
tr273:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st33
tr275:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st33
tr276:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st33
tr518:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st33
tr520:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st33
tr521:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st33
st33:
	p++
	if p == pe { goto _test_eof33 }
	fallthrough
case 33:
// line 3868 "zparse.go"
	switch data[p] {
		case 9: goto st33
		case 10: goto tr166
		case 32: goto st33
		case 34: goto st0
		case 40: goto tr167
		case 41: goto tr168
		case 59: goto tr169
		case 65: goto tr86
		case 67: goto tr87
		case 72: goto tr88
		case 73: goto tr89
		case 77: goto tr90
		case 78: goto tr91
		case 92: goto st0
		case 97: goto tr86
		case 99: goto tr87
		case 104: goto tr88
		case 105: goto tr89
		case 109: goto tr90
		case 110: goto tr91
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr84 }
	goto tr43
tr177:
// line 100 "zparse.rl"
	{ lines++ }
	goto st329
tr166:
// line 100 "zparse.rl"
	{ lines++ }
// line 89 "zparse.rl"
	{ mark = p }
	goto st329
tr179:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 100 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st329
tr226:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 100 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st329
tr274:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 100 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st329
tr519:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 100 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st329
st329:
	p++
	if p == pe { goto _test_eof329 }
	fallthrough
case 329:
// line 4016 "zparse.go"
	switch data[p] {
		case 9: goto st33
		case 10: goto tr166
		case 32: goto st33
		case 34: goto st0
		case 40: goto tr167
		case 41: goto tr168
		case 59: goto tr169
		case 65: goto tr918
		case 67: goto tr919
		case 72: goto tr920
		case 73: goto tr921
		case 77: goto tr922
		case 78: goto tr923
		case 92: goto st0
		case 97: goto tr918
		case 99: goto tr919
		case 104: goto tr920
		case 105: goto tr921
		case 109: goto tr922
		case 110: goto tr923
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr917 }
	goto tr916
tr917:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st34
st34:
	p++
	if p == pe { goto _test_eof34 }
	fallthrough
case 34:
// line 4052 "zparse.go"
	switch data[p] {
		case 9: goto tr170
		case 10: goto tr171
		case 32: goto tr170
		case 34: goto st0
		case 40: goto tr172
		case 41: goto tr173
		case 59: goto tr175
		case 92: goto st0
	}
	if 48 <= data[p] && data[p] <= 57 { goto st34 }
	goto st32
tr169:
// line 89 "zparse.rl"
	{ mark = p }
	goto st35
tr182:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st35
tr229:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st35
tr277:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st35
tr522:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st35
st35:
	p++
	if p == pe { goto _test_eof35 }
	fallthrough
case 35:
// line 4174 "zparse.go"
	if data[p] == 10 { goto tr177 }
	goto st35
tr918:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st36
st36:
	p++
	if p == pe { goto _test_eof36 }
	fallthrough
case 36:
// line 4188 "zparse.go"
	switch data[p] {
		case 9: goto tr178
		case 10: goto tr179
		case 32: goto tr178
		case 34: goto st0
		case 40: goto tr180
		case 41: goto tr181
		case 59: goto tr182
		case 65: goto st37
		case 78: goto st277
		case 92: goto st0
		case 97: goto st37
		case 110: goto st277
	}
	goto st32
st37:
	p++
	if p == pe { goto _test_eof37 }
	fallthrough
case 37:
	switch data[p] {
		case 9: goto tr160
		case 10: goto tr161
		case 32: goto tr160
		case 34: goto st0
		case 40: goto tr162
		case 41: goto tr163
		case 59: goto tr164
		case 65: goto st38
		case 92: goto st0
		case 97: goto st38
	}
	goto st32
st38:
	p++
	if p == pe { goto _test_eof38 }
	fallthrough
case 38:
	switch data[p] {
		case 9: goto tr160
		case 10: goto tr161
		case 32: goto tr160
		case 34: goto st0
		case 40: goto tr162
		case 41: goto tr163
		case 59: goto tr164
		case 65: goto st39
		case 92: goto st0
		case 97: goto st39
	}
	goto st32
st39:
	p++
	if p == pe { goto _test_eof39 }
	fallthrough
case 39:
	switch data[p] {
		case 9: goto tr187
		case 10: goto tr188
		case 32: goto tr187
		case 34: goto st0
		case 40: goto tr189
		case 41: goto tr190
		case 59: goto tr191
		case 92: goto st0
	}
	goto st32
tr195:
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st40
tr196:
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st40
tr187:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st40
tr189:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st40
tr190:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st40
tr234:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st40
tr236:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st40
tr237:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st40
tr282:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st40
tr284:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st40
tr285:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st40
tr527:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st40
tr529:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st40
tr530:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st40
st40:
	p++
	if p == pe { goto _test_eof40 }
	fallthrough
case 40:
// line 4585 "zparse.go"
	switch data[p] {
		case 9: goto st40
		case 10: goto tr194
		case 32: goto st40
		case 34: goto st0
		case 40: goto tr195
		case 41: goto tr196
		case 59: goto tr198
		case 65: goto tr199
		case 67: goto tr200
		case 72: goto tr201
		case 73: goto tr202
		case 77: goto tr203
		case 78: goto tr204
		case 92: goto st0
		case 97: goto tr199
		case 99: goto tr200
		case 104: goto tr201
		case 105: goto tr202
		case 109: goto tr203
		case 110: goto tr204
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr197 }
	goto tr192
tr192:
// line 89 "zparse.rl"
	{ mark = p }
	goto st41
st41:
	p++
	if p == pe { goto _test_eof41 }
	fallthrough
case 41:
// line 4619 "zparse.go"
	switch data[p] {
		case 9: goto tr206
		case 10: goto tr207
		case 32: goto tr206
		case 34: goto st0
		case 40: goto tr208
		case 41: goto tr209
		case 59: goto tr210
		case 92: goto st0
	}
	goto st41
tr224:
// line 100 "zparse.rl"
	{ lines++ }
	goto st330
tr194:
// line 100 "zparse.rl"
	{ lines++ }
// line 89 "zparse.rl"
	{ mark = p }
	goto st330
tr188:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 100 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st330
tr235:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 100 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st330
tr283:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 100 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st330
tr528:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 100 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st330
st330:
	p++
	if p == pe { goto _test_eof330 }
	fallthrough
case 330:
// line 4754 "zparse.go"
	switch data[p] {
		case 9: goto st40
		case 10: goto tr194
		case 32: goto st40
		case 34: goto st0
		case 40: goto tr195
		case 41: goto tr196
		case 59: goto tr198
		case 65: goto tr926
		case 67: goto tr927
		case 72: goto tr928
		case 73: goto tr929
		case 77: goto tr930
		case 78: goto tr931
		case 92: goto st0
		case 97: goto tr926
		case 99: goto tr927
		case 104: goto tr928
		case 105: goto tr929
		case 109: goto tr930
		case 110: goto tr931
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr925 }
	goto tr924
tr924:
// line 89 "zparse.rl"
	{ mark = p }
	goto st42
st42:
	p++
	if p == pe { goto _test_eof42 }
	fallthrough
case 42:
// line 4788 "zparse.go"
	switch data[p] {
		case 9: goto tr212
		case 10: goto tr213
		case 32: goto tr212
		case 34: goto st0
		case 40: goto tr214
		case 41: goto tr215
		case 59: goto tr216
		case 92: goto st0
	}
	goto st42
tr925:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st43
st43:
	p++
	if p == pe { goto _test_eof43 }
	fallthrough
case 43:
// line 4811 "zparse.go"
	switch data[p] {
		case 9: goto tr217
		case 10: goto tr218
		case 32: goto tr217
		case 34: goto st0
		case 40: goto tr219
		case 41: goto tr220
		case 59: goto tr222
		case 92: goto st0
	}
	if 48 <= data[p] && data[p] <= 57 { goto st43 }
	goto st42
tr198:
// line 89 "zparse.rl"
	{ mark = p }
	goto st44
tr191:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st44
tr238:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st44
tr286:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st44
tr531:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st44
st44:
	p++
	if p == pe { goto _test_eof44 }
	fallthrough
case 44:
// line 4933 "zparse.go"
	if data[p] == 10 { goto tr224 }
	goto st44
tr926:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st45
st45:
	p++
	if p == pe { goto _test_eof45 }
	fallthrough
case 45:
// line 4947 "zparse.go"
	switch data[p] {
		case 9: goto tr225
		case 10: goto tr226
		case 32: goto tr225
		case 34: goto st0
		case 40: goto tr227
		case 41: goto tr228
		case 59: goto tr229
		case 65: goto st46
		case 78: goto st49
		case 92: goto st0
		case 97: goto st46
		case 110: goto st49
	}
	goto st42
st46:
	p++
	if p == pe { goto _test_eof46 }
	fallthrough
case 46:
	switch data[p] {
		case 9: goto tr212
		case 10: goto tr213
		case 32: goto tr212
		case 34: goto st0
		case 40: goto tr214
		case 41: goto tr215
		case 59: goto tr216
		case 65: goto st47
		case 92: goto st0
		case 97: goto st47
	}
	goto st42
st47:
	p++
	if p == pe { goto _test_eof47 }
	fallthrough
case 47:
	switch data[p] {
		case 9: goto tr212
		case 10: goto tr213
		case 32: goto tr212
		case 34: goto st0
		case 40: goto tr214
		case 41: goto tr215
		case 59: goto tr216
		case 65: goto st48
		case 92: goto st0
		case 97: goto st48
	}
	goto st42
st48:
	p++
	if p == pe { goto _test_eof48 }
	fallthrough
case 48:
	switch data[p] {
		case 9: goto tr234
		case 10: goto tr235
		case 32: goto tr234
		case 34: goto st0
		case 40: goto tr236
		case 41: goto tr237
		case 59: goto tr238
		case 92: goto st0
	}
	goto st42
st49:
	p++
	if p == pe { goto _test_eof49 }
	fallthrough
case 49:
	switch data[p] {
		case 9: goto tr212
		case 10: goto tr213
		case 32: goto tr212
		case 34: goto st0
		case 40: goto tr214
		case 41: goto tr215
		case 59: goto tr216
		case 89: goto st50
		case 92: goto st0
		case 121: goto st50
	}
	goto st42
st50:
	p++
	if p == pe { goto _test_eof50 }
	fallthrough
case 50:
	switch data[p] {
		case 9: goto tr240
		case 10: goto tr241
		case 32: goto tr240
		case 34: goto st0
		case 40: goto tr242
		case 41: goto tr243
		case 59: goto tr244
		case 92: goto st0
	}
	goto st42
tr927:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st51
st51:
	p++
	if p == pe { goto _test_eof51 }
	fallthrough
case 51:
// line 5060 "zparse.go"
	switch data[p] {
		case 9: goto tr212
		case 10: goto tr213
		case 32: goto tr212
		case 34: goto st0
		case 40: goto tr214
		case 41: goto tr215
		case 59: goto tr216
		case 72: goto st50
		case 78: goto st52
		case 83: goto st50
		case 92: goto st0
		case 104: goto st50
		case 110: goto st52
		case 115: goto st50
	}
	goto st42
st52:
	p++
	if p == pe { goto _test_eof52 }
	fallthrough
case 52:
	switch data[p] {
		case 9: goto tr212
		case 10: goto tr213
		case 32: goto tr212
		case 34: goto st0
		case 40: goto tr214
		case 41: goto tr215
		case 59: goto tr216
		case 65: goto st53
		case 92: goto st0
		case 97: goto st53
	}
	goto st42
st53:
	p++
	if p == pe { goto _test_eof53 }
	fallthrough
case 53:
	switch data[p] {
		case 9: goto tr212
		case 10: goto tr213
		case 32: goto tr212
		case 34: goto st0
		case 40: goto tr214
		case 41: goto tr215
		case 59: goto tr216
		case 77: goto st54
		case 92: goto st0
		case 109: goto st54
	}
	goto st42
st54:
	p++
	if p == pe { goto _test_eof54 }
	fallthrough
case 54:
	switch data[p] {
		case 9: goto tr212
		case 10: goto tr213
		case 32: goto tr212
		case 34: goto st0
		case 40: goto tr214
		case 41: goto tr215
		case 59: goto tr216
		case 69: goto st55
		case 92: goto st0
		case 101: goto st55
	}
	goto st42
st55:
	p++
	if p == pe { goto _test_eof55 }
	fallthrough
case 55:
	switch data[p] {
		case 9: goto tr249
		case 10: goto tr250
		case 32: goto tr249
		case 34: goto st0
		case 40: goto tr251
		case 41: goto tr252
		case 59: goto tr253
		case 92: goto st0
	}
	goto st42
tr256:
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st56
tr257:
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st56
tr826:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st56
tr828:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st56
tr829:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st56
tr249:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st56
tr251:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st56
tr252:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st56
tr297:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st56
tr299:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st56
tr300:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st56
tr542:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st56
tr544:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st56
tr545:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st56
st56:
	p++
	if p == pe { goto _test_eof56 }
	fallthrough
case 56:
// line 5477 "zparse.go"
	switch data[p] {
		case 9: goto st56
		case 10: goto tr255
		case 32: goto st56
		case 34: goto st0
		case 40: goto tr256
		case 41: goto tr257
		case 59: goto tr258
		case 65: goto tr125
		case 67: goto tr126
		case 72: goto tr127
		case 73: goto tr128
		case 77: goto tr129
		case 78: goto tr130
		case 92: goto st0
		case 97: goto tr125
		case 99: goto tr126
		case 104: goto tr127
		case 105: goto tr128
		case 109: goto tr129
		case 110: goto tr130
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr123 }
	goto tr118
tr272:
// line 100 "zparse.rl"
	{ lines++ }
	goto st331
tr255:
// line 100 "zparse.rl"
	{ lines++ }
// line 89 "zparse.rl"
	{ mark = p }
	goto st331
tr827:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 100 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st331
tr250:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 100 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st331
tr298:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 100 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st331
tr543:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 100 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st331
st331:
	p++
	if p == pe { goto _test_eof331 }
	fallthrough
case 331:
// line 5625 "zparse.go"
	switch data[p] {
		case 9: goto st56
		case 10: goto tr255
		case 32: goto st56
		case 34: goto st0
		case 40: goto tr256
		case 41: goto tr257
		case 59: goto tr258
		case 65: goto tr934
		case 67: goto tr935
		case 72: goto tr936
		case 73: goto tr937
		case 77: goto tr938
		case 78: goto tr939
		case 92: goto st0
		case 97: goto tr934
		case 99: goto tr935
		case 104: goto tr936
		case 105: goto tr937
		case 109: goto tr938
		case 110: goto tr939
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr933 }
	goto tr932
tr932:
// line 89 "zparse.rl"
	{ mark = p }
	goto st57
st57:
	p++
	if p == pe { goto _test_eof57 }
	fallthrough
case 57:
// line 5659 "zparse.go"
	switch data[p] {
		case 9: goto tr260
		case 10: goto tr261
		case 32: goto tr260
		case 34: goto st0
		case 40: goto tr262
		case 41: goto tr263
		case 59: goto tr264
		case 92: goto st0
	}
	goto st57
tr933:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st58
st58:
	p++
	if p == pe { goto _test_eof58 }
	fallthrough
case 58:
// line 5682 "zparse.go"
	switch data[p] {
		case 9: goto tr265
		case 10: goto tr266
		case 32: goto tr265
		case 34: goto st0
		case 40: goto tr267
		case 41: goto tr268
		case 59: goto tr270
		case 92: goto st0
	}
	if 48 <= data[p] && data[p] <= 57 { goto st58 }
	goto st57
tr258:
// line 89 "zparse.rl"
	{ mark = p }
	goto st59
tr830:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st59
tr253:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st59
tr301:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st59
tr546:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st59
st59:
	p++
	if p == pe { goto _test_eof59 }
	fallthrough
case 59:
// line 5804 "zparse.go"
	if data[p] == 10 { goto tr272 }
	goto st59
tr934:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st60
st60:
	p++
	if p == pe { goto _test_eof60 }
	fallthrough
case 60:
// line 5818 "zparse.go"
	switch data[p] {
		case 9: goto tr273
		case 10: goto tr274
		case 32: goto tr273
		case 34: goto st0
		case 40: goto tr275
		case 41: goto tr276
		case 59: goto tr277
		case 65: goto st61
		case 78: goto st64
		case 92: goto st0
		case 97: goto st61
		case 110: goto st64
	}
	goto st57
st61:
	p++
	if p == pe { goto _test_eof61 }
	fallthrough
case 61:
	switch data[p] {
		case 9: goto tr260
		case 10: goto tr261
		case 32: goto tr260
		case 34: goto st0
		case 40: goto tr262
		case 41: goto tr263
		case 59: goto tr264
		case 65: goto st62
		case 92: goto st0
		case 97: goto st62
	}
	goto st57
st62:
	p++
	if p == pe { goto _test_eof62 }
	fallthrough
case 62:
	switch data[p] {
		case 9: goto tr260
		case 10: goto tr261
		case 32: goto tr260
		case 34: goto st0
		case 40: goto tr262
		case 41: goto tr263
		case 59: goto tr264
		case 65: goto st63
		case 92: goto st0
		case 97: goto st63
	}
	goto st57
st63:
	p++
	if p == pe { goto _test_eof63 }
	fallthrough
case 63:
	switch data[p] {
		case 9: goto tr282
		case 10: goto tr283
		case 32: goto tr282
		case 34: goto st0
		case 40: goto tr284
		case 41: goto tr285
		case 59: goto tr286
		case 92: goto st0
	}
	goto st57
st64:
	p++
	if p == pe { goto _test_eof64 }
	fallthrough
case 64:
	switch data[p] {
		case 9: goto tr260
		case 10: goto tr261
		case 32: goto tr260
		case 34: goto st0
		case 40: goto tr262
		case 41: goto tr263
		case 59: goto tr264
		case 89: goto st65
		case 92: goto st0
		case 121: goto st65
	}
	goto st57
st65:
	p++
	if p == pe { goto _test_eof65 }
	fallthrough
case 65:
	switch data[p] {
		case 9: goto tr288
		case 10: goto tr289
		case 32: goto tr288
		case 34: goto st0
		case 40: goto tr290
		case 41: goto tr291
		case 59: goto tr292
		case 92: goto st0
	}
	goto st57
tr935:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st66
st66:
	p++
	if p == pe { goto _test_eof66 }
	fallthrough
case 66:
// line 5931 "zparse.go"
	switch data[p] {
		case 9: goto tr260
		case 10: goto tr261
		case 32: goto tr260
		case 34: goto st0
		case 40: goto tr262
		case 41: goto tr263
		case 59: goto tr264
		case 72: goto st65
		case 78: goto st67
		case 83: goto st65
		case 92: goto st0
		case 104: goto st65
		case 110: goto st67
		case 115: goto st65
	}
	goto st57
st67:
	p++
	if p == pe { goto _test_eof67 }
	fallthrough
case 67:
	switch data[p] {
		case 9: goto tr260
		case 10: goto tr261
		case 32: goto tr260
		case 34: goto st0
		case 40: goto tr262
		case 41: goto tr263
		case 59: goto tr264
		case 65: goto st68
		case 92: goto st0
		case 97: goto st68
	}
	goto st57
st68:
	p++
	if p == pe { goto _test_eof68 }
	fallthrough
case 68:
	switch data[p] {
		case 9: goto tr260
		case 10: goto tr261
		case 32: goto tr260
		case 34: goto st0
		case 40: goto tr262
		case 41: goto tr263
		case 59: goto tr264
		case 77: goto st69
		case 92: goto st0
		case 109: goto st69
	}
	goto st57
st69:
	p++
	if p == pe { goto _test_eof69 }
	fallthrough
case 69:
	switch data[p] {
		case 9: goto tr260
		case 10: goto tr261
		case 32: goto tr260
		case 34: goto st0
		case 40: goto tr262
		case 41: goto tr263
		case 59: goto tr264
		case 69: goto st70
		case 92: goto st0
		case 101: goto st70
	}
	goto st57
st70:
	p++
	if p == pe { goto _test_eof70 }
	fallthrough
case 70:
	switch data[p] {
		case 9: goto tr297
		case 10: goto tr298
		case 32: goto tr297
		case 34: goto st0
		case 40: goto tr299
		case 41: goto tr300
		case 59: goto tr301
		case 92: goto st0
	}
	goto st57
tr936:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st71
st71:
	p++
	if p == pe { goto _test_eof71 }
	fallthrough
case 71:
// line 6030 "zparse.go"
	switch data[p] {
		case 9: goto tr260
		case 10: goto tr261
		case 32: goto tr260
		case 34: goto st0
		case 40: goto tr262
		case 41: goto tr263
		case 59: goto tr264
		case 83: goto st65
		case 92: goto st0
		case 115: goto st65
	}
	goto st57
tr937:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st72
st72:
	p++
	if p == pe { goto _test_eof72 }
	fallthrough
case 72:
// line 6055 "zparse.go"
	switch data[p] {
		case 9: goto tr260
		case 10: goto tr261
		case 32: goto tr260
		case 34: goto st0
		case 40: goto tr262
		case 41: goto tr263
		case 59: goto tr264
		case 78: goto st65
		case 92: goto st0
		case 110: goto st65
	}
	goto st57
tr938:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st73
st73:
	p++
	if p == pe { goto _test_eof73 }
	fallthrough
case 73:
// line 6080 "zparse.go"
	switch data[p] {
		case 9: goto tr260
		case 10: goto tr261
		case 32: goto tr260
		case 34: goto st0
		case 40: goto tr262
		case 41: goto tr263
		case 59: goto tr264
		case 88: goto st74
		case 92: goto st0
		case 120: goto st74
	}
	goto st57
st74:
	p++
	if p == pe { goto _test_eof74 }
	fallthrough
case 74:
	switch data[p] {
		case 9: goto tr303
		case 10: goto tr304
		case 32: goto tr303
		case 34: goto st0
		case 40: goto tr305
		case 41: goto tr306
		case 59: goto tr307
		case 92: goto st0
	}
	goto st57
tr310:
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st75
tr311:
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st75
tr832:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st75
tr834:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st75
tr835:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st75
tr803:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st75
tr805:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st75
tr806:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st75
tr303:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st75
tr305:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st75
tr306:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st75
tr548:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st75
tr550:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st75
tr551:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st75
st75:
	p++
	if p == pe { goto _test_eof75 }
	fallthrough
case 75:
// line 6439 "zparse.go"
	switch data[p] {
		case 9: goto st75
		case 10: goto tr309
		case 32: goto st75
		case 40: goto tr310
		case 41: goto tr311
		case 59: goto tr313
		case 65: goto tr13
		case 67: goto tr14
		case 72: goto tr15
		case 73: goto tr16
		case 77: goto tr17
		case 78: goto tr18
		case 97: goto tr13
		case 99: goto tr14
		case 104: goto tr15
		case 105: goto tr16
		case 109: goto tr17
		case 110: goto tr18
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr312 }
	goto st0
tr458:
// line 100 "zparse.rl"
	{ lines++ }
	goto st332
tr309:
// line 100 "zparse.rl"
	{ lines++ }
// line 89 "zparse.rl"
	{ mark = p }
	goto st332
tr833:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 100 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st332
tr804:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 100 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st332
tr304:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 100 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st332
tr549:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 100 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st332
st332:
	p++
	if p == pe { goto _test_eof332 }
	fallthrough
case 332:
// line 6585 "zparse.go"
	switch data[p] {
		case 9: goto st75
		case 10: goto tr309
		case 32: goto st75
		case 34: goto st0
		case 40: goto tr310
		case 41: goto tr311
		case 59: goto tr313
		case 65: goto tr904
		case 67: goto tr905
		case 72: goto tr906
		case 73: goto tr907
		case 77: goto tr908
		case 78: goto tr909
		case 92: goto st0
		case 97: goto tr904
		case 99: goto tr905
		case 104: goto tr906
		case 105: goto tr907
		case 109: goto tr908
		case 110: goto tr909
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr940 }
	goto st1
tr940:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st76
st76:
	p++
	if p == pe { goto _test_eof76 }
	fallthrough
case 76:
// line 6621 "zparse.go"
	switch data[p] {
		case 9: goto tr314
		case 10: goto tr315
		case 32: goto tr314
		case 34: goto st0
		case 40: goto tr316
		case 41: goto tr317
		case 59: goto tr319
		case 92: goto st0
	}
	if 48 <= data[p] && data[p] <= 57 { goto st76 }
	goto st1
tr322:
// line 100 "zparse.rl"
	{ lines++ }
	goto st77
tr323:
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st77
tr324:
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st77
tr314:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 94 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st77
tr315:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 100 "zparse.rl"
	{ lines++ }
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 94 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st77
tr316:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 94 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st77
tr317:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 94 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st77
tr451:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 94 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st77
tr452:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 100 "zparse.rl"
	{ lines++ }
// line 94 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st77
tr453:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 94 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st77
tr454:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 94 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st77
st77:
	p++
	if p == pe { goto _test_eof77 }
	fallthrough
case 77:
// line 6719 "zparse.go"
	switch data[p] {
		case 9: goto st77
		case 10: goto tr322
		case 32: goto st77
		case 34: goto st0
		case 40: goto tr323
		case 41: goto tr324
		case 59: goto st80
		case 65: goto tr327
		case 67: goto tr328
		case 72: goto tr329
		case 73: goto tr330
		case 77: goto tr331
		case 78: goto tr332
		case 92: goto st0
		case 97: goto tr327
		case 99: goto tr328
		case 104: goto tr329
		case 105: goto tr330
		case 109: goto tr331
		case 110: goto tr332
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr325 }
	goto tr320
tr320:
// line 89 "zparse.rl"
	{ mark = p }
	goto st78
st78:
	p++
	if p == pe { goto _test_eof78 }
	fallthrough
case 78:
// line 6753 "zparse.go"
	switch data[p] {
		case 9: goto tr334
		case 10: goto tr335
		case 32: goto tr334
		case 34: goto st0
		case 40: goto tr336
		case 41: goto tr337
		case 59: goto tr338
		case 92: goto st0
	}
	goto st78
tr325:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st79
st79:
	p++
	if p == pe { goto _test_eof79 }
	fallthrough
case 79:
// line 6776 "zparse.go"
	switch data[p] {
		case 9: goto tr339
		case 10: goto tr340
		case 32: goto tr339
		case 34: goto st0
		case 40: goto tr341
		case 41: goto tr342
		case 59: goto tr344
		case 92: goto st0
	}
	if 48 <= data[p] && data[p] <= 57 { goto st79 }
	goto st78
tr319:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 94 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st80
tr456:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 94 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st80
st80:
	p++
	if p == pe { goto _test_eof80 }
	fallthrough
case 80:
// line 6808 "zparse.go"
	if data[p] == 10 { goto tr322 }
	goto st80
tr327:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st81
st81:
	p++
	if p == pe { goto _test_eof81 }
	fallthrough
case 81:
// line 6822 "zparse.go"
	switch data[p] {
		case 9: goto tr345
		case 10: goto tr346
		case 32: goto tr345
		case 34: goto st0
		case 40: goto tr347
		case 41: goto tr348
		case 59: goto tr349
		case 65: goto st83
		case 78: goto st88
		case 92: goto st0
		case 97: goto st83
		case 110: goto st88
	}
	goto st78
tr158:
// line 89 "zparse.rl"
	{ mark = p }
	goto st82
tr151:
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st82
tr349:
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st82
tr405:
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st82
tr571:
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st82
tr849:
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st82
st82:
	p++
	if p == pe { goto _test_eof82 }
	fallthrough
case 82:
// line 6963 "zparse.go"
	if data[p] == 10 { goto tr353 }
	goto st82
st83:
	p++
	if p == pe { goto _test_eof83 }
	fallthrough
case 83:
	switch data[p] {
		case 9: goto tr334
		case 10: goto tr335
		case 32: goto tr334
		case 34: goto st0
		case 40: goto tr336
		case 41: goto tr337
		case 59: goto tr338
		case 65: goto st84
		case 92: goto st0
		case 97: goto st84
	}
	goto st78
st84:
	p++
	if p == pe { goto _test_eof84 }
	fallthrough
case 84:
	switch data[p] {
		case 9: goto tr334
		case 10: goto tr335
		case 32: goto tr334
		case 34: goto st0
		case 40: goto tr336
		case 41: goto tr337
		case 59: goto tr338
		case 65: goto st85
		case 92: goto st0
		case 97: goto st85
	}
	goto st78
st85:
	p++
	if p == pe { goto _test_eof85 }
	fallthrough
case 85:
	switch data[p] {
		case 9: goto tr356
		case 10: goto tr357
		case 32: goto tr356
		case 34: goto st0
		case 40: goto tr358
		case 41: goto tr359
		case 59: goto tr360
		case 92: goto st0
	}
	goto st78
tr363:
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st86
tr364:
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st86
tr890:
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st86
tr892:
// line 101 "zparse.rl"
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
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st86
tr893:
// line 101 "zparse.rl"
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
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st86
tr356:
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st86
tr358:
// line 101 "zparse.rl"
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
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st86
tr359:
// line 101 "zparse.rl"
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
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st86
tr410:
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st86
tr412:
// line 101 "zparse.rl"
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
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st86
tr413:
// line 101 "zparse.rl"
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
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st86
tr576:
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st86
tr578:
// line 101 "zparse.rl"
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
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st86
tr579:
// line 101 "zparse.rl"
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
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st86
tr854:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st86
tr856:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st86
tr857:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st86
st86:
	p++
	if p == pe { goto _test_eof86 }
	fallthrough
case 86:
// line 7399 "zparse.go"
	switch data[p] {
		case 9: goto st86
		case 10: goto tr362
		case 32: goto st86
		case 34: goto st0
		case 40: goto tr363
		case 41: goto tr364
		case 59: goto tr365
		case 92: goto st0
	}
	goto tr192
tr367:
// line 100 "zparse.rl"
	{ lines++ }
	goto st333
tr362:
// line 100 "zparse.rl"
	{ lines++ }
// line 89 "zparse.rl"
	{ mark = p }
	goto st333
tr891:
// line 101 "zparse.rl"
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
// line 100 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st333
tr357:
// line 101 "zparse.rl"
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
// line 100 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st333
tr411:
// line 101 "zparse.rl"
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
// line 100 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st333
tr577:
// line 101 "zparse.rl"
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
// line 100 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st333
tr855:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 100 "zparse.rl"
	{ lines++ }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st333
st333:
	p++
	if p == pe { goto _test_eof333 }
	fallthrough
case 333:
// line 7552 "zparse.go"
	switch data[p] {
		case 9: goto st40
		case 10: goto tr194
		case 32: goto st40
		case 34: goto st0
		case 40: goto tr195
		case 41: goto tr196
		case 59: goto tr198
		case 92: goto st0
	}
	goto tr924
tr365:
// line 89 "zparse.rl"
	{ mark = p }
	goto st87
tr894:
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st87
tr360:
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st87
tr414:
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st87
tr580:
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st87
tr858:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st87
st87:
	p++
	if p == pe { goto _test_eof87 }
	fallthrough
case 87:
// line 7689 "zparse.go"
	if data[p] == 10 { goto tr367 }
	goto st87
st88:
	p++
	if p == pe { goto _test_eof88 }
	fallthrough
case 88:
	switch data[p] {
		case 9: goto tr334
		case 10: goto tr335
		case 32: goto tr334
		case 34: goto st0
		case 40: goto tr336
		case 41: goto tr337
		case 59: goto tr338
		case 89: goto st89
		case 92: goto st0
		case 121: goto st89
	}
	goto st78
st89:
	p++
	if p == pe { goto _test_eof89 }
	fallthrough
case 89:
	switch data[p] {
		case 9: goto tr369
		case 10: goto tr370
		case 32: goto tr369
		case 34: goto st0
		case 40: goto tr371
		case 41: goto tr372
		case 59: goto tr373
		case 92: goto st0
	}
	goto st78
tr376:
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st90
tr377:
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st90
tr369:
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st90
tr371:
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st90
tr372:
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st90
tr416:
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st90
tr418:
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st90
tr419:
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st90
tr582:
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st90
tr584:
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st90
tr585:
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st90
tr775:
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st90
tr777:
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st90
tr778:
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st90
tr860:
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st90
tr862:
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st90
tr863:
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st90
st90:
	p++
	if p == pe { goto _test_eof90 }
	fallthrough
case 90:
// line 7972 "zparse.go"
	switch data[p] {
		case 9: goto st90
		case 10: goto tr375
		case 32: goto st90
		case 40: goto tr376
		case 41: goto tr377
		case 59: goto tr379
		case 65: goto tr380
		case 67: goto tr381
		case 77: goto tr34
		case 78: goto tr382
		case 97: goto tr380
		case 99: goto tr381
		case 109: goto tr34
		case 110: goto tr382
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr378 }
	goto st0
tr422:
// line 100 "zparse.rl"
	{ lines++ }
	goto st334
tr375:
// line 100 "zparse.rl"
	{ lines++ }
// line 89 "zparse.rl"
	{ mark = p }
	goto st334
tr370:
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 100 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st334
tr417:
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 100 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st334
tr583:
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 100 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st334
tr776:
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 100 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st334
tr861:
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 100 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st334
st334:
	p++
	if p == pe { goto _test_eof334 }
	fallthrough
case 334:
// line 8087 "zparse.go"
	switch data[p] {
		case 9: goto st10
		case 10: goto tr61
		case 32: goto st10
		case 34: goto st0
		case 40: goto tr62
		case 41: goto tr63
		case 59: goto tr64
		case 65: goto tr942
		case 67: goto tr943
		case 77: goto tr914
		case 78: goto tr944
		case 92: goto st0
		case 97: goto tr942
		case 99: goto tr943
		case 109: goto tr914
		case 110: goto tr944
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr941 }
	goto st1
tr942:
// line 89 "zparse.rl"
	{ mark = p }
	goto st91
st91:
	p++
	if p == pe { goto _test_eof91 }
	fallthrough
case 91:
// line 8117 "zparse.go"
	switch data[p] {
		case 9: goto tr73
		case 10: goto tr74
		case 32: goto tr73
		case 34: goto st0
		case 40: goto tr75
		case 41: goto tr76
		case 59: goto tr77
		case 65: goto st93
		case 92: goto st0
		case 97: goto st93
	}
	goto st1
tr77:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
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
	goto st92
st92:
	p++
	if p == pe { goto _test_eof92 }
	fallthrough
case 92:
// line 8151 "zparse.go"
	if data[p] == 10 { goto tr81 }
	goto st92
st93:
	p++
	if p == pe { goto _test_eof93 }
	fallthrough
case 93:
	switch data[p] {
		case 9: goto tr1
		case 10: goto tr2
		case 32: goto tr1
		case 34: goto st0
		case 40: goto tr4
		case 41: goto tr5
		case 59: goto tr6
		case 65: goto st94
		case 92: goto st0
		case 97: goto st94
	}
	goto st1
st94:
	p++
	if p == pe { goto _test_eof94 }
	fallthrough
case 94:
	switch data[p] {
		case 9: goto tr1
		case 10: goto tr2
		case 32: goto tr1
		case 34: goto st0
		case 40: goto tr4
		case 41: goto tr5
		case 59: goto tr6
		case 65: goto st95
		case 92: goto st0
		case 97: goto st95
	}
	goto st1
st95:
	p++
	if p == pe { goto _test_eof95 }
	fallthrough
case 95:
	switch data[p] {
		case 9: goto tr385
		case 10: goto tr386
		case 32: goto tr385
		case 34: goto st0
		case 40: goto tr387
		case 41: goto tr388
		case 59: goto tr389
		case 92: goto st0
	}
	goto st1
tr391:
// line 100 "zparse.rl"
	{ lines++ }
	goto st96
tr392:
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st96
tr393:
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st96
tr385:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
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
	goto st96
tr386:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 100 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
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
	goto st96
tr387:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
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
	goto st96
tr388:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
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
	goto st96
st96:
	p++
	if p == pe { goto _test_eof96 }
	fallthrough
case 96:
// line 8289 "zparse.go"
	switch data[p] {
		case 9: goto st96
		case 10: goto tr391
		case 32: goto st96
		case 34: goto st0
		case 40: goto tr392
		case 41: goto tr393
		case 59: goto st98
		case 65: goto tr199
		case 67: goto tr200
		case 72: goto tr201
		case 73: goto tr202
		case 77: goto tr203
		case 78: goto tr204
		case 92: goto st0
		case 97: goto tr199
		case 99: goto tr200
		case 104: goto tr201
		case 105: goto tr202
		case 109: goto tr203
		case 110: goto tr204
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr197 }
	goto tr192
tr197:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st97
st97:
	p++
	if p == pe { goto _test_eof97 }
	fallthrough
case 97:
// line 8325 "zparse.go"
	switch data[p] {
		case 9: goto tr395
		case 10: goto tr396
		case 32: goto tr395
		case 34: goto st0
		case 40: goto tr397
		case 41: goto tr398
		case 59: goto tr400
		case 92: goto st0
	}
	if 48 <= data[p] && data[p] <= 57 { goto st97 }
	goto st41
tr389:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
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
	goto st98
st98:
	p++
	if p == pe { goto _test_eof98 }
	fallthrough
case 98:
// line 8358 "zparse.go"
	if data[p] == 10 { goto tr391 }
	goto st98
tr199:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st99
st99:
	p++
	if p == pe { goto _test_eof99 }
	fallthrough
case 99:
// line 8372 "zparse.go"
	switch data[p] {
		case 9: goto tr401
		case 10: goto tr402
		case 32: goto tr401
		case 34: goto st0
		case 40: goto tr403
		case 41: goto tr404
		case 59: goto tr405
		case 65: goto st100
		case 78: goto st103
		case 92: goto st0
		case 97: goto st100
		case 110: goto st103
	}
	goto st41
st100:
	p++
	if p == pe { goto _test_eof100 }
	fallthrough
case 100:
	switch data[p] {
		case 9: goto tr206
		case 10: goto tr207
		case 32: goto tr206
		case 34: goto st0
		case 40: goto tr208
		case 41: goto tr209
		case 59: goto tr210
		case 65: goto st101
		case 92: goto st0
		case 97: goto st101
	}
	goto st41
st101:
	p++
	if p == pe { goto _test_eof101 }
	fallthrough
case 101:
	switch data[p] {
		case 9: goto tr206
		case 10: goto tr207
		case 32: goto tr206
		case 34: goto st0
		case 40: goto tr208
		case 41: goto tr209
		case 59: goto tr210
		case 65: goto st102
		case 92: goto st0
		case 97: goto st102
	}
	goto st41
st102:
	p++
	if p == pe { goto _test_eof102 }
	fallthrough
case 102:
	switch data[p] {
		case 9: goto tr410
		case 10: goto tr411
		case 32: goto tr410
		case 34: goto st0
		case 40: goto tr412
		case 41: goto tr413
		case 59: goto tr414
		case 92: goto st0
	}
	goto st41
st103:
	p++
	if p == pe { goto _test_eof103 }
	fallthrough
case 103:
	switch data[p] {
		case 9: goto tr206
		case 10: goto tr207
		case 32: goto tr206
		case 34: goto st0
		case 40: goto tr208
		case 41: goto tr209
		case 59: goto tr210
		case 89: goto st104
		case 92: goto st0
		case 121: goto st104
	}
	goto st41
st104:
	p++
	if p == pe { goto _test_eof104 }
	fallthrough
case 104:
	switch data[p] {
		case 9: goto tr416
		case 10: goto tr417
		case 32: goto tr416
		case 34: goto st0
		case 40: goto tr418
		case 41: goto tr419
		case 59: goto tr420
		case 92: goto st0
	}
	goto st41
tr379:
// line 89 "zparse.rl"
	{ mark = p }
	goto st105
tr373:
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st105
tr420:
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st105
tr586:
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st105
tr779:
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st105
tr864:
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st105
st105:
	p++
	if p == pe { goto _test_eof105 }
	fallthrough
case 105:
// line 8554 "zparse.go"
	if data[p] == 10 { goto tr422 }
	goto st105
tr200:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st106
st106:
	p++
	if p == pe { goto _test_eof106 }
	fallthrough
case 106:
// line 8568 "zparse.go"
	switch data[p] {
		case 9: goto tr206
		case 10: goto tr207
		case 32: goto tr206
		case 34: goto st0
		case 40: goto tr208
		case 41: goto tr209
		case 59: goto tr210
		case 72: goto st104
		case 78: goto st107
		case 83: goto st104
		case 92: goto st0
		case 104: goto st104
		case 110: goto st107
		case 115: goto st104
	}
	goto st41
st107:
	p++
	if p == pe { goto _test_eof107 }
	fallthrough
case 107:
	switch data[p] {
		case 9: goto tr206
		case 10: goto tr207
		case 32: goto tr206
		case 34: goto st0
		case 40: goto tr208
		case 41: goto tr209
		case 59: goto tr210
		case 65: goto st108
		case 92: goto st0
		case 97: goto st108
	}
	goto st41
st108:
	p++
	if p == pe { goto _test_eof108 }
	fallthrough
case 108:
	switch data[p] {
		case 9: goto tr206
		case 10: goto tr207
		case 32: goto tr206
		case 34: goto st0
		case 40: goto tr208
		case 41: goto tr209
		case 59: goto tr210
		case 77: goto st109
		case 92: goto st0
		case 109: goto st109
	}
	goto st41
st109:
	p++
	if p == pe { goto _test_eof109 }
	fallthrough
case 109:
	switch data[p] {
		case 9: goto tr206
		case 10: goto tr207
		case 32: goto tr206
		case 34: goto st0
		case 40: goto tr208
		case 41: goto tr209
		case 59: goto tr210
		case 69: goto st110
		case 92: goto st0
		case 101: goto st110
	}
	goto st41
st110:
	p++
	if p == pe { goto _test_eof110 }
	fallthrough
case 110:
	switch data[p] {
		case 9: goto tr427
		case 10: goto tr428
		case 32: goto tr427
		case 34: goto st0
		case 40: goto tr429
		case 41: goto tr430
		case 59: goto tr431
		case 92: goto st0
	}
	goto st41
tr434:
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st111
tr435:
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st111
tr783:
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st111
tr785:
// line 101 "zparse.rl"
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
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st111
tr786:
// line 101 "zparse.rl"
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
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st111
tr717:
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st111
tr719:
// line 101 "zparse.rl"
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
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st111
tr720:
// line 101 "zparse.rl"
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
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st111
tr427:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st111
tr429:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st111
tr430:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st111
tr591:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st111
tr593:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 101 "zparse.rl"
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
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st111
tr594:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 101 "zparse.rl"
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
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st111
tr869:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st111
tr871:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st111
tr872:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st111
st111:
	p++
	if p == pe { goto _test_eof111 }
	fallthrough
case 111:
// line 9037 "zparse.go"
	switch data[p] {
		case 9: goto st111
		case 10: goto tr433
		case 32: goto st111
		case 34: goto st0
		case 40: goto tr434
		case 41: goto tr435
		case 59: goto tr436
		case 92: goto st0
	}
	goto tr118
tr438:
// line 100 "zparse.rl"
	{ lines++ }
	goto st335
tr433:
// line 100 "zparse.rl"
	{ lines++ }
// line 89 "zparse.rl"
	{ mark = p }
	goto st335
tr784:
// line 101 "zparse.rl"
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
// line 100 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st335
tr718:
// line 101 "zparse.rl"
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
// line 100 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st335
tr428:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 100 "zparse.rl"
	{ lines++ }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st335
tr592:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 101 "zparse.rl"
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
// line 100 "zparse.rl"
	{ lines++ }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st335
tr870:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 100 "zparse.rl"
	{ lines++ }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st335
st335:
	p++
	if p == pe { goto _test_eof335 }
	fallthrough
case 335:
// line 9190 "zparse.go"
	switch data[p] {
		case 9: goto st56
		case 10: goto tr255
		case 32: goto st56
		case 34: goto st0
		case 40: goto tr256
		case 41: goto tr257
		case 59: goto tr258
		case 92: goto st0
	}
	goto tr932
tr436:
// line 89 "zparse.rl"
	{ mark = p }
	goto st112
tr787:
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st112
tr721:
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st112
tr431:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st112
tr595:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st112
tr873:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st112
st112:
	p++
	if p == pe { goto _test_eof112 }
	fallthrough
case 112:
// line 9327 "zparse.go"
	if data[p] == 10 { goto tr438 }
	goto st112
tr201:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st113
st113:
	p++
	if p == pe { goto _test_eof113 }
	fallthrough
case 113:
// line 9341 "zparse.go"
	switch data[p] {
		case 9: goto tr206
		case 10: goto tr207
		case 32: goto tr206
		case 34: goto st0
		case 40: goto tr208
		case 41: goto tr209
		case 59: goto tr210
		case 83: goto st104
		case 92: goto st0
		case 115: goto st104
	}
	goto st41
tr202:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st114
st114:
	p++
	if p == pe { goto _test_eof114 }
	fallthrough
case 114:
// line 9366 "zparse.go"
	switch data[p] {
		case 9: goto tr206
		case 10: goto tr207
		case 32: goto tr206
		case 34: goto st0
		case 40: goto tr208
		case 41: goto tr209
		case 59: goto tr210
		case 78: goto st104
		case 92: goto st0
		case 110: goto st104
	}
	goto st41
tr203:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st115
st115:
	p++
	if p == pe { goto _test_eof115 }
	fallthrough
case 115:
// line 9391 "zparse.go"
	switch data[p] {
		case 9: goto tr206
		case 10: goto tr207
		case 32: goto tr206
		case 34: goto st0
		case 40: goto tr208
		case 41: goto tr209
		case 59: goto tr210
		case 88: goto st116
		case 92: goto st0
		case 120: goto st116
	}
	goto st41
st116:
	p++
	if p == pe { goto _test_eof116 }
	fallthrough
case 116:
	switch data[p] {
		case 9: goto tr440
		case 10: goto tr441
		case 32: goto tr440
		case 34: goto st0
		case 40: goto tr442
		case 41: goto tr443
		case 59: goto tr444
		case 92: goto st0
	}
	goto st41
tr447:
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st117
tr448:
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st117
tr723:
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st117
tr725:
// line 101 "zparse.rl"
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
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st117
tr726:
// line 101 "zparse.rl"
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
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st117
tr440:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st117
tr442:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st117
tr443:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st117
tr597:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st117
tr599:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 101 "zparse.rl"
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
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st117
tr600:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 101 "zparse.rl"
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
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st117
tr789:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st117
tr791:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 101 "zparse.rl"
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
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st117
tr792:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 101 "zparse.rl"
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
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st117
tr875:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st117
tr877:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st117
tr878:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st117
st117:
	p++
	if p == pe { goto _test_eof117 }
	fallthrough
case 117:
// line 9802 "zparse.go"
	switch data[p] {
		case 9: goto st117
		case 10: goto tr446
		case 32: goto st117
		case 40: goto tr447
		case 41: goto tr448
		case 59: goto tr450
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr449 }
	goto st0
tr471:
// line 100 "zparse.rl"
	{ lines++ }
	goto st336
tr446:
// line 100 "zparse.rl"
	{ lines++ }
// line 89 "zparse.rl"
	{ mark = p }
	goto st336
tr724:
// line 101 "zparse.rl"
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
// line 100 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st336
tr441:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 100 "zparse.rl"
	{ lines++ }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st336
tr598:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 101 "zparse.rl"
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
// line 100 "zparse.rl"
	{ lines++ }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st336
tr790:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 101 "zparse.rl"
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
// line 100 "zparse.rl"
	{ lines++ }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st336
tr876:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 100 "zparse.rl"
	{ lines++ }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st336
st336:
	p++
	if p == pe { goto _test_eof336 }
	fallthrough
case 336:
// line 9954 "zparse.go"
	switch data[p] {
		case 9: goto st75
		case 10: goto tr309
		case 32: goto st75
		case 34: goto st0
		case 40: goto tr310
		case 41: goto tr311
		case 59: goto tr313
		case 92: goto st0
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr945 }
	goto st1
tr945:
// line 89 "zparse.rl"
	{ mark = p }
	goto st118
st118:
	p++
	if p == pe { goto _test_eof118 }
	fallthrough
case 118:
// line 9976 "zparse.go"
	switch data[p] {
		case 9: goto tr451
		case 10: goto tr452
		case 32: goto tr451
		case 34: goto st0
		case 40: goto tr453
		case 41: goto tr454
		case 59: goto tr456
		case 92: goto st0
	}
	if 48 <= data[p] && data[p] <= 57 { goto st118 }
	goto st1
tr313:
// line 89 "zparse.rl"
	{ mark = p }
	goto st119
tr836:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st119
tr807:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st119
tr307:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st119
tr552:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st119
st119:
	p++
	if p == pe { goto _test_eof119 }
	fallthrough
case 119:
// line 10098 "zparse.go"
	if data[p] == 10 { goto tr458 }
	goto st119
tr449:
// line 89 "zparse.rl"
	{ mark = p }
	goto st120
st120:
	p++
	if p == pe { goto _test_eof120 }
	fallthrough
case 120:
// line 10110 "zparse.go"
	switch data[p] {
		case 9: goto tr459
		case 10: goto tr460
		case 32: goto tr459
		case 40: goto tr461
		case 41: goto tr462
		case 59: goto tr464
	}
	if 48 <= data[p] && data[p] <= 57 { goto st120 }
	goto st0
tr466:
// line 100 "zparse.rl"
	{ lines++ }
	goto st121
tr467:
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st121
tr468:
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st121
tr459:
// line 94 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st121
tr460:
// line 94 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 100 "zparse.rl"
	{ lines++ }
	goto st121
tr461:
// line 94 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st121
tr462:
// line 94 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st121
st121:
	p++
	if p == pe { goto _test_eof121 }
	fallthrough
case 121:
// line 10160 "zparse.go"
	switch data[p] {
		case 9: goto st121
		case 10: goto tr466
		case 32: goto st121
		case 34: goto st0
		case 40: goto tr467
		case 41: goto tr468
		case 59: goto st122
		case 92: goto st0
	}
	goto tr320
tr464:
// line 94 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st122
st122:
	p++
	if p == pe { goto _test_eof122 }
	fallthrough
case 122:
// line 10181 "zparse.go"
	if data[p] == 10 { goto tr466 }
	goto st122
tr450:
// line 89 "zparse.rl"
	{ mark = p }
	goto st123
tr727:
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st123
tr444:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st123
tr601:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st123
tr793:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st123
tr879:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st123
st123:
	p++
	if p == pe { goto _test_eof123 }
	fallthrough
case 123:
// line 10309 "zparse.go"
	if data[p] == 10 { goto tr471 }
	goto st123
tr204:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st124
st124:
	p++
	if p == pe { goto _test_eof124 }
	fallthrough
case 124:
// line 10323 "zparse.go"
	switch data[p] {
		case 9: goto tr206
		case 10: goto tr207
		case 32: goto tr206
		case 34: goto st0
		case 40: goto tr208
		case 41: goto tr209
		case 59: goto tr210
		case 79: goto st125
		case 83: goto st127
		case 92: goto st0
		case 111: goto st125
		case 115: goto st127
	}
	goto st41
st125:
	p++
	if p == pe { goto _test_eof125 }
	fallthrough
case 125:
	switch data[p] {
		case 9: goto tr206
		case 10: goto tr207
		case 32: goto tr206
		case 34: goto st0
		case 40: goto tr208
		case 41: goto tr209
		case 59: goto tr210
		case 78: goto st126
		case 92: goto st0
		case 110: goto st126
	}
	goto st41
st126:
	p++
	if p == pe { goto _test_eof126 }
	fallthrough
case 126:
	switch data[p] {
		case 9: goto tr206
		case 10: goto tr207
		case 32: goto tr206
		case 34: goto st0
		case 40: goto tr208
		case 41: goto tr209
		case 59: goto tr210
		case 69: goto st104
		case 92: goto st0
		case 101: goto st104
	}
	goto st41
st127:
	p++
	if p == pe { goto _test_eof127 }
	fallthrough
case 127:
	switch data[p] {
		case 9: goto tr475
		case 10: goto tr476
		case 32: goto tr475
		case 34: goto st0
		case 40: goto tr477
		case 41: goto tr478
		case 59: goto tr479
		case 92: goto st0
	}
	goto st41
tr483:
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st128
tr484:
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st128
tr797:
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st128
tr799:
// line 101 "zparse.rl"
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
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st128
tr800:
// line 101 "zparse.rl"
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
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st128
tr731:
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st128
tr733:
// line 101 "zparse.rl"
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
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st128
tr734:
// line 101 "zparse.rl"
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
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st128
tr475:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st128
tr477:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st128
tr478:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st128
tr605:
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st128
tr607:
// line 101 "zparse.rl"
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
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st128
tr608:
// line 101 "zparse.rl"
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
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st128
tr883:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st128
tr885:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st128
tr886:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st128
st128:
	p++
	if p == pe { goto _test_eof128 }
	fallthrough
case 128:
// line 10772 "zparse.go"
	switch data[p] {
		case 9: goto st128
		case 10: goto tr482
		case 32: goto st128
		case 34: goto st0
		case 40: goto tr483
		case 41: goto tr484
		case 59: goto tr485
		case 92: goto st0
	}
	goto tr480
tr480:
// line 89 "zparse.rl"
	{ mark = p }
	goto st129
st129:
	p++
	if p == pe { goto _test_eof129 }
	fallthrough
case 129:
// line 10793 "zparse.go"
	switch data[p] {
		case 9: goto tr487
		case 10: goto tr488
		case 32: goto tr487
		case 34: goto st0
		case 40: goto tr489
		case 41: goto tr490
		case 59: goto tr491
		case 92: goto st0
	}
	goto st129
tr611:
// line 100 "zparse.rl"
	{ lines++ }
	goto st337
tr482:
// line 100 "zparse.rl"
	{ lines++ }
// line 89 "zparse.rl"
	{ mark = p }
	goto st337
tr798:
// line 101 "zparse.rl"
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
// line 100 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st337
tr732:
// line 101 "zparse.rl"
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
// line 100 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st337
tr476:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 100 "zparse.rl"
	{ lines++ }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st337
tr606:
// line 101 "zparse.rl"
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
// line 100 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st337
tr884:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 100 "zparse.rl"
	{ lines++ }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st337
st337:
	p++
	if p == pe { goto _test_eof337 }
	fallthrough
case 337:
// line 10946 "zparse.go"
	switch data[p] {
		case 9: goto st131
		case 10: goto tr499
		case 32: goto st131
		case 34: goto st0
		case 40: goto tr500
		case 41: goto tr501
		case 59: goto tr503
		case 92: goto st0
	}
	goto tr946
tr946:
// line 89 "zparse.rl"
	{ mark = p }
	goto st130
st130:
	p++
	if p == pe { goto _test_eof130 }
	fallthrough
case 130:
// line 10967 "zparse.go"
	switch data[p] {
		case 9: goto tr493
		case 10: goto tr494
		case 32: goto tr493
		case 34: goto st0
		case 40: goto tr495
		case 41: goto tr496
		case 59: goto tr497
		case 92: goto st0
	}
	goto st130
tr500:
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st131
tr501:
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st131
tr840:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st131
tr842:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st131
tr843:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st131
tr811:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st131
tr813:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st131
tr814:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st131
tr768:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st131
tr770:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st131
tr771:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st131
tr556:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st131
tr558:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st131
tr559:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st131
st131:
	p++
	if p == pe { goto _test_eof131 }
	fallthrough
case 131:
// line 11308 "zparse.go"
	switch data[p] {
		case 9: goto st131
		case 10: goto tr499
		case 32: goto st131
		case 34: goto st0
		case 40: goto tr500
		case 41: goto tr501
		case 59: goto tr503
		case 65: goto tr504
		case 67: goto tr505
		case 72: goto tr506
		case 73: goto tr507
		case 77: goto tr508
		case 78: goto tr509
		case 92: goto st0
		case 97: goto tr504
		case 99: goto tr505
		case 104: goto tr506
		case 105: goto tr507
		case 109: goto tr508
		case 110: goto tr509
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr502 }
	goto tr480
tr517:
// line 100 "zparse.rl"
	{ lines++ }
	goto st338
tr499:
// line 100 "zparse.rl"
	{ lines++ }
// line 89 "zparse.rl"
	{ mark = p }
	goto st338
tr841:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 100 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st338
tr812:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 100 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st338
tr769:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 100 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st338
tr557:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 100 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st338
st338:
	p++
	if p == pe { goto _test_eof338 }
	fallthrough
case 338:
// line 11456 "zparse.go"
	switch data[p] {
		case 9: goto st131
		case 10: goto tr499
		case 32: goto st131
		case 34: goto st0
		case 40: goto tr500
		case 41: goto tr501
		case 59: goto tr503
		case 65: goto tr948
		case 67: goto tr949
		case 72: goto tr950
		case 73: goto tr951
		case 77: goto tr952
		case 78: goto tr953
		case 92: goto st0
		case 97: goto tr948
		case 99: goto tr949
		case 104: goto tr950
		case 105: goto tr951
		case 109: goto tr952
		case 110: goto tr953
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr947 }
	goto tr946
tr947:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st132
st132:
	p++
	if p == pe { goto _test_eof132 }
	fallthrough
case 132:
// line 11492 "zparse.go"
	switch data[p] {
		case 9: goto tr510
		case 10: goto tr511
		case 32: goto tr510
		case 34: goto st0
		case 40: goto tr512
		case 41: goto tr513
		case 59: goto tr515
		case 92: goto st0
	}
	if 48 <= data[p] && data[p] <= 57 { goto st132 }
	goto st130
tr503:
// line 89 "zparse.rl"
	{ mark = p }
	goto st133
tr844:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st133
tr815:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st133
tr772:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st133
tr560:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st133
st133:
	p++
	if p == pe { goto _test_eof133 }
	fallthrough
case 133:
// line 11614 "zparse.go"
	if data[p] == 10 { goto tr517 }
	goto st133
tr948:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st134
st134:
	p++
	if p == pe { goto _test_eof134 }
	fallthrough
case 134:
// line 11628 "zparse.go"
	switch data[p] {
		case 9: goto tr518
		case 10: goto tr519
		case 32: goto tr518
		case 34: goto st0
		case 40: goto tr520
		case 41: goto tr521
		case 59: goto tr522
		case 65: goto st135
		case 78: goto st138
		case 92: goto st0
		case 97: goto st135
		case 110: goto st138
	}
	goto st130
st135:
	p++
	if p == pe { goto _test_eof135 }
	fallthrough
case 135:
	switch data[p] {
		case 9: goto tr493
		case 10: goto tr494
		case 32: goto tr493
		case 34: goto st0
		case 40: goto tr495
		case 41: goto tr496
		case 59: goto tr497
		case 65: goto st136
		case 92: goto st0
		case 97: goto st136
	}
	goto st130
st136:
	p++
	if p == pe { goto _test_eof136 }
	fallthrough
case 136:
	switch data[p] {
		case 9: goto tr493
		case 10: goto tr494
		case 32: goto tr493
		case 34: goto st0
		case 40: goto tr495
		case 41: goto tr496
		case 59: goto tr497
		case 65: goto st137
		case 92: goto st0
		case 97: goto st137
	}
	goto st130
st137:
	p++
	if p == pe { goto _test_eof137 }
	fallthrough
case 137:
	switch data[p] {
		case 9: goto tr527
		case 10: goto tr528
		case 32: goto tr527
		case 34: goto st0
		case 40: goto tr529
		case 41: goto tr530
		case 59: goto tr531
		case 92: goto st0
	}
	goto st130
st138:
	p++
	if p == pe { goto _test_eof138 }
	fallthrough
case 138:
	switch data[p] {
		case 9: goto tr493
		case 10: goto tr494
		case 32: goto tr493
		case 34: goto st0
		case 40: goto tr495
		case 41: goto tr496
		case 59: goto tr497
		case 89: goto st139
		case 92: goto st0
		case 121: goto st139
	}
	goto st130
st139:
	p++
	if p == pe { goto _test_eof139 }
	fallthrough
case 139:
	switch data[p] {
		case 9: goto tr533
		case 10: goto tr534
		case 32: goto tr533
		case 34: goto st0
		case 40: goto tr535
		case 41: goto tr536
		case 59: goto tr537
		case 92: goto st0
	}
	goto st130
tr949:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st140
st140:
	p++
	if p == pe { goto _test_eof140 }
	fallthrough
case 140:
// line 11741 "zparse.go"
	switch data[p] {
		case 9: goto tr493
		case 10: goto tr494
		case 32: goto tr493
		case 34: goto st0
		case 40: goto tr495
		case 41: goto tr496
		case 59: goto tr497
		case 72: goto st139
		case 78: goto st141
		case 83: goto st139
		case 92: goto st0
		case 104: goto st139
		case 110: goto st141
		case 115: goto st139
	}
	goto st130
st141:
	p++
	if p == pe { goto _test_eof141 }
	fallthrough
case 141:
	switch data[p] {
		case 9: goto tr493
		case 10: goto tr494
		case 32: goto tr493
		case 34: goto st0
		case 40: goto tr495
		case 41: goto tr496
		case 59: goto tr497
		case 65: goto st142
		case 92: goto st0
		case 97: goto st142
	}
	goto st130
st142:
	p++
	if p == pe { goto _test_eof142 }
	fallthrough
case 142:
	switch data[p] {
		case 9: goto tr493
		case 10: goto tr494
		case 32: goto tr493
		case 34: goto st0
		case 40: goto tr495
		case 41: goto tr496
		case 59: goto tr497
		case 77: goto st143
		case 92: goto st0
		case 109: goto st143
	}
	goto st130
st143:
	p++
	if p == pe { goto _test_eof143 }
	fallthrough
case 143:
	switch data[p] {
		case 9: goto tr493
		case 10: goto tr494
		case 32: goto tr493
		case 34: goto st0
		case 40: goto tr495
		case 41: goto tr496
		case 59: goto tr497
		case 69: goto st144
		case 92: goto st0
		case 101: goto st144
	}
	goto st130
st144:
	p++
	if p == pe { goto _test_eof144 }
	fallthrough
case 144:
	switch data[p] {
		case 9: goto tr542
		case 10: goto tr543
		case 32: goto tr542
		case 34: goto st0
		case 40: goto tr544
		case 41: goto tr545
		case 59: goto tr546
		case 92: goto st0
	}
	goto st130
tr950:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st145
st145:
	p++
	if p == pe { goto _test_eof145 }
	fallthrough
case 145:
// line 11840 "zparse.go"
	switch data[p] {
		case 9: goto tr493
		case 10: goto tr494
		case 32: goto tr493
		case 34: goto st0
		case 40: goto tr495
		case 41: goto tr496
		case 59: goto tr497
		case 83: goto st139
		case 92: goto st0
		case 115: goto st139
	}
	goto st130
tr951:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st146
st146:
	p++
	if p == pe { goto _test_eof146 }
	fallthrough
case 146:
// line 11865 "zparse.go"
	switch data[p] {
		case 9: goto tr493
		case 10: goto tr494
		case 32: goto tr493
		case 34: goto st0
		case 40: goto tr495
		case 41: goto tr496
		case 59: goto tr497
		case 78: goto st139
		case 92: goto st0
		case 110: goto st139
	}
	goto st130
tr952:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st147
st147:
	p++
	if p == pe { goto _test_eof147 }
	fallthrough
case 147:
// line 11890 "zparse.go"
	switch data[p] {
		case 9: goto tr493
		case 10: goto tr494
		case 32: goto tr493
		case 34: goto st0
		case 40: goto tr495
		case 41: goto tr496
		case 59: goto tr497
		case 88: goto st148
		case 92: goto st0
		case 120: goto st148
	}
	goto st130
st148:
	p++
	if p == pe { goto _test_eof148 }
	fallthrough
case 148:
	switch data[p] {
		case 9: goto tr548
		case 10: goto tr549
		case 32: goto tr548
		case 34: goto st0
		case 40: goto tr550
		case 41: goto tr551
		case 59: goto tr552
		case 92: goto st0
	}
	goto st130
tr953:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st149
st149:
	p++
	if p == pe { goto _test_eof149 }
	fallthrough
case 149:
// line 11931 "zparse.go"
	switch data[p] {
		case 9: goto tr493
		case 10: goto tr494
		case 32: goto tr493
		case 34: goto st0
		case 40: goto tr495
		case 41: goto tr496
		case 59: goto tr497
		case 79: goto st150
		case 83: goto st152
		case 92: goto st0
		case 111: goto st150
		case 115: goto st152
	}
	goto st130
st150:
	p++
	if p == pe { goto _test_eof150 }
	fallthrough
case 150:
	switch data[p] {
		case 9: goto tr493
		case 10: goto tr494
		case 32: goto tr493
		case 34: goto st0
		case 40: goto tr495
		case 41: goto tr496
		case 59: goto tr497
		case 78: goto st151
		case 92: goto st0
		case 110: goto st151
	}
	goto st130
st151:
	p++
	if p == pe { goto _test_eof151 }
	fallthrough
case 151:
	switch data[p] {
		case 9: goto tr493
		case 10: goto tr494
		case 32: goto tr493
		case 34: goto st0
		case 40: goto tr495
		case 41: goto tr496
		case 59: goto tr497
		case 69: goto st139
		case 92: goto st0
		case 101: goto st139
	}
	goto st130
st152:
	p++
	if p == pe { goto _test_eof152 }
	fallthrough
case 152:
	switch data[p] {
		case 9: goto tr556
		case 10: goto tr557
		case 32: goto tr556
		case 34: goto st0
		case 40: goto tr558
		case 41: goto tr559
		case 59: goto tr560
		case 92: goto st0
	}
	goto st130
tr502:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st153
st153:
	p++
	if p == pe { goto _test_eof153 }
	fallthrough
case 153:
// line 12010 "zparse.go"
	switch data[p] {
		case 9: goto tr561
		case 10: goto tr562
		case 32: goto tr561
		case 34: goto st0
		case 40: goto tr563
		case 41: goto tr564
		case 59: goto tr566
		case 92: goto st0
	}
	if 48 <= data[p] && data[p] <= 57 { goto st153 }
	goto st129
tr504:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st154
st154:
	p++
	if p == pe { goto _test_eof154 }
	fallthrough
case 154:
// line 12034 "zparse.go"
	switch data[p] {
		case 9: goto tr567
		case 10: goto tr568
		case 32: goto tr567
		case 34: goto st0
		case 40: goto tr569
		case 41: goto tr570
		case 59: goto tr571
		case 65: goto st155
		case 78: goto st158
		case 92: goto st0
		case 97: goto st155
		case 110: goto st158
	}
	goto st129
st155:
	p++
	if p == pe { goto _test_eof155 }
	fallthrough
case 155:
	switch data[p] {
		case 9: goto tr487
		case 10: goto tr488
		case 32: goto tr487
		case 34: goto st0
		case 40: goto tr489
		case 41: goto tr490
		case 59: goto tr491
		case 65: goto st156
		case 92: goto st0
		case 97: goto st156
	}
	goto st129
st156:
	p++
	if p == pe { goto _test_eof156 }
	fallthrough
case 156:
	switch data[p] {
		case 9: goto tr487
		case 10: goto tr488
		case 32: goto tr487
		case 34: goto st0
		case 40: goto tr489
		case 41: goto tr490
		case 59: goto tr491
		case 65: goto st157
		case 92: goto st0
		case 97: goto st157
	}
	goto st129
st157:
	p++
	if p == pe { goto _test_eof157 }
	fallthrough
case 157:
	switch data[p] {
		case 9: goto tr576
		case 10: goto tr577
		case 32: goto tr576
		case 34: goto st0
		case 40: goto tr578
		case 41: goto tr579
		case 59: goto tr580
		case 92: goto st0
	}
	goto st129
st158:
	p++
	if p == pe { goto _test_eof158 }
	fallthrough
case 158:
	switch data[p] {
		case 9: goto tr487
		case 10: goto tr488
		case 32: goto tr487
		case 34: goto st0
		case 40: goto tr489
		case 41: goto tr490
		case 59: goto tr491
		case 89: goto st159
		case 92: goto st0
		case 121: goto st159
	}
	goto st129
st159:
	p++
	if p == pe { goto _test_eof159 }
	fallthrough
case 159:
	switch data[p] {
		case 9: goto tr582
		case 10: goto tr583
		case 32: goto tr582
		case 34: goto st0
		case 40: goto tr584
		case 41: goto tr585
		case 59: goto tr586
		case 92: goto st0
	}
	goto st129
tr505:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st160
st160:
	p++
	if p == pe { goto _test_eof160 }
	fallthrough
case 160:
// line 12147 "zparse.go"
	switch data[p] {
		case 9: goto tr487
		case 10: goto tr488
		case 32: goto tr487
		case 34: goto st0
		case 40: goto tr489
		case 41: goto tr490
		case 59: goto tr491
		case 72: goto st159
		case 78: goto st161
		case 83: goto st159
		case 92: goto st0
		case 104: goto st159
		case 110: goto st161
		case 115: goto st159
	}
	goto st129
st161:
	p++
	if p == pe { goto _test_eof161 }
	fallthrough
case 161:
	switch data[p] {
		case 9: goto tr487
		case 10: goto tr488
		case 32: goto tr487
		case 34: goto st0
		case 40: goto tr489
		case 41: goto tr490
		case 59: goto tr491
		case 65: goto st162
		case 92: goto st0
		case 97: goto st162
	}
	goto st129
st162:
	p++
	if p == pe { goto _test_eof162 }
	fallthrough
case 162:
	switch data[p] {
		case 9: goto tr487
		case 10: goto tr488
		case 32: goto tr487
		case 34: goto st0
		case 40: goto tr489
		case 41: goto tr490
		case 59: goto tr491
		case 77: goto st163
		case 92: goto st0
		case 109: goto st163
	}
	goto st129
st163:
	p++
	if p == pe { goto _test_eof163 }
	fallthrough
case 163:
	switch data[p] {
		case 9: goto tr487
		case 10: goto tr488
		case 32: goto tr487
		case 34: goto st0
		case 40: goto tr489
		case 41: goto tr490
		case 59: goto tr491
		case 69: goto st164
		case 92: goto st0
		case 101: goto st164
	}
	goto st129
st164:
	p++
	if p == pe { goto _test_eof164 }
	fallthrough
case 164:
	switch data[p] {
		case 9: goto tr591
		case 10: goto tr592
		case 32: goto tr591
		case 34: goto st0
		case 40: goto tr593
		case 41: goto tr594
		case 59: goto tr595
		case 92: goto st0
	}
	goto st129
tr506:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st165
st165:
	p++
	if p == pe { goto _test_eof165 }
	fallthrough
case 165:
// line 12246 "zparse.go"
	switch data[p] {
		case 9: goto tr487
		case 10: goto tr488
		case 32: goto tr487
		case 34: goto st0
		case 40: goto tr489
		case 41: goto tr490
		case 59: goto tr491
		case 83: goto st159
		case 92: goto st0
		case 115: goto st159
	}
	goto st129
tr507:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st166
st166:
	p++
	if p == pe { goto _test_eof166 }
	fallthrough
case 166:
// line 12271 "zparse.go"
	switch data[p] {
		case 9: goto tr487
		case 10: goto tr488
		case 32: goto tr487
		case 34: goto st0
		case 40: goto tr489
		case 41: goto tr490
		case 59: goto tr491
		case 78: goto st159
		case 92: goto st0
		case 110: goto st159
	}
	goto st129
tr508:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st167
st167:
	p++
	if p == pe { goto _test_eof167 }
	fallthrough
case 167:
// line 12296 "zparse.go"
	switch data[p] {
		case 9: goto tr487
		case 10: goto tr488
		case 32: goto tr487
		case 34: goto st0
		case 40: goto tr489
		case 41: goto tr490
		case 59: goto tr491
		case 88: goto st168
		case 92: goto st0
		case 120: goto st168
	}
	goto st129
st168:
	p++
	if p == pe { goto _test_eof168 }
	fallthrough
case 168:
	switch data[p] {
		case 9: goto tr597
		case 10: goto tr598
		case 32: goto tr597
		case 34: goto st0
		case 40: goto tr599
		case 41: goto tr600
		case 59: goto tr601
		case 92: goto st0
	}
	goto st129
tr509:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st169
st169:
	p++
	if p == pe { goto _test_eof169 }
	fallthrough
case 169:
// line 12337 "zparse.go"
	switch data[p] {
		case 9: goto tr487
		case 10: goto tr488
		case 32: goto tr487
		case 34: goto st0
		case 40: goto tr489
		case 41: goto tr490
		case 59: goto tr491
		case 79: goto st170
		case 83: goto st172
		case 92: goto st0
		case 111: goto st170
		case 115: goto st172
	}
	goto st129
st170:
	p++
	if p == pe { goto _test_eof170 }
	fallthrough
case 170:
	switch data[p] {
		case 9: goto tr487
		case 10: goto tr488
		case 32: goto tr487
		case 34: goto st0
		case 40: goto tr489
		case 41: goto tr490
		case 59: goto tr491
		case 78: goto st171
		case 92: goto st0
		case 110: goto st171
	}
	goto st129
st171:
	p++
	if p == pe { goto _test_eof171 }
	fallthrough
case 171:
	switch data[p] {
		case 9: goto tr487
		case 10: goto tr488
		case 32: goto tr487
		case 34: goto st0
		case 40: goto tr489
		case 41: goto tr490
		case 59: goto tr491
		case 69: goto st159
		case 92: goto st0
		case 101: goto st159
	}
	goto st129
st172:
	p++
	if p == pe { goto _test_eof172 }
	fallthrough
case 172:
	switch data[p] {
		case 9: goto tr605
		case 10: goto tr606
		case 32: goto tr605
		case 34: goto st0
		case 40: goto tr607
		case 41: goto tr608
		case 59: goto tr609
		case 92: goto st0
	}
	goto st129
tr485:
// line 89 "zparse.rl"
	{ mark = p }
	goto st173
tr801:
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 19 "types.rl"
	{
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Cname = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st173
tr735:
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st173
tr479:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 9 "types.rl"
	{
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st173
tr609:
// line 101 "zparse.rl"
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
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 14 "types.rl"
	{
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Ns = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st173
tr887:
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.A = net.ParseIP(tok.T[0])
        }
// line 101 "zparse.rl"
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
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st173
st173:
	p++
	if p == pe { goto _test_eof173 }
	fallthrough
case 173:
// line 12530 "zparse.go"
	if data[p] == 10 { goto tr611 }
	goto st173
tr943:
// line 89 "zparse.rl"
	{ mark = p }
	goto st174
st174:
	p++
	if p == pe { goto _test_eof174 }
	fallthrough
case 174:
// line 12542 "zparse.go"
	switch data[p] {
		case 9: goto tr1
		case 10: goto tr2
		case 32: goto tr1
		case 34: goto st0
		case 40: goto tr4
		case 41: goto tr5
		case 59: goto tr6
		case 78: goto st20
		case 92: goto st0
		case 110: goto st20
	}
	goto st1
tr908:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st175
tr914:
// line 89 "zparse.rl"
	{ mark = p }
	goto st175
st175:
	p++
	if p == pe { goto _test_eof175 }
	fallthrough
case 175:
// line 12571 "zparse.go"
	switch data[p] {
		case 9: goto tr1
		case 10: goto tr2
		case 32: goto tr1
		case 34: goto st0
		case 40: goto tr4
		case 41: goto tr5
		case 59: goto tr6
		case 88: goto st176
		case 92: goto st0
		case 120: goto st176
	}
	goto st1
st176:
	p++
	if p == pe { goto _test_eof176 }
	fallthrough
case 176:
	switch data[p] {
		case 9: goto tr613
		case 10: goto tr614
		case 32: goto tr613
		case 34: goto st0
		case 40: goto tr615
		case 41: goto tr616
		case 59: goto tr617
		case 92: goto st0
	}
	goto st1
tr619:
// line 100 "zparse.rl"
	{ lines++ }
	goto st177
tr620:
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st177
tr621:
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st177
tr613:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
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
	goto st177
tr614:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 100 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
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
	goto st177
tr615:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
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
	goto st177
tr616:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
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
	goto st177
st177:
	p++
	if p == pe { goto _test_eof177 }
	fallthrough
case 177:
// line 12684 "zparse.go"
	switch data[p] {
		case 9: goto st177
		case 10: goto tr619
		case 32: goto st177
		case 40: goto tr620
		case 41: goto tr621
		case 59: goto st225
		case 65: goto tr13
		case 67: goto tr14
		case 72: goto tr15
		case 73: goto tr16
		case 77: goto tr17
		case 78: goto tr18
		case 97: goto tr13
		case 99: goto tr14
		case 104: goto tr15
		case 105: goto tr16
		case 109: goto tr17
		case 110: goto tr18
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr312 }
	goto st0
tr312:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st178
st178:
	p++
	if p == pe { goto _test_eof178 }
	fallthrough
case 178:
// line 12718 "zparse.go"
	switch data[p] {
		case 9: goto tr623
		case 10: goto tr624
		case 32: goto tr623
		case 40: goto tr625
		case 41: goto tr626
		case 59: goto tr628
	}
	if 48 <= data[p] && data[p] <= 57 { goto st178 }
	goto st0
tr630:
// line 100 "zparse.rl"
	{ lines++ }
	goto st179
tr631:
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st179
tr632:
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st179
tr623:
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 94 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st179
tr624:
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 100 "zparse.rl"
	{ lines++ }
// line 94 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st179
tr625:
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 94 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st179
tr626:
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 94 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st179
st179:
	p++
	if p == pe { goto _test_eof179 }
	fallthrough
case 179:
// line 12776 "zparse.go"
	switch data[p] {
		case 9: goto st179
		case 10: goto tr630
		case 32: goto st179
		case 34: goto st0
		case 40: goto tr631
		case 41: goto tr632
		case 59: goto st180
		case 65: goto tr634
		case 67: goto tr635
		case 72: goto tr636
		case 73: goto tr637
		case 77: goto tr638
		case 78: goto tr639
		case 92: goto st0
		case 97: goto tr634
		case 99: goto tr635
		case 104: goto tr636
		case 105: goto tr637
		case 109: goto tr638
		case 110: goto tr639
	}
	goto tr320
tr628:
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 94 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st180
st180:
	p++
	if p == pe { goto _test_eof180 }
	fallthrough
case 180:
// line 12811 "zparse.go"
	if data[p] == 10 { goto tr630 }
	goto st180
tr634:
// line 89 "zparse.rl"
	{ mark = p }
	goto st181
st181:
	p++
	if p == pe { goto _test_eof181 }
	fallthrough
case 181:
// line 12823 "zparse.go"
	switch data[p] {
		case 9: goto tr345
		case 10: goto tr346
		case 32: goto tr345
		case 34: goto st0
		case 40: goto tr347
		case 41: goto tr348
		case 59: goto tr349
		case 65: goto st83
		case 78: goto st182
		case 92: goto st0
		case 97: goto st83
		case 110: goto st182
	}
	goto st78
st182:
	p++
	if p == pe { goto _test_eof182 }
	fallthrough
case 182:
	switch data[p] {
		case 9: goto tr334
		case 10: goto tr335
		case 32: goto tr334
		case 34: goto st0
		case 40: goto tr336
		case 41: goto tr337
		case 59: goto tr338
		case 89: goto st183
		case 92: goto st0
		case 121: goto st183
	}
	goto st78
st183:
	p++
	if p == pe { goto _test_eof183 }
	fallthrough
case 183:
	switch data[p] {
		case 9: goto tr642
		case 10: goto tr643
		case 32: goto tr642
		case 34: goto st0
		case 40: goto tr644
		case 41: goto tr645
		case 59: goto tr646
		case 92: goto st0
	}
	goto st78
tr649:
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st184
tr650:
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st184
tr642:
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st184
tr644:
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st184
tr645:
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st184
st184:
	p++
	if p == pe { goto _test_eof184 }
	fallthrough
case 184:
// line 12935 "zparse.go"
	switch data[p] {
		case 9: goto st184
		case 10: goto tr648
		case 32: goto st184
		case 40: goto tr649
		case 41: goto tr650
		case 59: goto tr651
		case 65: goto tr380
		case 67: goto tr381
		case 77: goto tr34
		case 78: goto tr382
		case 97: goto tr380
		case 99: goto tr381
		case 109: goto tr34
		case 110: goto tr382
	}
	goto st0
tr664:
// line 100 "zparse.rl"
	{ lines++ }
	goto st339
tr648:
// line 100 "zparse.rl"
	{ lines++ }
// line 89 "zparse.rl"
	{ mark = p }
	goto st339
tr643:
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 100 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st339
st339:
	p++
	if p == pe { goto _test_eof339 }
	fallthrough
case 339:
// line 12985 "zparse.go"
	switch data[p] {
		case 9: goto st10
		case 10: goto tr61
		case 32: goto st10
		case 34: goto st0
		case 40: goto tr62
		case 41: goto tr63
		case 59: goto tr64
		case 65: goto tr942
		case 67: goto tr943
		case 77: goto tr914
		case 78: goto tr944
		case 92: goto st0
		case 97: goto tr942
		case 99: goto tr943
		case 109: goto tr914
		case 110: goto tr944
	}
	goto st1
tr944:
// line 89 "zparse.rl"
	{ mark = p }
	goto st185
st185:
	p++
	if p == pe { goto _test_eof185 }
	fallthrough
case 185:
// line 13014 "zparse.go"
	switch data[p] {
		case 9: goto tr1
		case 10: goto tr2
		case 32: goto tr1
		case 34: goto st0
		case 40: goto tr4
		case 41: goto tr5
		case 59: goto tr6
		case 83: goto st186
		case 92: goto st0
		case 115: goto st186
	}
	goto st1
st186:
	p++
	if p == pe { goto _test_eof186 }
	fallthrough
case 186:
	switch data[p] {
		case 9: goto tr653
		case 10: goto tr654
		case 32: goto tr653
		case 34: goto st0
		case 40: goto tr655
		case 41: goto tr656
		case 59: goto tr657
		case 92: goto st0
	}
	goto st1
tr659:
// line 100 "zparse.rl"
	{ lines++ }
	goto st187
tr660:
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st187
tr661:
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st187
tr653:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
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
	goto st187
tr654:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 100 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
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
	goto st187
tr655:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
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
	goto st187
tr656:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
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
	goto st187
st187:
	p++
	if p == pe { goto _test_eof187 }
	fallthrough
case 187:
// line 13127 "zparse.go"
	switch data[p] {
		case 9: goto st187
		case 10: goto tr659
		case 32: goto st187
		case 34: goto st0
		case 40: goto tr660
		case 41: goto tr661
		case 59: goto st188
		case 65: goto tr504
		case 67: goto tr505
		case 72: goto tr506
		case 73: goto tr507
		case 77: goto tr508
		case 78: goto tr509
		case 92: goto st0
		case 97: goto tr504
		case 99: goto tr505
		case 104: goto tr506
		case 105: goto tr507
		case 109: goto tr508
		case 110: goto tr509
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr502 }
	goto tr480
tr657:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
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
	goto st188
st188:
	p++
	if p == pe { goto _test_eof188 }
	fallthrough
case 188:
// line 13172 "zparse.go"
	if data[p] == 10 { goto tr659 }
	goto st188
tr651:
// line 89 "zparse.rl"
	{ mark = p }
	goto st189
tr646:
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 95 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 35 "types.rl"
	{
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 96 "zparse.rl"
	{ z.Push(rr); tok.reset() }
	goto st189
st189:
	p++
	if p == pe { goto _test_eof189 }
	fallthrough
case 189:
// line 13199 "zparse.go"
	if data[p] == 10 { goto tr664 }
	goto st189
tr380:
// line 89 "zparse.rl"
	{ mark = p }
	goto st190
st190:
	p++
	if p == pe { goto _test_eof190 }
	fallthrough
case 190:
// line 13211 "zparse.go"
	switch data[p] {
		case 9: goto tr36
		case 10: goto tr37
		case 32: goto tr36
		case 40: goto tr38
		case 41: goto tr39
		case 59: goto tr40
		case 65: goto st192
		case 97: goto st192
	}
	goto st0
tr40:
// line 101 "zparse.rl"
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
	goto st191
st191:
	p++
	if p == pe { goto _test_eof191 }
	fallthrough
case 191:
// line 13241 "zparse.go"
	if data[p] == 10 { goto tr45 }
	goto st191
st192:
	p++
	if p == pe { goto _test_eof192 }
	fallthrough
case 192:
	switch data[p] {
		case 65: goto st193
		case 97: goto st193
	}
	goto st0
st193:
	p++
	if p == pe { goto _test_eof193 }
	fallthrough
case 193:
	switch data[p] {
		case 65: goto st194
		case 97: goto st194
	}
	goto st0
st194:
	p++
	if p == pe { goto _test_eof194 }
	fallthrough
case 194:
	switch data[p] {
		case 9: goto tr667
		case 10: goto tr668
		case 32: goto tr667
		case 40: goto tr669
		case 41: goto tr670
		case 59: goto tr671
	}
	goto st0
tr673:
// line 100 "zparse.rl"
	{ lines++ }
	goto st195
tr674:
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st195
tr675:
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st195
tr667:
// line 101 "zparse.rl"
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
	goto st195
tr668:
// line 101 "zparse.rl"
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
// line 100 "zparse.rl"
	{ lines++ }
	goto st195
tr669:
// line 101 "zparse.rl"
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
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st195
tr670:
// line 101 "zparse.rl"
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
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st195
st195:
	p++
	if p == pe { goto _test_eof195 }
	fallthrough
case 195:
// line 13353 "zparse.go"
	switch data[p] {
		case 9: goto st195
		case 10: goto tr673
		case 32: goto st195
		case 34: goto st0
		case 40: goto tr674
		case 41: goto tr675
		case 59: goto st196
		case 92: goto st0
	}
	goto tr192
tr671:
// line 101 "zparse.rl"
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
	goto st196
st196:
	p++
	if p == pe { goto _test_eof196 }
	fallthrough
case 196:
// line 13383 "zparse.go"
	if data[p] == 10 { goto tr673 }
	goto st196
tr381:
// line 89 "zparse.rl"
	{ mark = p }
	goto st197
st197:
	p++
	if p == pe { goto _test_eof197 }
	fallthrough
case 197:
// line 13395 "zparse.go"
	switch data[p] {
		case 78: goto st198
		case 110: goto st198
	}
	goto st0
st198:
	p++
	if p == pe { goto _test_eof198 }
	fallthrough
case 198:
	switch data[p] {
		case 65: goto st199
		case 97: goto st199
	}
	goto st0
st199:
	p++
	if p == pe { goto _test_eof199 }
	fallthrough
case 199:
	switch data[p] {
		case 77: goto st200
		case 109: goto st200
	}
	goto st0
st200:
	p++
	if p == pe { goto _test_eof200 }
	fallthrough
case 200:
	switch data[p] {
		case 69: goto st201
		case 101: goto st201
	}
	goto st0
st201:
	p++
	if p == pe { goto _test_eof201 }
	fallthrough
case 201:
	switch data[p] {
		case 9: goto tr681
		case 10: goto tr682
		case 32: goto tr681
		case 40: goto tr683
		case 41: goto tr684
		case 59: goto tr685
	}
	goto st0
tr687:
// line 100 "zparse.rl"
	{ lines++ }
	goto st202
tr688:
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st202
tr689:
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st202
tr681:
// line 101 "zparse.rl"
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
	goto st202
tr682:
// line 101 "zparse.rl"
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
// line 100 "zparse.rl"
	{ lines++ }
	goto st202
tr683:
// line 101 "zparse.rl"
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
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st202
tr684:
// line 101 "zparse.rl"
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
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st202
st202:
	p++
	if p == pe { goto _test_eof202 }
	fallthrough
case 202:
// line 13520 "zparse.go"
	switch data[p] {
		case 9: goto st202
		case 10: goto tr687
		case 32: goto st202
		case 34: goto st0
		case 40: goto tr688
		case 41: goto tr689
		case 59: goto st203
		case 92: goto st0
	}
	goto tr118
tr685:
// line 101 "zparse.rl"
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
	goto st203
st203:
	p++
	if p == pe { goto _test_eof203 }
	fallthrough
case 203:
// line 13550 "zparse.go"
	if data[p] == 10 { goto tr687 }
	goto st203
tr17:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st204
tr34:
// line 89 "zparse.rl"
	{ mark = p }
	goto st204
st204:
	p++
	if p == pe { goto _test_eof204 }
	fallthrough
case 204:
// line 13568 "zparse.go"
	switch data[p] {
		case 88: goto st205
		case 120: goto st205
	}
	goto st0
st205:
	p++
	if p == pe { goto _test_eof205 }
	fallthrough
case 205:
	switch data[p] {
		case 9: goto tr692
		case 10: goto tr693
		case 32: goto tr692
		case 40: goto tr694
		case 41: goto tr695
		case 59: goto tr696
	}
	goto st0
tr698:
// line 100 "zparse.rl"
	{ lines++ }
	goto st206
tr699:
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st206
tr700:
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st206
tr692:
// line 101 "zparse.rl"
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
	goto st206
tr693:
// line 101 "zparse.rl"
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
// line 100 "zparse.rl"
	{ lines++ }
	goto st206
tr694:
// line 101 "zparse.rl"
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
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st206
tr695:
// line 101 "zparse.rl"
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
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st206
st206:
	p++
	if p == pe { goto _test_eof206 }
	fallthrough
case 206:
// line 13663 "zparse.go"
	switch data[p] {
		case 9: goto st206
		case 10: goto tr698
		case 32: goto st206
		case 40: goto tr699
		case 41: goto tr700
		case 59: goto st207
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr449 }
	goto st0
tr696:
// line 101 "zparse.rl"
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
	goto st207
st207:
	p++
	if p == pe { goto _test_eof207 }
	fallthrough
case 207:
// line 13692 "zparse.go"
	if data[p] == 10 { goto tr698 }
	goto st207
tr382:
// line 89 "zparse.rl"
	{ mark = p }
	goto st208
st208:
	p++
	if p == pe { goto _test_eof208 }
	fallthrough
case 208:
// line 13704 "zparse.go"
	switch data[p] {
		case 83: goto st209
		case 115: goto st209
	}
	goto st0
st209:
	p++
	if p == pe { goto _test_eof209 }
	fallthrough
case 209:
	switch data[p] {
		case 9: goto tr703
		case 10: goto tr704
		case 32: goto tr703
		case 40: goto tr705
		case 41: goto tr706
		case 59: goto tr707
	}
	goto st0
tr709:
// line 100 "zparse.rl"
	{ lines++ }
	goto st210
tr710:
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st210
tr711:
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st210
tr703:
// line 101 "zparse.rl"
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
	goto st210
tr704:
// line 101 "zparse.rl"
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
// line 100 "zparse.rl"
	{ lines++ }
	goto st210
tr705:
// line 101 "zparse.rl"
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
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st210
tr706:
// line 101 "zparse.rl"
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
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st210
st210:
	p++
	if p == pe { goto _test_eof210 }
	fallthrough
case 210:
// line 13799 "zparse.go"
	switch data[p] {
		case 9: goto st210
		case 10: goto tr709
		case 32: goto st210
		case 34: goto st0
		case 40: goto tr710
		case 41: goto tr711
		case 59: goto st211
		case 92: goto st0
	}
	goto tr480
tr707:
// line 101 "zparse.rl"
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
	goto st211
st211:
	p++
	if p == pe { goto _test_eof211 }
	fallthrough
case 211:
// line 13829 "zparse.go"
	if data[p] == 10 { goto tr709 }
	goto st211
tr635:
// line 89 "zparse.rl"
	{ mark = p }
	goto st212
st212:
	p++
	if p == pe { goto _test_eof212 }
	fallthrough
case 212:
// line 13841 "zparse.go"
	switch data[p] {
		case 9: goto tr334
		case 10: goto tr335
		case 32: goto tr334
		case 34: goto st0
		case 40: goto tr336
		case 41: goto tr337
		case 59: goto tr338
		case 72: goto st183
		case 78: goto st213
		case 83: goto st183
		case 92: goto st0
		case 104: goto st183
		case 110: goto st213
		case 115: goto st183
	}
	goto st78
st213:
	p++
	if p == pe { goto _test_eof213 }
	fallthrough
case 213:
	switch data[p] {
		case 9: goto tr334
		case 10: goto tr335
		case 32: goto tr334
		case 34: goto st0
		case 40: goto tr336
		case 41: goto tr337
		case 59: goto tr338
		case 65: goto st214
		case 92: goto st0
		case 97: goto st214
	}
	goto st78
st214:
	p++
	if p == pe { goto _test_eof214 }
	fallthrough
case 214:
	switch data[p] {
		case 9: goto tr334
		case 10: goto tr335
		case 32: goto tr334
		case 34: goto st0
		case 40: goto tr336
		case 41: goto tr337
		case 59: goto tr338
		case 77: goto st215
		case 92: goto st0
		case 109: goto st215
	}
	goto st78
st215:
	p++
	if p == pe { goto _test_eof215 }
	fallthrough
case 215:
	switch data[p] {
		case 9: goto tr334
		case 10: goto tr335
		case 32: goto tr334
		case 34: goto st0
		case 40: goto tr336
		case 41: goto tr337
		case 59: goto tr338
		case 69: goto st216
		case 92: goto st0
		case 101: goto st216
	}
	goto st78
st216:
	p++
	if p == pe { goto _test_eof216 }
	fallthrough
case 216:
	switch data[p] {
		case 9: goto tr717
		case 10: goto tr718
		case 32: goto tr717
		case 34: goto st0
		case 40: goto tr719
		case 41: goto tr720
		case 59: goto tr721
		case 92: goto st0
	}
	goto st78
tr636:
// line 89 "zparse.rl"
	{ mark = p }
	goto st217
st217:
	p++
	if p == pe { goto _test_eof217 }
	fallthrough
case 217:
// line 13938 "zparse.go"
	switch data[p] {
		case 9: goto tr334
		case 10: goto tr335
		case 32: goto tr334
		case 34: goto st0
		case 40: goto tr336
		case 41: goto tr337
		case 59: goto tr338
		case 83: goto st183
		case 92: goto st0
		case 115: goto st183
	}
	goto st78
tr637:
// line 89 "zparse.rl"
	{ mark = p }
	goto st218
st218:
	p++
	if p == pe { goto _test_eof218 }
	fallthrough
case 218:
// line 13961 "zparse.go"
	switch data[p] {
		case 9: goto tr334
		case 10: goto tr335
		case 32: goto tr334
		case 34: goto st0
		case 40: goto tr336
		case 41: goto tr337
		case 59: goto tr338
		case 78: goto st183
		case 92: goto st0
		case 110: goto st183
	}
	goto st78
tr331:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st219
tr638:
// line 89 "zparse.rl"
	{ mark = p }
	goto st219
st219:
	p++
	if p == pe { goto _test_eof219 }
	fallthrough
case 219:
// line 13990 "zparse.go"
	switch data[p] {
		case 9: goto tr334
		case 10: goto tr335
		case 32: goto tr334
		case 34: goto st0
		case 40: goto tr336
		case 41: goto tr337
		case 59: goto tr338
		case 88: goto st220
		case 92: goto st0
		case 120: goto st220
	}
	goto st78
st220:
	p++
	if p == pe { goto _test_eof220 }
	fallthrough
case 220:
	switch data[p] {
		case 9: goto tr723
		case 10: goto tr724
		case 32: goto tr723
		case 34: goto st0
		case 40: goto tr725
		case 41: goto tr726
		case 59: goto tr727
		case 92: goto st0
	}
	goto st78
tr639:
// line 89 "zparse.rl"
	{ mark = p }
	goto st221
st221:
	p++
	if p == pe { goto _test_eof221 }
	fallthrough
case 221:
// line 14029 "zparse.go"
	switch data[p] {
		case 9: goto tr334
		case 10: goto tr335
		case 32: goto tr334
		case 34: goto st0
		case 40: goto tr336
		case 41: goto tr337
		case 59: goto tr338
		case 79: goto st222
		case 83: goto st224
		case 92: goto st0
		case 111: goto st222
		case 115: goto st224
	}
	goto st78
st222:
	p++
	if p == pe { goto _test_eof222 }
	fallthrough
case 222:
	switch data[p] {
		case 9: goto tr334
		case 10: goto tr335
		case 32: goto tr334
		case 34: goto st0
		case 40: goto tr336
		case 41: goto tr337
		case 59: goto tr338
		case 78: goto st223
		case 92: goto st0
		case 110: goto st223
	}
	goto st78
st223:
	p++
	if p == pe { goto _test_eof223 }
	fallthrough
case 223:
	switch data[p] {
		case 9: goto tr334
		case 10: goto tr335
		case 32: goto tr334
		case 34: goto st0
		case 40: goto tr336
		case 41: goto tr337
		case 59: goto tr338
		case 69: goto st183
		case 92: goto st0
		case 101: goto st183
	}
	goto st78
st224:
	p++
	if p == pe { goto _test_eof224 }
	fallthrough
case 224:
	switch data[p] {
		case 9: goto tr731
		case 10: goto tr732
		case 32: goto tr731
		case 34: goto st0
		case 40: goto tr733
		case 41: goto tr734
		case 59: goto tr735
		case 92: goto st0
	}
	goto st78
tr617:
// line 90 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
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
	goto st225
st225:
	p++
	if p == pe { goto _test_eof225 }
	fallthrough
case 225:
// line 14117 "zparse.go"
	if data[p] == 10 { goto tr619 }
	goto st225
tr13:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st226
st226:
	p++
	if p == pe { goto _test_eof226 }
	fallthrough
case 226:
// line 14131 "zparse.go"
	switch data[p] {
		case 9: goto tr36
		case 10: goto tr37
		case 32: goto tr36
		case 40: goto tr38
		case 41: goto tr39
		case 59: goto tr40
		case 65: goto st192
		case 78: goto st227
		case 97: goto st192
		case 110: goto st227
	}
	goto st0
st227:
	p++
	if p == pe { goto _test_eof227 }
	fallthrough
case 227:
	switch data[p] {
		case 89: goto st228
		case 121: goto st228
	}
	goto st0
st228:
	p++
	if p == pe { goto _test_eof228 }
	fallthrough
case 228:
	switch data[p] {
		case 9: goto tr738
		case 10: goto tr739
		case 32: goto tr738
		case 40: goto tr740
		case 41: goto tr741
		case 59: goto tr742
	}
	goto st0
tr744:
// line 100 "zparse.rl"
	{ lines++ }
	goto st229
tr745:
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st229
tr746:
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st229
tr738:
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st229
tr739:
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 100 "zparse.rl"
	{ lines++ }
	goto st229
tr740:
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st229
tr741:
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st229
st229:
	p++
	if p == pe { goto _test_eof229 }
	fallthrough
case 229:
// line 14208 "zparse.go"
	switch data[p] {
		case 9: goto st229
		case 10: goto tr744
		case 32: goto st229
		case 40: goto tr745
		case 41: goto tr746
		case 59: goto st233
		case 65: goto tr380
		case 67: goto tr381
		case 77: goto tr34
		case 78: goto tr382
		case 97: goto tr380
		case 99: goto tr381
		case 109: goto tr34
		case 110: goto tr382
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr378 }
	goto st0
tr378:
// line 89 "zparse.rl"
	{ mark = p }
	goto st230
st230:
	p++
	if p == pe { goto _test_eof230 }
	fallthrough
case 230:
// line 14236 "zparse.go"
	switch data[p] {
		case 9: goto tr748
		case 10: goto tr749
		case 32: goto tr748
		case 40: goto tr750
		case 41: goto tr751
		case 59: goto tr753
	}
	if 48 <= data[p] && data[p] <= 57 { goto st230 }
	goto st0
tr755:
// line 100 "zparse.rl"
	{ lines++ }
	goto st231
tr756:
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st231
tr757:
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st231
tr748:
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st231
tr749:
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 100 "zparse.rl"
	{ lines++ }
	goto st231
tr750:
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st231
tr751:
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st231
tr896:
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st231
tr897:
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 100 "zparse.rl"
	{ lines++ }
	goto st231
tr898:
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 97 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st231
tr899:
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 98 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st231
st231:
	p++
	if p == pe { goto _test_eof231 }
	fallthrough
case 231:
// line 14308 "zparse.go"
	switch data[p] {
		case 9: goto st231
		case 10: goto tr755
		case 32: goto st231
		case 40: goto tr756
		case 41: goto tr757
		case 59: goto st232
		case 65: goto tr380
		case 67: goto tr381
		case 77: goto tr34
		case 78: goto tr382
		case 97: goto tr380
		case 99: goto tr381
		case 109: goto tr34
		case 110: goto tr382
	}
	goto st0
tr753:
// line 93 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st232
tr900:
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st232
st232:
	p++
	if p == pe { goto _test_eof232 }
	fallthrough
case 232:
// line 14339 "zparse.go"
	if data[p] == 10 { goto tr755 }
	goto st232
tr742:
// line 91 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st233
st233:
	p++
	if p == pe { goto _test_eof233 }
	fallthrough
case 233:
// line 14351 "zparse.go"
	if data[p] == 10 { goto tr744 }
	goto st233
tr14:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st234
st234:
	p++
	if p == pe { goto _test_eof234 }
	fallthrough
case 234:
// line 14365 "zparse.go"
	switch data[p] {
		case 72: goto st228
		case 78: goto st198
		case 83: goto st228
		case 104: goto st228
		case 110: goto st198
		case 115: goto st228
	}
	goto st0
tr15:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st235
st235:
	p++
	if p == pe { goto _test_eof235 }
	fallthrough
case 235:
// line 14386 "zparse.go"
	switch data[p] {
		case 83: goto st228
		case 115: goto st228
	}
	goto st0
tr16:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st236
st236:
	p++
	if p == pe { goto _test_eof236 }
	fallthrough
case 236:
// line 14403 "zparse.go"
	switch data[p] {
		case 78: goto st228
		case 110: goto st228
	}
	goto st0
tr18:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st237
st237:
	p++
	if p == pe { goto _test_eof237 }
	fallthrough
case 237:
// line 14420 "zparse.go"
	switch data[p] {
		case 79: goto st238
		case 83: goto st209
		case 111: goto st238
		case 115: goto st209
	}
	goto st0
st238:
	p++
	if p == pe { goto _test_eof238 }
	fallthrough
case 238:
	switch data[p] {
		case 78: goto st239
		case 110: goto st239
	}
	goto st0
st239:
	p++
	if p == pe { goto _test_eof239 }
	fallthrough
case 239:
	switch data[p] {
		case 69: goto st228
		case 101: goto st228
	}
	goto st0
tr328:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st240
st240:
	p++
	if p == pe { goto _test_eof240 }
	fallthrough
case 240:
// line 14459 "zparse.go"
	switch data[p] {
		case 9: goto tr334
		case 10: goto tr335
		case 32: goto tr334
		case 34: goto st0
		case 40: goto tr336
		case 41: goto tr337
		case 59: goto tr338
		case 72: goto st89
		case 78: goto st213
		case 83: goto st89
		case 92: goto st0
		case 104: goto st89
		case 110: goto st213
		case 115: goto st89
	}
	goto st78
tr329:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st241
st241:
	p++
	if p == pe { goto _test_eof241 }
	fallthrough
case 241:
// line 14488 "zparse.go"
	switch data[p] {
		case 9: goto tr334
		case 10: goto tr335
		case 32: goto tr334
		case 34: goto st0
		case 40: goto tr336
		case 41: goto tr337
		case 59: goto tr338
		case 83: goto st89
		case 92: goto st0
		case 115: goto st89
	}
	goto st78
tr330:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st242
st242:
	p++
	if p == pe { goto _test_eof242 }
	fallthrough
case 242:
// line 14513 "zparse.go"
	switch data[p] {
		case 9: goto tr334
		case 10: goto tr335
		case 32: goto tr334
		case 34: goto st0
		case 40: goto tr336
		case 41: goto tr337
		case 59: goto tr338
		case 78: goto st89
		case 92: goto st0
		case 110: goto st89
	}
	goto st78
tr332:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st243
st243:
	p++
	if p == pe { goto _test_eof243 }
	fallthrough
case 243:
// line 14538 "zparse.go"
	switch data[p] {
		case 9: goto tr334
		case 10: goto tr335
		case 32: goto tr334
		case 34: goto st0
		case 40: goto tr336
		case 41: goto tr337
		case 59: goto tr338
		case 79: goto st244
		case 83: goto st224
		case 92: goto st0
		case 111: goto st244
		case 115: goto st224
	}
	goto st78
st244:
	p++
	if p == pe { goto _test_eof244 }
	fallthrough
case 244:
	switch data[p] {
		case 9: goto tr334
		case 10: goto tr335
		case 32: goto tr334
		case 34: goto st0
		case 40: goto tr336
		case 41: goto tr337
		case 59: goto tr338
		case 78: goto st245
		case 92: goto st0
		case 110: goto st245
	}
	goto st78
st245:
	p++
	if p == pe { goto _test_eof245 }
	fallthrough
case 245:
	switch data[p] {
		case 9: goto tr334
		case 10: goto tr335
		case 32: goto tr334
		case 34: goto st0
		case 40: goto tr336
		case 41: goto tr337
		case 59: goto tr338
		case 69: goto st89
		case 92: goto st0
		case 101: goto st89
	}
	goto st78
tr906:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st246
tr912:
// line 89 "zparse.rl"
	{ mark = p }
	goto st246
st246:
	p++
	if p == pe { goto _test_eof246 }
	fallthrough
case 246:
// line 14605 "zparse.go"
	switch data[p] {
		case 9: goto tr1
		case 10: goto tr2
		case 32: goto tr1
		case 34: goto st0
		case 40: goto tr4
		case 41: goto tr5
		case 59: goto tr6
		case 83: goto st19
		case 92: goto st0
		case 115: goto st19
	}
	goto st1
tr907:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st247
tr913:
// line 89 "zparse.rl"
	{ mark = p }
	goto st247
st247:
	p++
	if p == pe { goto _test_eof247 }
	fallthrough
case 247:
// line 14634 "zparse.go"
	switch data[p] {
		case 9: goto tr1
		case 10: goto tr2
		case 32: goto tr1
		case 34: goto st0
		case 40: goto tr4
		case 41: goto tr5
		case 59: goto tr6
		case 78: goto st19
		case 92: goto st0
		case 110: goto st19
	}
	goto st1
tr909:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st248
tr915:
// line 89 "zparse.rl"
	{ mark = p }
	goto st248
st248:
	p++
	if p == pe { goto _test_eof248 }
	fallthrough
case 248:
// line 14663 "zparse.go"
	switch data[p] {
		case 9: goto tr1
		case 10: goto tr2
		case 32: goto tr1
		case 34: goto st0
		case 40: goto tr4
		case 41: goto tr5
		case 59: goto tr6
		case 79: goto st249
		case 83: goto st186
		case 92: goto st0
		case 111: goto st249
		case 115: goto st186
	}
	goto st1
st249:
	p++
	if p == pe { goto _test_eof249 }
	fallthrough
case 249:
	switch data[p] {
		case 9: goto tr1
		case 10: goto tr2
		case 32: goto tr1
		case 34: goto st0
		case 40: goto tr4
		case 41: goto tr5
		case 59: goto tr6
		case 78: goto st250
		case 92: goto st0
		case 110: goto st250
	}
	goto st1
st250:
	p++
	if p == pe { goto _test_eof250 }
	fallthrough
case 250:
	switch data[p] {
		case 9: goto tr1
		case 10: goto tr2
		case 32: goto tr1
		case 34: goto st0
		case 40: goto tr4
		case 41: goto tr5
		case 59: goto tr6
		case 69: goto st19
		case 92: goto st0
		case 101: goto st19
	}
	goto st1
tr939:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st251
st251:
	p++
	if p == pe { goto _test_eof251 }
	fallthrough
case 251:
// line 14726 "zparse.go"
	switch data[p] {
		case 9: goto tr260
		case 10: goto tr261
		case 32: goto tr260
		case 34: goto st0
		case 40: goto tr262
		case 41: goto tr263
		case 59: goto tr264
		case 79: goto st252
		case 83: goto st254
		case 92: goto st0
		case 111: goto st252
		case 115: goto st254
	}
	goto st57
st252:
	p++
	if p == pe { goto _test_eof252 }
	fallthrough
case 252:
	switch data[p] {
		case 9: goto tr260
		case 10: goto tr261
		case 32: goto tr260
		case 34: goto st0
		case 40: goto tr262
		case 41: goto tr263
		case 59: goto tr264
		case 78: goto st253
		case 92: goto st0
		case 110: goto st253
	}
	goto st57
st253:
	p++
	if p == pe { goto _test_eof253 }
	fallthrough
case 253:
	switch data[p] {
		case 9: goto tr260
		case 10: goto tr261
		case 32: goto tr260
		case 34: goto st0
		case 40: goto tr262
		case 41: goto tr263
		case 59: goto tr264
		case 69: goto st65
		case 92: goto st0
		case 101: goto st65
	}
	goto st57
st254:
	p++
	if p == pe { goto _test_eof254 }
	fallthrough
case 254:
	switch data[p] {
		case 9: goto tr768
		case 10: goto tr769
		case 32: goto tr768
		case 34: goto st0
		case 40: goto tr770
		case 41: goto tr771
		case 59: goto tr772
		case 92: goto st0
	}
	goto st57
tr126:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st255
st255:
	p++
	if p == pe { goto _test_eof255 }
	fallthrough
case 255:
// line 14805 "zparse.go"
	switch data[p] {
		case 9: goto tr132
		case 10: goto tr133
		case 32: goto tr132
		case 34: goto st0
		case 40: goto tr134
		case 41: goto tr135
		case 59: goto tr136
		case 72: goto st256
		case 78: goto st257
		case 83: goto st256
		case 92: goto st0
		case 104: goto st256
		case 110: goto st257
		case 115: goto st256
	}
	goto st25
st256:
	p++
	if p == pe { goto _test_eof256 }
	fallthrough
case 256:
	switch data[p] {
		case 9: goto tr775
		case 10: goto tr776
		case 32: goto tr775
		case 34: goto st0
		case 40: goto tr777
		case 41: goto tr778
		case 59: goto tr779
		case 92: goto st0
	}
	goto st25
st257:
	p++
	if p == pe { goto _test_eof257 }
	fallthrough
case 257:
	switch data[p] {
		case 9: goto tr132
		case 10: goto tr133
		case 32: goto tr132
		case 34: goto st0
		case 40: goto tr134
		case 41: goto tr135
		case 59: goto tr136
		case 65: goto st258
		case 92: goto st0
		case 97: goto st258
	}
	goto st25
st258:
	p++
	if p == pe { goto _test_eof258 }
	fallthrough
case 258:
	switch data[p] {
		case 9: goto tr132
		case 10: goto tr133
		case 32: goto tr132
		case 34: goto st0
		case 40: goto tr134
		case 41: goto tr135
		case 59: goto tr136
		case 77: goto st259
		case 92: goto st0
		case 109: goto st259
	}
	goto st25
st259:
	p++
	if p == pe { goto _test_eof259 }
	fallthrough
case 259:
	switch data[p] {
		case 9: goto tr132
		case 10: goto tr133
		case 32: goto tr132
		case 34: goto st0
		case 40: goto tr134
		case 41: goto tr135
		case 59: goto tr136
		case 69: goto st260
		case 92: goto st0
		case 101: goto st260
	}
	goto st25
st260:
	p++
	if p == pe { goto _test_eof260 }
	fallthrough
case 260:
	switch data[p] {
		case 9: goto tr783
		case 10: goto tr784
		case 32: goto tr783
		case 34: goto st0
		case 40: goto tr785
		case 41: goto tr786
		case 59: goto tr787
		case 92: goto st0
	}
	goto st25
tr127:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st261
st261:
	p++
	if p == pe { goto _test_eof261 }
	fallthrough
case 261:
// line 14920 "zparse.go"
	switch data[p] {
		case 9: goto tr132
		case 10: goto tr133
		case 32: goto tr132
		case 34: goto st0
		case 40: goto tr134
		case 41: goto tr135
		case 59: goto tr136
		case 83: goto st256
		case 92: goto st0
		case 115: goto st256
	}
	goto st25
tr128:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st262
st262:
	p++
	if p == pe { goto _test_eof262 }
	fallthrough
case 262:
// line 14945 "zparse.go"
	switch data[p] {
		case 9: goto tr132
		case 10: goto tr133
		case 32: goto tr132
		case 34: goto st0
		case 40: goto tr134
		case 41: goto tr135
		case 59: goto tr136
		case 78: goto st256
		case 92: goto st0
		case 110: goto st256
	}
	goto st25
tr129:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st263
st263:
	p++
	if p == pe { goto _test_eof263 }
	fallthrough
case 263:
// line 14970 "zparse.go"
	switch data[p] {
		case 9: goto tr132
		case 10: goto tr133
		case 32: goto tr132
		case 34: goto st0
		case 40: goto tr134
		case 41: goto tr135
		case 59: goto tr136
		case 88: goto st264
		case 92: goto st0
		case 120: goto st264
	}
	goto st25
st264:
	p++
	if p == pe { goto _test_eof264 }
	fallthrough
case 264:
	switch data[p] {
		case 9: goto tr789
		case 10: goto tr790
		case 32: goto tr789
		case 34: goto st0
		case 40: goto tr791
		case 41: goto tr792
		case 59: goto tr793
		case 92: goto st0
	}
	goto st25
tr130:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st265
st265:
	p++
	if p == pe { goto _test_eof265 }
	fallthrough
case 265:
// line 15011 "zparse.go"
	switch data[p] {
		case 9: goto tr132
		case 10: goto tr133
		case 32: goto tr132
		case 34: goto st0
		case 40: goto tr134
		case 41: goto tr135
		case 59: goto tr136
		case 79: goto st266
		case 83: goto st268
		case 92: goto st0
		case 111: goto st266
		case 115: goto st268
	}
	goto st25
st266:
	p++
	if p == pe { goto _test_eof266 }
	fallthrough
case 266:
	switch data[p] {
		case 9: goto tr132
		case 10: goto tr133
		case 32: goto tr132
		case 34: goto st0
		case 40: goto tr134
		case 41: goto tr135
		case 59: goto tr136
		case 78: goto st267
		case 92: goto st0
		case 110: goto st267
	}
	goto st25
st267:
	p++
	if p == pe { goto _test_eof267 }
	fallthrough
case 267:
	switch data[p] {
		case 9: goto tr132
		case 10: goto tr133
		case 32: goto tr132
		case 34: goto st0
		case 40: goto tr134
		case 41: goto tr135
		case 59: goto tr136
		case 69: goto st256
		case 92: goto st0
		case 101: goto st256
	}
	goto st25
st268:
	p++
	if p == pe { goto _test_eof268 }
	fallthrough
case 268:
	switch data[p] {
		case 9: goto tr797
		case 10: goto tr798
		case 32: goto tr797
		case 34: goto st0
		case 40: goto tr799
		case 41: goto tr800
		case 59: goto tr801
		case 92: goto st0
	}
	goto st25
tr928:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st269
st269:
	p++
	if p == pe { goto _test_eof269 }
	fallthrough
case 269:
// line 15090 "zparse.go"
	switch data[p] {
		case 9: goto tr212
		case 10: goto tr213
		case 32: goto tr212
		case 34: goto st0
		case 40: goto tr214
		case 41: goto tr215
		case 59: goto tr216
		case 83: goto st50
		case 92: goto st0
		case 115: goto st50
	}
	goto st42
tr929:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st270
st270:
	p++
	if p == pe { goto _test_eof270 }
	fallthrough
case 270:
// line 15115 "zparse.go"
	switch data[p] {
		case 9: goto tr212
		case 10: goto tr213
		case 32: goto tr212
		case 34: goto st0
		case 40: goto tr214
		case 41: goto tr215
		case 59: goto tr216
		case 78: goto st50
		case 92: goto st0
		case 110: goto st50
	}
	goto st42
tr930:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st271
st271:
	p++
	if p == pe { goto _test_eof271 }
	fallthrough
case 271:
// line 15140 "zparse.go"
	switch data[p] {
		case 9: goto tr212
		case 10: goto tr213
		case 32: goto tr212
		case 34: goto st0
		case 40: goto tr214
		case 41: goto tr215
		case 59: goto tr216
		case 88: goto st272
		case 92: goto st0
		case 120: goto st272
	}
	goto st42
st272:
	p++
	if p == pe { goto _test_eof272 }
	fallthrough
case 272:
	switch data[p] {
		case 9: goto tr803
		case 10: goto tr804
		case 32: goto tr803
		case 34: goto st0
		case 40: goto tr805
		case 41: goto tr806
		case 59: goto tr807
		case 92: goto st0
	}
	goto st42
tr931:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st273
st273:
	p++
	if p == pe { goto _test_eof273 }
	fallthrough
case 273:
// line 15181 "zparse.go"
	switch data[p] {
		case 9: goto tr212
		case 10: goto tr213
		case 32: goto tr212
		case 34: goto st0
		case 40: goto tr214
		case 41: goto tr215
		case 59: goto tr216
		case 79: goto st274
		case 83: goto st276
		case 92: goto st0
		case 111: goto st274
		case 115: goto st276
	}
	goto st42
st274:
	p++
	if p == pe { goto _test_eof274 }
	fallthrough
case 274:
	switch data[p] {
		case 9: goto tr212
		case 10: goto tr213
		case 32: goto tr212
		case 34: goto st0
		case 40: goto tr214
		case 41: goto tr215
		case 59: goto tr216
		case 78: goto st275
		case 92: goto st0
		case 110: goto st275
	}
	goto st42
st275:
	p++
	if p == pe { goto _test_eof275 }
	fallthrough
case 275:
	switch data[p] {
		case 9: goto tr212
		case 10: goto tr213
		case 32: goto tr212
		case 34: goto st0
		case 40: goto tr214
		case 41: goto tr215
		case 59: goto tr216
		case 69: goto st50
		case 92: goto st0
		case 101: goto st50
	}
	goto st42
st276:
	p++
	if p == pe { goto _test_eof276 }
	fallthrough
case 276:
	switch data[p] {
		case 9: goto tr811
		case 10: goto tr812
		case 32: goto tr811
		case 34: goto st0
		case 40: goto tr813
		case 41: goto tr814
		case 59: goto tr815
		case 92: goto st0
	}
	goto st42
st277:
	p++
	if p == pe { goto _test_eof277 }
	fallthrough
case 277:
	switch data[p] {
		case 9: goto tr160
		case 10: goto tr161
		case 32: goto tr160
		case 34: goto st0
		case 40: goto tr162
		case 41: goto tr163
		case 59: goto tr164
		case 89: goto st278
		case 92: goto st0
		case 121: goto st278
	}
	goto st32
st278:
	p++
	if p == pe { goto _test_eof278 }
	fallthrough
case 278:
	switch data[p] {
		case 9: goto tr817
		case 10: goto tr818
		case 32: goto tr817
		case 34: goto st0
		case 40: goto tr819
		case 41: goto tr820
		case 59: goto tr821
		case 92: goto st0
	}
	goto st32
tr919:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st279
st279:
	p++
	if p == pe { goto _test_eof279 }
	fallthrough
case 279:
// line 15294 "zparse.go"
	switch data[p] {
		case 9: goto tr160
		case 10: goto tr161
		case 32: goto tr160
		case 34: goto st0
		case 40: goto tr162
		case 41: goto tr163
		case 59: goto tr164
		case 72: goto st278
		case 78: goto st280
		case 83: goto st278
		case 92: goto st0
		case 104: goto st278
		case 110: goto st280
		case 115: goto st278
	}
	goto st32
st280:
	p++
	if p == pe { goto _test_eof280 }
	fallthrough
case 280:
	switch data[p] {
		case 9: goto tr160
		case 10: goto tr161
		case 32: goto tr160
		case 34: goto st0
		case 40: goto tr162
		case 41: goto tr163
		case 59: goto tr164
		case 65: goto st281
		case 92: goto st0
		case 97: goto st281
	}
	goto st32
st281:
	p++
	if p == pe { goto _test_eof281 }
	fallthrough
case 281:
	switch data[p] {
		case 9: goto tr160
		case 10: goto tr161
		case 32: goto tr160
		case 34: goto st0
		case 40: goto tr162
		case 41: goto tr163
		case 59: goto tr164
		case 77: goto st282
		case 92: goto st0
		case 109: goto st282
	}
	goto st32
st282:
	p++
	if p == pe { goto _test_eof282 }
	fallthrough
case 282:
	switch data[p] {
		case 9: goto tr160
		case 10: goto tr161
		case 32: goto tr160
		case 34: goto st0
		case 40: goto tr162
		case 41: goto tr163
		case 59: goto tr164
		case 69: goto st283
		case 92: goto st0
		case 101: goto st283
	}
	goto st32
st283:
	p++
	if p == pe { goto _test_eof283 }
	fallthrough
case 283:
	switch data[p] {
		case 9: goto tr826
		case 10: goto tr827
		case 32: goto tr826
		case 34: goto st0
		case 40: goto tr828
		case 41: goto tr829
		case 59: goto tr830
		case 92: goto st0
	}
	goto st32
tr920:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st284
st284:
	p++
	if p == pe { goto _test_eof284 }
	fallthrough
case 284:
// line 15393 "zparse.go"
	switch data[p] {
		case 9: goto tr160
		case 10: goto tr161
		case 32: goto tr160
		case 34: goto st0
		case 40: goto tr162
		case 41: goto tr163
		case 59: goto tr164
		case 83: goto st278
		case 92: goto st0
		case 115: goto st278
	}
	goto st32
tr921:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st285
st285:
	p++
	if p == pe { goto _test_eof285 }
	fallthrough
case 285:
// line 15418 "zparse.go"
	switch data[p] {
		case 9: goto tr160
		case 10: goto tr161
		case 32: goto tr160
		case 34: goto st0
		case 40: goto tr162
		case 41: goto tr163
		case 59: goto tr164
		case 78: goto st278
		case 92: goto st0
		case 110: goto st278
	}
	goto st32
tr922:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st286
st286:
	p++
	if p == pe { goto _test_eof286 }
	fallthrough
case 286:
// line 15443 "zparse.go"
	switch data[p] {
		case 9: goto tr160
		case 10: goto tr161
		case 32: goto tr160
		case 34: goto st0
		case 40: goto tr162
		case 41: goto tr163
		case 59: goto tr164
		case 88: goto st287
		case 92: goto st0
		case 120: goto st287
	}
	goto st32
st287:
	p++
	if p == pe { goto _test_eof287 }
	fallthrough
case 287:
	switch data[p] {
		case 9: goto tr832
		case 10: goto tr833
		case 32: goto tr832
		case 34: goto st0
		case 40: goto tr834
		case 41: goto tr835
		case 59: goto tr836
		case 92: goto st0
	}
	goto st32
tr923:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st288
st288:
	p++
	if p == pe { goto _test_eof288 }
	fallthrough
case 288:
// line 15484 "zparse.go"
	switch data[p] {
		case 9: goto tr160
		case 10: goto tr161
		case 32: goto tr160
		case 34: goto st0
		case 40: goto tr162
		case 41: goto tr163
		case 59: goto tr164
		case 79: goto st289
		case 83: goto st291
		case 92: goto st0
		case 111: goto st289
		case 115: goto st291
	}
	goto st32
st289:
	p++
	if p == pe { goto _test_eof289 }
	fallthrough
case 289:
	switch data[p] {
		case 9: goto tr160
		case 10: goto tr161
		case 32: goto tr160
		case 34: goto st0
		case 40: goto tr162
		case 41: goto tr163
		case 59: goto tr164
		case 78: goto st290
		case 92: goto st0
		case 110: goto st290
	}
	goto st32
st290:
	p++
	if p == pe { goto _test_eof290 }
	fallthrough
case 290:
	switch data[p] {
		case 9: goto tr160
		case 10: goto tr161
		case 32: goto tr160
		case 34: goto st0
		case 40: goto tr162
		case 41: goto tr163
		case 59: goto tr164
		case 69: goto st278
		case 92: goto st0
		case 101: goto st278
	}
	goto st32
st291:
	p++
	if p == pe { goto _test_eof291 }
	fallthrough
case 291:
	switch data[p] {
		case 9: goto tr840
		case 10: goto tr841
		case 32: goto tr840
		case 34: goto st0
		case 40: goto tr842
		case 41: goto tr843
		case 59: goto tr844
		case 92: goto st0
	}
	goto st32
tr86:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st292
st292:
	p++
	if p == pe { goto _test_eof292 }
	fallthrough
case 292:
// line 15563 "zparse.go"
	switch data[p] {
		case 9: goto tr845
		case 10: goto tr846
		case 32: goto tr845
		case 34: goto st0
		case 40: goto tr847
		case 41: goto tr848
		case 59: goto tr849
		case 65: goto st293
		case 78: goto st296
		case 92: goto st0
		case 97: goto st293
		case 110: goto st296
	}
	goto st8
st293:
	p++
	if p == pe { goto _test_eof293 }
	fallthrough
case 293:
	switch data[p] {
		case 9: goto tr50
		case 10: goto tr51
		case 32: goto tr50
		case 34: goto st0
		case 40: goto tr52
		case 41: goto tr53
		case 59: goto tr54
		case 65: goto st294
		case 92: goto st0
		case 97: goto st294
	}
	goto st8
st294:
	p++
	if p == pe { goto _test_eof294 }
	fallthrough
case 294:
	switch data[p] {
		case 9: goto tr50
		case 10: goto tr51
		case 32: goto tr50
		case 34: goto st0
		case 40: goto tr52
		case 41: goto tr53
		case 59: goto tr54
		case 65: goto st295
		case 92: goto st0
		case 97: goto st295
	}
	goto st8
st295:
	p++
	if p == pe { goto _test_eof295 }
	fallthrough
case 295:
	switch data[p] {
		case 9: goto tr854
		case 10: goto tr855
		case 32: goto tr854
		case 34: goto st0
		case 40: goto tr856
		case 41: goto tr857
		case 59: goto tr858
		case 92: goto st0
	}
	goto st8
st296:
	p++
	if p == pe { goto _test_eof296 }
	fallthrough
case 296:
	switch data[p] {
		case 9: goto tr50
		case 10: goto tr51
		case 32: goto tr50
		case 34: goto st0
		case 40: goto tr52
		case 41: goto tr53
		case 59: goto tr54
		case 89: goto st297
		case 92: goto st0
		case 121: goto st297
	}
	goto st8
st297:
	p++
	if p == pe { goto _test_eof297 }
	fallthrough
case 297:
	switch data[p] {
		case 9: goto tr860
		case 10: goto tr861
		case 32: goto tr860
		case 34: goto st0
		case 40: goto tr862
		case 41: goto tr863
		case 59: goto tr864
		case 92: goto st0
	}
	goto st8
tr87:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st298
st298:
	p++
	if p == pe { goto _test_eof298 }
	fallthrough
case 298:
// line 15676 "zparse.go"
	switch data[p] {
		case 9: goto tr50
		case 10: goto tr51
		case 32: goto tr50
		case 34: goto st0
		case 40: goto tr52
		case 41: goto tr53
		case 59: goto tr54
		case 72: goto st297
		case 78: goto st299
		case 83: goto st297
		case 92: goto st0
		case 104: goto st297
		case 110: goto st299
		case 115: goto st297
	}
	goto st8
st299:
	p++
	if p == pe { goto _test_eof299 }
	fallthrough
case 299:
	switch data[p] {
		case 9: goto tr50
		case 10: goto tr51
		case 32: goto tr50
		case 34: goto st0
		case 40: goto tr52
		case 41: goto tr53
		case 59: goto tr54
		case 65: goto st300
		case 92: goto st0
		case 97: goto st300
	}
	goto st8
st300:
	p++
	if p == pe { goto _test_eof300 }
	fallthrough
case 300:
	switch data[p] {
		case 9: goto tr50
		case 10: goto tr51
		case 32: goto tr50
		case 34: goto st0
		case 40: goto tr52
		case 41: goto tr53
		case 59: goto tr54
		case 77: goto st301
		case 92: goto st0
		case 109: goto st301
	}
	goto st8
st301:
	p++
	if p == pe { goto _test_eof301 }
	fallthrough
case 301:
	switch data[p] {
		case 9: goto tr50
		case 10: goto tr51
		case 32: goto tr50
		case 34: goto st0
		case 40: goto tr52
		case 41: goto tr53
		case 59: goto tr54
		case 69: goto st302
		case 92: goto st0
		case 101: goto st302
	}
	goto st8
st302:
	p++
	if p == pe { goto _test_eof302 }
	fallthrough
case 302:
	switch data[p] {
		case 9: goto tr869
		case 10: goto tr870
		case 32: goto tr869
		case 34: goto st0
		case 40: goto tr871
		case 41: goto tr872
		case 59: goto tr873
		case 92: goto st0
	}
	goto st8
tr88:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st303
st303:
	p++
	if p == pe { goto _test_eof303 }
	fallthrough
case 303:
// line 15775 "zparse.go"
	switch data[p] {
		case 9: goto tr50
		case 10: goto tr51
		case 32: goto tr50
		case 34: goto st0
		case 40: goto tr52
		case 41: goto tr53
		case 59: goto tr54
		case 83: goto st297
		case 92: goto st0
		case 115: goto st297
	}
	goto st8
tr89:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st304
st304:
	p++
	if p == pe { goto _test_eof304 }
	fallthrough
case 304:
// line 15800 "zparse.go"
	switch data[p] {
		case 9: goto tr50
		case 10: goto tr51
		case 32: goto tr50
		case 34: goto st0
		case 40: goto tr52
		case 41: goto tr53
		case 59: goto tr54
		case 78: goto st297
		case 92: goto st0
		case 110: goto st297
	}
	goto st8
tr90:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st305
st305:
	p++
	if p == pe { goto _test_eof305 }
	fallthrough
case 305:
// line 15825 "zparse.go"
	switch data[p] {
		case 9: goto tr50
		case 10: goto tr51
		case 32: goto tr50
		case 34: goto st0
		case 40: goto tr52
		case 41: goto tr53
		case 59: goto tr54
		case 88: goto st306
		case 92: goto st0
		case 120: goto st306
	}
	goto st8
st306:
	p++
	if p == pe { goto _test_eof306 }
	fallthrough
case 306:
	switch data[p] {
		case 9: goto tr875
		case 10: goto tr876
		case 32: goto tr875
		case 34: goto st0
		case 40: goto tr877
		case 41: goto tr878
		case 59: goto tr879
		case 92: goto st0
	}
	goto st8
tr91:
// line 89 "zparse.rl"
	{ mark = p }
// line 92 "zparse.rl"
	{ /* ... */ }
	goto st307
st307:
	p++
	if p == pe { goto _test_eof307 }
	fallthrough
case 307:
// line 15866 "zparse.go"
	switch data[p] {
		case 9: goto tr50
		case 10: goto tr51
		case 32: goto tr50
		case 34: goto st0
		case 40: goto tr52
		case 41: goto tr53
		case 59: goto tr54
		case 79: goto st308
		case 83: goto st310
		case 92: goto st0
		case 111: goto st308
		case 115: goto st310
	}
	goto st8
st308:
	p++
	if p == pe { goto _test_eof308 }
	fallthrough
case 308:
	switch data[p] {
		case 9: goto tr50
		case 10: goto tr51
		case 32: goto tr50
		case 34: goto st0
		case 40: goto tr52
		case 41: goto tr53
		case 59: goto tr54
		case 78: goto st309
		case 92: goto st0
		case 110: goto st309
	}
	goto st8
st309:
	p++
	if p == pe { goto _test_eof309 }
	fallthrough
case 309:
	switch data[p] {
		case 9: goto tr50
		case 10: goto tr51
		case 32: goto tr50
		case 34: goto st0
		case 40: goto tr52
		case 41: goto tr53
		case 59: goto tr54
		case 69: goto st297
		case 92: goto st0
		case 101: goto st297
	}
	goto st8
st310:
	p++
	if p == pe { goto _test_eof310 }
	fallthrough
case 310:
	switch data[p] {
		case 9: goto tr883
		case 10: goto tr884
		case 32: goto tr883
		case 34: goto st0
		case 40: goto tr885
		case 41: goto tr886
		case 59: goto tr887
		case 92: goto st0
	}
	goto st8
st311:
	p++
	if p == pe { goto _test_eof311 }
	fallthrough
case 311:
	switch data[p] {
		case 9: goto tr132
		case 10: goto tr133
		case 32: goto tr132
		case 34: goto st0
		case 40: goto tr134
		case 41: goto tr135
		case 59: goto tr136
		case 65: goto st312
		case 92: goto st0
		case 97: goto st312
	}
	goto st25
st312:
	p++
	if p == pe { goto _test_eof312 }
	fallthrough
case 312:
	switch data[p] {
		case 9: goto tr132
		case 10: goto tr133
		case 32: goto tr132
		case 34: goto st0
		case 40: goto tr134
		case 41: goto tr135
		case 59: goto tr136
		case 65: goto st313
		case 92: goto st0
		case 97: goto st313
	}
	goto st25
st313:
	p++
	if p == pe { goto _test_eof313 }
	fallthrough
case 313:
	switch data[p] {
		case 9: goto tr890
		case 10: goto tr891
		case 32: goto tr890
		case 34: goto st0
		case 40: goto tr892
		case 41: goto tr893
		case 59: goto tr894
		case 92: goto st0
	}
	goto st25
st314:
	p++
	if p == pe { goto _test_eof314 }
	fallthrough
case 314:
	switch data[p] {
		case 9: goto tr132
		case 10: goto tr133
		case 32: goto tr132
		case 34: goto st0
		case 40: goto tr134
		case 41: goto tr135
		case 59: goto tr136
		case 89: goto st256
		case 92: goto st0
		case 121: goto st256
	}
	goto st25
tr31:
// line 89 "zparse.rl"
	{ mark = p }
	goto st315
st315:
	p++
	if p == pe { goto _test_eof315 }
	fallthrough
case 315:
// line 16013 "zparse.go"
	switch data[p] {
		case 72: goto st316
		case 78: goto st198
		case 83: goto st316
		case 104: goto st316
		case 110: goto st198
		case 115: goto st316
	}
	goto st0
st316:
	p++
	if p == pe { goto _test_eof316 }
	fallthrough
case 316:
	switch data[p] {
		case 9: goto tr896
		case 10: goto tr897
		case 32: goto tr896
		case 40: goto tr898
		case 41: goto tr899
		case 59: goto tr900
	}
	goto st0
tr32:
// line 89 "zparse.rl"
	{ mark = p }
	goto st317
st317:
	p++
	if p == pe { goto _test_eof317 }
	fallthrough
case 317:
// line 16046 "zparse.go"
	switch data[p] {
		case 83: goto st316
		case 115: goto st316
	}
	goto st0
tr33:
// line 89 "zparse.rl"
	{ mark = p }
	goto st318
st318:
	p++
	if p == pe { goto _test_eof318 }
	fallthrough
case 318:
// line 16061 "zparse.go"
	switch data[p] {
		case 78: goto st316
		case 110: goto st316
	}
	goto st0
tr35:
// line 89 "zparse.rl"
	{ mark = p }
	goto st319
st319:
	p++
	if p == pe { goto _test_eof319 }
	fallthrough
case 319:
// line 16076 "zparse.go"
	switch data[p] {
		case 79: goto st320
		case 83: goto st209
		case 111: goto st320
		case 115: goto st209
	}
	goto st0
st320:
	p++
	if p == pe { goto _test_eof320 }
	fallthrough
case 320:
	switch data[p] {
		case 78: goto st321
		case 110: goto st321
	}
	goto st0
st321:
	p++
	if p == pe { goto _test_eof321 }
	fallthrough
case 321:
	switch data[p] {
		case 69: goto st316
		case 101: goto st316
	}
	goto st0
st322:
	p++
	if p == pe { goto _test_eof322 }
	fallthrough
case 322:
	switch data[p] {
		case 9: goto tr1
		case 10: goto tr2
		case 32: goto tr1
		case 34: goto st0
		case 40: goto tr4
		case 41: goto tr5
		case 59: goto tr6
		case 89: goto st19
		case 92: goto st0
		case 121: goto st19
	}
	goto st1
st323:
	p++
	if p == pe { goto _test_eof323 }
	fallthrough
case 323:
	switch data[p] {
		case 89: goto st316
		case 121: goto st316
	}
	goto st0
	}
	_test_eof1: cs = 1; goto _test_eof; 
	_test_eof2: cs = 2; goto _test_eof; 
	_test_eof3: cs = 3; goto _test_eof; 
	_test_eof4: cs = 4; goto _test_eof; 
	_test_eof5: cs = 5; goto _test_eof; 
	_test_eof6: cs = 6; goto _test_eof; 
	_test_eof7: cs = 7; goto _test_eof; 
	_test_eof8: cs = 8; goto _test_eof; 
	_test_eof9: cs = 9; goto _test_eof; 
	_test_eof325: cs = 325; goto _test_eof; 
	_test_eof10: cs = 10; goto _test_eof; 
	_test_eof326: cs = 326; goto _test_eof; 
	_test_eof11: cs = 11; goto _test_eof; 
	_test_eof12: cs = 12; goto _test_eof; 
	_test_eof13: cs = 13; goto _test_eof; 
	_test_eof14: cs = 14; goto _test_eof; 
	_test_eof15: cs = 15; goto _test_eof; 
	_test_eof16: cs = 16; goto _test_eof; 
	_test_eof17: cs = 17; goto _test_eof; 
	_test_eof327: cs = 327; goto _test_eof; 
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
	_test_eof328: cs = 328; goto _test_eof; 
	_test_eof32: cs = 32; goto _test_eof; 
	_test_eof33: cs = 33; goto _test_eof; 
	_test_eof329: cs = 329; goto _test_eof; 
	_test_eof34: cs = 34; goto _test_eof; 
	_test_eof35: cs = 35; goto _test_eof; 
	_test_eof36: cs = 36; goto _test_eof; 
	_test_eof37: cs = 37; goto _test_eof; 
	_test_eof38: cs = 38; goto _test_eof; 
	_test_eof39: cs = 39; goto _test_eof; 
	_test_eof40: cs = 40; goto _test_eof; 
	_test_eof41: cs = 41; goto _test_eof; 
	_test_eof330: cs = 330; goto _test_eof; 
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
	_test_eof331: cs = 331; goto _test_eof; 
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
	_test_eof332: cs = 332; goto _test_eof; 
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
	_test_eof333: cs = 333; goto _test_eof; 
	_test_eof87: cs = 87; goto _test_eof; 
	_test_eof88: cs = 88; goto _test_eof; 
	_test_eof89: cs = 89; goto _test_eof; 
	_test_eof90: cs = 90; goto _test_eof; 
	_test_eof334: cs = 334; goto _test_eof; 
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
	_test_eof335: cs = 335; goto _test_eof; 
	_test_eof112: cs = 112; goto _test_eof; 
	_test_eof113: cs = 113; goto _test_eof; 
	_test_eof114: cs = 114; goto _test_eof; 
	_test_eof115: cs = 115; goto _test_eof; 
	_test_eof116: cs = 116; goto _test_eof; 
	_test_eof117: cs = 117; goto _test_eof; 
	_test_eof336: cs = 336; goto _test_eof; 
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
	_test_eof337: cs = 337; goto _test_eof; 
	_test_eof130: cs = 130; goto _test_eof; 
	_test_eof131: cs = 131; goto _test_eof; 
	_test_eof338: cs = 338; goto _test_eof; 
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
	_test_eof148: cs = 148; goto _test_eof; 
	_test_eof149: cs = 149; goto _test_eof; 
	_test_eof150: cs = 150; goto _test_eof; 
	_test_eof151: cs = 151; goto _test_eof; 
	_test_eof152: cs = 152; goto _test_eof; 
	_test_eof153: cs = 153; goto _test_eof; 
	_test_eof154: cs = 154; goto _test_eof; 
	_test_eof155: cs = 155; goto _test_eof; 
	_test_eof156: cs = 156; goto _test_eof; 
	_test_eof157: cs = 157; goto _test_eof; 
	_test_eof158: cs = 158; goto _test_eof; 
	_test_eof159: cs = 159; goto _test_eof; 
	_test_eof160: cs = 160; goto _test_eof; 
	_test_eof161: cs = 161; goto _test_eof; 
	_test_eof162: cs = 162; goto _test_eof; 
	_test_eof163: cs = 163; goto _test_eof; 
	_test_eof164: cs = 164; goto _test_eof; 
	_test_eof165: cs = 165; goto _test_eof; 
	_test_eof166: cs = 166; goto _test_eof; 
	_test_eof167: cs = 167; goto _test_eof; 
	_test_eof168: cs = 168; goto _test_eof; 
	_test_eof169: cs = 169; goto _test_eof; 
	_test_eof170: cs = 170; goto _test_eof; 
	_test_eof171: cs = 171; goto _test_eof; 
	_test_eof172: cs = 172; goto _test_eof; 
	_test_eof173: cs = 173; goto _test_eof; 
	_test_eof174: cs = 174; goto _test_eof; 
	_test_eof175: cs = 175; goto _test_eof; 
	_test_eof176: cs = 176; goto _test_eof; 
	_test_eof177: cs = 177; goto _test_eof; 
	_test_eof178: cs = 178; goto _test_eof; 
	_test_eof179: cs = 179; goto _test_eof; 
	_test_eof180: cs = 180; goto _test_eof; 
	_test_eof181: cs = 181; goto _test_eof; 
	_test_eof182: cs = 182; goto _test_eof; 
	_test_eof183: cs = 183; goto _test_eof; 
	_test_eof184: cs = 184; goto _test_eof; 
	_test_eof339: cs = 339; goto _test_eof; 
	_test_eof185: cs = 185; goto _test_eof; 
	_test_eof186: cs = 186; goto _test_eof; 
	_test_eof187: cs = 187; goto _test_eof; 
	_test_eof188: cs = 188; goto _test_eof; 
	_test_eof189: cs = 189; goto _test_eof; 
	_test_eof190: cs = 190; goto _test_eof; 
	_test_eof191: cs = 191; goto _test_eof; 
	_test_eof192: cs = 192; goto _test_eof; 
	_test_eof193: cs = 193; goto _test_eof; 
	_test_eof194: cs = 194; goto _test_eof; 
	_test_eof195: cs = 195; goto _test_eof; 
	_test_eof196: cs = 196; goto _test_eof; 
	_test_eof197: cs = 197; goto _test_eof; 
	_test_eof198: cs = 198; goto _test_eof; 
	_test_eof199: cs = 199; goto _test_eof; 
	_test_eof200: cs = 200; goto _test_eof; 
	_test_eof201: cs = 201; goto _test_eof; 
	_test_eof202: cs = 202; goto _test_eof; 
	_test_eof203: cs = 203; goto _test_eof; 
	_test_eof204: cs = 204; goto _test_eof; 
	_test_eof205: cs = 205; goto _test_eof; 
	_test_eof206: cs = 206; goto _test_eof; 
	_test_eof207: cs = 207; goto _test_eof; 
	_test_eof208: cs = 208; goto _test_eof; 
	_test_eof209: cs = 209; goto _test_eof; 
	_test_eof210: cs = 210; goto _test_eof; 
	_test_eof211: cs = 211; goto _test_eof; 
	_test_eof212: cs = 212; goto _test_eof; 
	_test_eof213: cs = 213; goto _test_eof; 
	_test_eof214: cs = 214; goto _test_eof; 
	_test_eof215: cs = 215; goto _test_eof; 
	_test_eof216: cs = 216; goto _test_eof; 
	_test_eof217: cs = 217; goto _test_eof; 
	_test_eof218: cs = 218; goto _test_eof; 
	_test_eof219: cs = 219; goto _test_eof; 
	_test_eof220: cs = 220; goto _test_eof; 
	_test_eof221: cs = 221; goto _test_eof; 
	_test_eof222: cs = 222; goto _test_eof; 
	_test_eof223: cs = 223; goto _test_eof; 
	_test_eof224: cs = 224; goto _test_eof; 
	_test_eof225: cs = 225; goto _test_eof; 
	_test_eof226: cs = 226; goto _test_eof; 
	_test_eof227: cs = 227; goto _test_eof; 
	_test_eof228: cs = 228; goto _test_eof; 
	_test_eof229: cs = 229; goto _test_eof; 
	_test_eof230: cs = 230; goto _test_eof; 
	_test_eof231: cs = 231; goto _test_eof; 
	_test_eof232: cs = 232; goto _test_eof; 
	_test_eof233: cs = 233; goto _test_eof; 
	_test_eof234: cs = 234; goto _test_eof; 
	_test_eof235: cs = 235; goto _test_eof; 
	_test_eof236: cs = 236; goto _test_eof; 
	_test_eof237: cs = 237; goto _test_eof; 
	_test_eof238: cs = 238; goto _test_eof; 
	_test_eof239: cs = 239; goto _test_eof; 
	_test_eof240: cs = 240; goto _test_eof; 
	_test_eof241: cs = 241; goto _test_eof; 
	_test_eof242: cs = 242; goto _test_eof; 
	_test_eof243: cs = 243; goto _test_eof; 
	_test_eof244: cs = 244; goto _test_eof; 
	_test_eof245: cs = 245; goto _test_eof; 
	_test_eof246: cs = 246; goto _test_eof; 
	_test_eof247: cs = 247; goto _test_eof; 
	_test_eof248: cs = 248; goto _test_eof; 
	_test_eof249: cs = 249; goto _test_eof; 
	_test_eof250: cs = 250; goto _test_eof; 
	_test_eof251: cs = 251; goto _test_eof; 
	_test_eof252: cs = 252; goto _test_eof; 
	_test_eof253: cs = 253; goto _test_eof; 
	_test_eof254: cs = 254; goto _test_eof; 
	_test_eof255: cs = 255; goto _test_eof; 
	_test_eof256: cs = 256; goto _test_eof; 
	_test_eof257: cs = 257; goto _test_eof; 
	_test_eof258: cs = 258; goto _test_eof; 
	_test_eof259: cs = 259; goto _test_eof; 
	_test_eof260: cs = 260; goto _test_eof; 
	_test_eof261: cs = 261; goto _test_eof; 
	_test_eof262: cs = 262; goto _test_eof; 
	_test_eof263: cs = 263; goto _test_eof; 
	_test_eof264: cs = 264; goto _test_eof; 
	_test_eof265: cs = 265; goto _test_eof; 
	_test_eof266: cs = 266; goto _test_eof; 
	_test_eof267: cs = 267; goto _test_eof; 
	_test_eof268: cs = 268; goto _test_eof; 
	_test_eof269: cs = 269; goto _test_eof; 
	_test_eof270: cs = 270; goto _test_eof; 
	_test_eof271: cs = 271; goto _test_eof; 
	_test_eof272: cs = 272; goto _test_eof; 
	_test_eof273: cs = 273; goto _test_eof; 
	_test_eof274: cs = 274; goto _test_eof; 
	_test_eof275: cs = 275; goto _test_eof; 
	_test_eof276: cs = 276; goto _test_eof; 
	_test_eof277: cs = 277; goto _test_eof; 
	_test_eof278: cs = 278; goto _test_eof; 
	_test_eof279: cs = 279; goto _test_eof; 
	_test_eof280: cs = 280; goto _test_eof; 
	_test_eof281: cs = 281; goto _test_eof; 
	_test_eof282: cs = 282; goto _test_eof; 
	_test_eof283: cs = 283; goto _test_eof; 
	_test_eof284: cs = 284; goto _test_eof; 
	_test_eof285: cs = 285; goto _test_eof; 
	_test_eof286: cs = 286; goto _test_eof; 
	_test_eof287: cs = 287; goto _test_eof; 
	_test_eof288: cs = 288; goto _test_eof; 
	_test_eof289: cs = 289; goto _test_eof; 
	_test_eof290: cs = 290; goto _test_eof; 
	_test_eof291: cs = 291; goto _test_eof; 
	_test_eof292: cs = 292; goto _test_eof; 
	_test_eof293: cs = 293; goto _test_eof; 
	_test_eof294: cs = 294; goto _test_eof; 
	_test_eof295: cs = 295; goto _test_eof; 
	_test_eof296: cs = 296; goto _test_eof; 
	_test_eof297: cs = 297; goto _test_eof; 
	_test_eof298: cs = 298; goto _test_eof; 
	_test_eof299: cs = 299; goto _test_eof; 
	_test_eof300: cs = 300; goto _test_eof; 
	_test_eof301: cs = 301; goto _test_eof; 
	_test_eof302: cs = 302; goto _test_eof; 
	_test_eof303: cs = 303; goto _test_eof; 
	_test_eof304: cs = 304; goto _test_eof; 
	_test_eof305: cs = 305; goto _test_eof; 
	_test_eof306: cs = 306; goto _test_eof; 
	_test_eof307: cs = 307; goto _test_eof; 
	_test_eof308: cs = 308; goto _test_eof; 
	_test_eof309: cs = 309; goto _test_eof; 
	_test_eof310: cs = 310; goto _test_eof; 
	_test_eof311: cs = 311; goto _test_eof; 
	_test_eof312: cs = 312; goto _test_eof; 
	_test_eof313: cs = 313; goto _test_eof; 
	_test_eof314: cs = 314; goto _test_eof; 
	_test_eof315: cs = 315; goto _test_eof; 
	_test_eof316: cs = 316; goto _test_eof; 
	_test_eof317: cs = 317; goto _test_eof; 
	_test_eof318: cs = 318; goto _test_eof; 
	_test_eof319: cs = 319; goto _test_eof; 
	_test_eof320: cs = 320; goto _test_eof; 
	_test_eof321: cs = 321; goto _test_eof; 
	_test_eof322: cs = 322; goto _test_eof; 
	_test_eof323: cs = 323; goto _test_eof; 

	_test_eof: {}
	_out: {}
	}

// line 163 "zparse.rl"

        
        if eof > -1 {
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
        }
        return z, nil
}
