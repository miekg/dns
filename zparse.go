
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
        ts, te, act := 0, 0, 0
//        top := 0
//        stack := make([]int, 100)
        eof := len(data)
        // keep Go happy
        ts = ts; te = te; act = act

        brace := false
        lines := 0
        mark := 0
        hdr := new(RR_Header)
        tok := newToken()
        var rr RR

        
// line 105 "zparse.go"
	cs = z_start

// line 108 "zparse.go"
	{
	if p == pe { goto _test_eof }
	switch cs {
	case -666: // i am a hack D:
	fallthrough
case 324:
	switch data[p] {
		case 9: goto st10
		case 10: goto tr67
		case 32: goto st10
		case 34: goto st0
		case 40: goto tr57
		case 41: goto tr58
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
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
	goto st2
tr2:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 106 "zparse.rl"
	{ lines++ }
	goto st2
tr4:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st2
tr5:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st2
tr8:
// line 106 "zparse.rl"
	{ lines++ }
	goto st2
tr9:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st2
tr10:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st2
tr60:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st2
tr61:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 106 "zparse.rl"
	{ lines++ }
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st2
tr62:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st2
tr63:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st2
tr100:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st2
tr101:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 106 "zparse.rl"
	{ lines++ }
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st2
tr102:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st2
tr103:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st2
st2:
	p++
	if p == pe { goto _test_eof2 }
	fallthrough
case 2:
// line 241 "zparse.go"
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
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st3
st3:
	p++
	if p == pe { goto _test_eof3 }
	fallthrough
case 3:
// line 278 "zparse.go"
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
// line 106 "zparse.rl"
	{ lines++ }
	goto st4
tr27:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st4
tr28:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st4
tr19:
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st4
tr20:
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 106 "zparse.rl"
	{ lines++ }
	goto st4
tr21:
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st4
tr22:
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st4
st4:
	p++
	if p == pe { goto _test_eof4 }
	fallthrough
case 4:
// line 328 "zparse.go"
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
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st5
st5:
	p++
	if p == pe { goto _test_eof5 }
	fallthrough
case 5:
// line 359 "zparse.go"
	if data[p] == 10 { goto tr26 }
	goto st5
tr30:
// line 95 "zparse.rl"
	{ mark = p }
	goto st6
st6:
	p++
	if p == pe { goto _test_eof6 }
	fallthrough
case 6:
// line 371 "zparse.go"
	switch data[p] {
		case 9: goto st7
		case 10: goto tr37
		case 32: goto st7
		case 40: goto tr38
		case 41: goto tr39
		case 59: goto st191
		case 65: goto st192
		case 78: goto st323
		case 97: goto st192
		case 110: goto st323
	}
	goto st0
tr37:
// line 106 "zparse.rl"
	{ lines++ }
	goto st7
tr38:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st7
tr39:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st7
st7:
	p++
	if p == pe { goto _test_eof7 }
	fallthrough
case 7:
// line 402 "zparse.go"
	switch data[p] {
		case 9: goto st7
		case 10: goto tr37
		case 32: goto st7
		case 34: goto st0
		case 40: goto tr38
		case 41: goto tr39
		case 59: goto st191
		case 92: goto st0
	}
	goto tr43
tr43:
// line 95 "zparse.rl"
	{ mark = p }
	goto st8
st8:
	p++
	if p == pe { goto _test_eof8 }
	fallthrough
case 8:
// line 423 "zparse.go"
	switch data[p] {
		case 9: goto tr45
		case 10: goto tr46
		case 32: goto tr45
		case 34: goto st0
		case 40: goto tr47
		case 41: goto tr48
		case 59: goto tr49
		case 92: goto st0
	}
	goto st8
tr52:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st9
tr53:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st9
tr45:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st9
tr47:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st9
tr48:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st9
tr127:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st9
tr129:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st9
tr130:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st9
tr201:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st9
tr203:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st9
tr204:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st9
tr329:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr = new(RR_MX)
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeMX
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st9
tr331:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr = new(RR_MX)
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeMX
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st9
tr332:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr = new(RR_MX)
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeMX
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st9
tr482:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st9
tr484:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st9
tr485:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st9
st9:
	p++
	if p == pe { goto _test_eof9 }
	fallthrough
case 9:
// line 681 "zparse.go"
	switch data[p] {
		case 9: goto st9
		case 10: goto tr51
		case 32: goto st9
		case 40: goto tr52
		case 41: goto tr53
		case 59: goto tr54
	}
	goto st0
tr133:
// line 106 "zparse.rl"
	{ lines++ }
	goto st325
tr46:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
// line 106 "zparse.rl"
	{ lines++ }
	goto st325
tr51:
// line 106 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ mark = p }
	goto st325
tr128:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
// line 106 "zparse.rl"
	{ lines++ }
	goto st325
tr202:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
// line 106 "zparse.rl"
	{ lines++ }
	goto st325
tr330:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr = new(RR_MX)
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeMX
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
// line 106 "zparse.rl"
	{ lines++ }
	goto st325
tr483:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
// line 106 "zparse.rl"
	{ lines++ }
	goto st325
st325:
	p++
	if p == pe { goto _test_eof325 }
	fallthrough
case 325:
// line 787 "zparse.go"
	switch data[p] {
		case 9: goto st10
		case 10: goto tr56
		case 32: goto st10
		case 34: goto st0
		case 40: goto tr57
		case 41: goto tr58
		case 59: goto tr59
		case 92: goto st0
	}
	goto st1
tr57:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st10
tr58:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st10
tr155:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st10
tr157:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st10
tr158:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st10
tr165:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st10
tr167:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st10
tr168:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st10
tr207:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st10
tr209:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st10
tr210:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st10
tr212:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st10
tr214:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st10
tr215:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st10
tr235:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st10
tr237:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st10
tr238:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st10
tr255:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st10
tr257:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st10
tr258:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st10
tr260:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st10
tr262:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st10
tr263:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st10
tr283:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st10
tr285:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st10
tr286:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st10
tr488:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st10
tr490:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st10
tr491:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st10
tr505:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st10
tr507:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st10
tr508:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st10
tr528:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st10
tr530:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st10
tr531:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st10
tr792:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st10
tr794:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st10
tr795:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st10
st10:
	p++
	if p == pe { goto _test_eof10 }
	fallthrough
case 10:
// line 1484 "zparse.go"
	switch data[p] {
		case 9: goto st10
		case 10: goto tr56
		case 32: goto st10
		case 40: goto tr57
		case 41: goto tr58
		case 59: goto tr59
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
tr67:
// line 106 "zparse.rl"
	{ lines++ }
	goto st326
tr56:
// line 106 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ mark = p }
	goto st326
tr156:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st326
tr166:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 106 "zparse.rl"
	{ lines++ }
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st326
tr208:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st326
tr213:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 106 "zparse.rl"
	{ lines++ }
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st326
tr236:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 106 "zparse.rl"
	{ lines++ }
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st326
tr256:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st326
tr261:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 106 "zparse.rl"
	{ lines++ }
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st326
tr284:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 106 "zparse.rl"
	{ lines++ }
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st326
tr489:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st326
tr506:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 106 "zparse.rl"
	{ lines++ }
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st326
tr529:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 106 "zparse.rl"
	{ lines++ }
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st326
tr793:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 106 "zparse.rl"
	{ lines++ }
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st326
st326:
	p++
	if p == pe { goto _test_eof326 }
	fallthrough
case 326:
// line 1754 "zparse.go"
	switch data[p] {
		case 9: goto st10
		case 10: goto tr56
		case 32: goto st10
		case 34: goto st0
		case 40: goto tr57
		case 41: goto tr58
		case 59: goto tr59
		case 65: goto tr879
		case 67: goto tr880
		case 72: goto tr881
		case 73: goto tr882
		case 77: goto tr883
		case 78: goto tr884
		case 92: goto st0
		case 97: goto tr879
		case 99: goto tr880
		case 104: goto tr881
		case 105: goto tr882
		case 109: goto tr883
		case 110: goto tr884
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr878 }
	goto st1
tr878:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st11
tr916:
// line 95 "zparse.rl"
	{ mark = p }
	goto st11
st11:
	p++
	if p == pe { goto _test_eof11 }
	fallthrough
case 11:
// line 1794 "zparse.go"
	switch data[p] {
		case 9: goto tr60
		case 10: goto tr61
		case 32: goto tr60
		case 34: goto st0
		case 40: goto tr62
		case 41: goto tr63
		case 59: goto tr65
		case 92: goto st0
	}
	if 48 <= data[p] && data[p] <= 57 { goto st11 }
	goto st1
tr6:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
	goto st12
tr65:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st12
tr104:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st12
st12:
	p++
	if p == pe { goto _test_eof12 }
	fallthrough
case 12:
// line 1828 "zparse.go"
	if data[p] == 10 { goto tr8 }
	goto st12
tr59:
// line 95 "zparse.rl"
	{ mark = p }
	goto st13
tr159:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st13
tr170:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st13
tr211:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st13
tr217:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st13
tr239:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st13
tr259:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st13
tr265:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st13
tr287:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st13
tr492:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st13
tr510:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st13
tr532:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st13
tr796:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st13
st13:
	p++
	if p == pe { goto _test_eof13 }
	fallthrough
case 13:
// line 2048 "zparse.go"
	if data[p] == 10 { goto tr67 }
	goto st13
tr879:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st14
tr885:
// line 95 "zparse.rl"
	{ mark = p }
	goto st14
st14:
	p++
	if p == pe { goto _test_eof14 }
	fallthrough
case 14:
// line 2066 "zparse.go"
	switch data[p] {
		case 9: goto tr68
		case 10: goto tr69
		case 32: goto tr68
		case 34: goto st0
		case 40: goto tr70
		case 41: goto tr71
		case 59: goto tr72
		case 65: goto st93
		case 78: goto st322
		case 92: goto st0
		case 97: goto st93
		case 110: goto st322
	}
	goto st1
tr68:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
	goto st15
tr69:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 106 "zparse.rl"
	{ lines++ }
	goto st15
tr70:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st15
tr71:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st15
tr76:
// line 106 "zparse.rl"
	{ lines++ }
	goto st15
tr77:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st15
tr78:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st15
st15:
	p++
	if p == pe { goto _test_eof15 }
	fallthrough
case 15:
// line 2121 "zparse.go"
	switch data[p] {
		case 9: goto st15
		case 10: goto tr76
		case 32: goto st15
		case 34: goto st0
		case 40: goto tr77
		case 41: goto tr78
		case 59: goto st92
		case 65: goto tr81
		case 67: goto tr82
		case 72: goto tr83
		case 73: goto tr84
		case 77: goto tr85
		case 78: goto tr86
		case 92: goto st0
		case 97: goto tr81
		case 99: goto tr82
		case 104: goto tr83
		case 105: goto tr84
		case 109: goto tr85
		case 110: goto tr86
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr79 }
	goto tr43
tr79:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st16
st16:
	p++
	if p == pe { goto _test_eof16 }
	fallthrough
case 16:
// line 2157 "zparse.go"
	switch data[p] {
		case 9: goto tr87
		case 10: goto tr88
		case 32: goto tr87
		case 34: goto st0
		case 40: goto tr89
		case 41: goto tr90
		case 59: goto tr92
		case 92: goto st0
	}
	if 48 <= data[p] && data[p] <= 57 { goto st16 }
	goto st8
tr95:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st17
tr96:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st17
tr87:
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st17
tr89:
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st17
tr90:
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st17
tr134:
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st17
tr136:
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st17
tr137:
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st17
tr334:
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr = new(RR_MX)
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeMX
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st17
tr336:
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr = new(RR_MX)
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeMX
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st17
tr337:
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr = new(RR_MX)
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeMX
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st17
tr390:
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st17
tr392:
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st17
tr393:
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st17
tr556:
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st17
tr558:
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st17
tr559:
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st17
st17:
	p++
	if p == pe { goto _test_eof17 }
	fallthrough
case 17:
// line 2446 "zparse.go"
	switch data[p] {
		case 9: goto st17
		case 10: goto tr94
		case 32: goto st17
		case 40: goto tr95
		case 41: goto tr96
		case 59: goto tr97
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
tr141:
// line 106 "zparse.rl"
	{ lines++ }
	goto st327
tr94:
// line 106 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ mark = p }
	goto st327
tr88:
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st327
tr135:
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st327
tr335:
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr = new(RR_MX)
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeMX
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st327
tr391:
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st327
tr557:
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st327
st327:
	p++
	if p == pe { goto _test_eof327 }
	fallthrough
case 327:
// line 2574 "zparse.go"
	switch data[p] {
		case 9: goto st10
		case 10: goto tr56
		case 32: goto st10
		case 34: goto st0
		case 40: goto tr57
		case 41: goto tr58
		case 59: goto tr59
		case 65: goto tr885
		case 67: goto tr886
		case 72: goto tr887
		case 73: goto tr888
		case 77: goto tr889
		case 78: goto tr890
		case 92: goto st0
		case 97: goto tr885
		case 99: goto tr886
		case 104: goto tr887
		case 105: goto tr888
		case 109: goto tr889
		case 110: goto tr890
	}
	goto st1
tr880:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st18
tr886:
// line 95 "zparse.rl"
	{ mark = p }
	goto st18
st18:
	p++
	if p == pe { goto _test_eof18 }
	fallthrough
case 18:
// line 2613 "zparse.go"
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
		case 9: goto tr100
		case 10: goto tr101
		case 32: goto tr100
		case 34: goto st0
		case 40: goto tr102
		case 41: goto tr103
		case 59: goto tr104
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
		case 9: goto tr108
		case 10: goto tr109
		case 32: goto tr108
		case 34: goto st0
		case 40: goto tr110
		case 41: goto tr111
		case 59: goto tr112
		case 92: goto st0
	}
	goto st1
tr108:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
	goto st24
tr109:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 106 "zparse.rl"
	{ lines++ }
	goto st24
tr110:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st24
tr111:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st24
tr115:
// line 106 "zparse.rl"
	{ lines++ }
	goto st24
tr116:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st24
tr117:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st24
st24:
	p++
	if p == pe { goto _test_eof24 }
	fallthrough
case 24:
// line 2756 "zparse.go"
	switch data[p] {
		case 9: goto st24
		case 10: goto tr115
		case 32: goto st24
		case 34: goto st0
		case 40: goto tr116
		case 41: goto tr117
		case 59: goto st29
		case 65: goto tr120
		case 67: goto tr121
		case 72: goto tr122
		case 73: goto tr123
		case 77: goto tr124
		case 78: goto tr125
		case 92: goto st0
		case 97: goto tr120
		case 99: goto tr121
		case 104: goto tr122
		case 105: goto tr123
		case 109: goto tr124
		case 110: goto tr125
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr118 }
	goto tr113
tr113:
// line 95 "zparse.rl"
	{ mark = p }
	goto st25
st25:
	p++
	if p == pe { goto _test_eof25 }
	fallthrough
case 25:
// line 2790 "zparse.go"
	switch data[p] {
		case 9: goto tr127
		case 10: goto tr128
		case 32: goto tr127
		case 34: goto st0
		case 40: goto tr129
		case 41: goto tr130
		case 59: goto tr131
		case 92: goto st0
	}
	goto st25
tr54:
// line 95 "zparse.rl"
	{ mark = p }
	goto st26
tr49:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st26
tr131:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st26
tr205:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st26
tr333:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr = new(RR_MX)
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeMX
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st26
tr486:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st26
st26:
	p++
	if p == pe { goto _test_eof26 }
	fallthrough
case 26:
// line 2882 "zparse.go"
	if data[p] == 10 { goto tr133 }
	goto st26
tr118:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st27
st27:
	p++
	if p == pe { goto _test_eof27 }
	fallthrough
case 27:
// line 2896 "zparse.go"
	switch data[p] {
		case 9: goto tr134
		case 10: goto tr135
		case 32: goto tr134
		case 34: goto st0
		case 40: goto tr136
		case 41: goto tr137
		case 59: goto tr139
		case 92: goto st0
	}
	if 48 <= data[p] && data[p] <= 57 { goto st27 }
	goto st25
tr97:
// line 95 "zparse.rl"
	{ mark = p }
	goto st28
tr92:
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st28
tr139:
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st28
tr339:
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr = new(RR_MX)
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeMX
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st28
tr395:
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st28
tr561:
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st28
st28:
	p++
	if p == pe { goto _test_eof28 }
	fallthrough
case 28:
// line 2999 "zparse.go"
	if data[p] == 10 { goto tr141 }
	goto st28
tr112:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
	goto st29
st29:
	p++
	if p == pe { goto _test_eof29 }
	fallthrough
case 29:
// line 3011 "zparse.go"
	if data[p] == 10 { goto tr115 }
	goto st29
tr120:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st30
st30:
	p++
	if p == pe { goto _test_eof30 }
	fallthrough
case 30:
// line 3025 "zparse.go"
	switch data[p] {
		case 9: goto tr142
		case 10: goto tr143
		case 32: goto tr142
		case 34: goto st0
		case 40: goto tr144
		case 41: goto tr145
		case 59: goto tr146
		case 65: goto st311
		case 78: goto st314
		case 92: goto st0
		case 97: goto st311
		case 110: goto st314
	}
	goto st25
tr151:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st31
tr152:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st31
tr820:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st31
tr142:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st31
tr144:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st31
tr145:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st31
tr396:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st31
tr340:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr = new(RR_MX)
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeMX
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st31
tr342:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr = new(RR_MX)
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeMX
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st31
tr343:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr = new(RR_MX)
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeMX
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st31
tr398:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st31
tr399:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st31
tr562:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st31
tr564:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st31
tr565:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st31
tr822:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st31
tr823:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st31
st31:
	p++
	if p == pe { goto _test_eof31 }
	fallthrough
case 31:
// line 3287 "zparse.go"
	switch data[p] {
		case 9: goto st31
		case 10: goto tr150
		case 32: goto st31
		case 34: goto st0
		case 40: goto tr151
		case 41: goto tr152
		case 59: goto tr153
		case 92: goto st0
	}
	goto tr43
tr348:
// line 106 "zparse.rl"
	{ lines++ }
	goto st328
tr150:
// line 106 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ mark = p }
	goto st328
tr143:
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st328
tr341:
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr = new(RR_MX)
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeMX
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st328
tr397:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 106 "zparse.rl"
	{ lines++ }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st328
tr563:
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st328
tr821:
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st328
st328:
	p++
	if p == pe { goto _test_eof328 }
	fallthrough
case 328:
// line 3395 "zparse.go"
	switch data[p] {
		case 9: goto st33
		case 10: goto tr161
		case 32: goto st33
		case 34: goto st0
		case 40: goto tr162
		case 41: goto tr163
		case 59: goto tr164
		case 92: goto st0
	}
	goto tr891
tr891:
// line 95 "zparse.rl"
	{ mark = p }
	goto st32
st32:
	p++
	if p == pe { goto _test_eof32 }
	fallthrough
case 32:
// line 3416 "zparse.go"
	switch data[p] {
		case 9: goto tr155
		case 10: goto tr156
		case 32: goto tr155
		case 34: goto st0
		case 40: goto tr157
		case 41: goto tr158
		case 59: goto tr159
		case 92: goto st0
	}
	goto st32
tr162:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st33
tr163:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st33
tr173:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st33
tr175:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st33
tr176:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st33
tr220:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st33
tr222:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st33
tr223:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st33
tr268:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st33
tr270:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st33
tr271:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st33
tr513:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st33
tr515:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st33
tr516:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st33
st33:
	p++
	if p == pe { goto _test_eof33 }
	fallthrough
case 33:
// line 3649 "zparse.go"
	switch data[p] {
		case 9: goto st33
		case 10: goto tr161
		case 32: goto st33
		case 34: goto st0
		case 40: goto tr162
		case 41: goto tr163
		case 59: goto tr164
		case 65: goto tr81
		case 67: goto tr82
		case 72: goto tr83
		case 73: goto tr84
		case 77: goto tr85
		case 78: goto tr86
		case 92: goto st0
		case 97: goto tr81
		case 99: goto tr82
		case 104: goto tr83
		case 105: goto tr84
		case 109: goto tr85
		case 110: goto tr86
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr79 }
	goto tr43
tr172:
// line 106 "zparse.rl"
	{ lines++ }
	goto st329
tr161:
// line 106 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ mark = p }
	goto st329
tr174:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st329
tr221:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st329
tr269:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st329
tr514:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st329
st329:
	p++
	if p == pe { goto _test_eof329 }
	fallthrough
case 329:
// line 3761 "zparse.go"
	switch data[p] {
		case 9: goto st33
		case 10: goto tr161
		case 32: goto st33
		case 34: goto st0
		case 40: goto tr162
		case 41: goto tr163
		case 59: goto tr164
		case 65: goto tr893
		case 67: goto tr894
		case 72: goto tr895
		case 73: goto tr896
		case 77: goto tr897
		case 78: goto tr898
		case 92: goto st0
		case 97: goto tr893
		case 99: goto tr894
		case 104: goto tr895
		case 105: goto tr896
		case 109: goto tr897
		case 110: goto tr898
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr892 }
	goto tr891
tr892:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st34
st34:
	p++
	if p == pe { goto _test_eof34 }
	fallthrough
case 34:
// line 3797 "zparse.go"
	switch data[p] {
		case 9: goto tr165
		case 10: goto tr166
		case 32: goto tr165
		case 34: goto st0
		case 40: goto tr167
		case 41: goto tr168
		case 59: goto tr170
		case 92: goto st0
	}
	if 48 <= data[p] && data[p] <= 57 { goto st34 }
	goto st32
tr164:
// line 95 "zparse.rl"
	{ mark = p }
	goto st35
tr177:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st35
tr224:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st35
tr272:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st35
tr517:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st35
st35:
	p++
	if p == pe { goto _test_eof35 }
	fallthrough
case 35:
// line 3883 "zparse.go"
	if data[p] == 10 { goto tr172 }
	goto st35
tr893:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st36
st36:
	p++
	if p == pe { goto _test_eof36 }
	fallthrough
case 36:
// line 3897 "zparse.go"
	switch data[p] {
		case 9: goto tr173
		case 10: goto tr174
		case 32: goto tr173
		case 34: goto st0
		case 40: goto tr175
		case 41: goto tr176
		case 59: goto tr177
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
		case 9: goto tr155
		case 10: goto tr156
		case 32: goto tr155
		case 34: goto st0
		case 40: goto tr157
		case 41: goto tr158
		case 59: goto tr159
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
		case 9: goto tr155
		case 10: goto tr156
		case 32: goto tr155
		case 34: goto st0
		case 40: goto tr157
		case 41: goto tr158
		case 59: goto tr159
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
		case 9: goto tr182
		case 10: goto tr183
		case 32: goto tr182
		case 34: goto st0
		case 40: goto tr184
		case 41: goto tr185
		case 59: goto tr186
		case 92: goto st0
	}
	goto st32
tr190:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st40
tr191:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st40
tr182:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st40
tr184:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st40
tr185:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st40
tr229:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st40
tr231:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st40
tr232:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st40
tr277:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st40
tr279:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st40
tr280:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st40
tr522:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st40
tr524:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st40
tr525:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st40
st40:
	p++
	if p == pe { goto _test_eof40 }
	fallthrough
case 40:
// line 4186 "zparse.go"
	switch data[p] {
		case 9: goto st40
		case 10: goto tr189
		case 32: goto st40
		case 34: goto st0
		case 40: goto tr190
		case 41: goto tr191
		case 59: goto tr193
		case 65: goto tr194
		case 67: goto tr195
		case 72: goto tr196
		case 73: goto tr197
		case 77: goto tr198
		case 78: goto tr199
		case 92: goto st0
		case 97: goto tr194
		case 99: goto tr195
		case 104: goto tr196
		case 105: goto tr197
		case 109: goto tr198
		case 110: goto tr199
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr192 }
	goto tr187
tr187:
// line 95 "zparse.rl"
	{ mark = p }
	goto st41
st41:
	p++
	if p == pe { goto _test_eof41 }
	fallthrough
case 41:
// line 4220 "zparse.go"
	switch data[p] {
		case 9: goto tr201
		case 10: goto tr202
		case 32: goto tr201
		case 34: goto st0
		case 40: goto tr203
		case 41: goto tr204
		case 59: goto tr205
		case 92: goto st0
	}
	goto st41
tr219:
// line 106 "zparse.rl"
	{ lines++ }
	goto st330
tr189:
// line 106 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ mark = p }
	goto st330
tr183:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st330
tr230:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st330
tr278:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st330
tr523:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st330
st330:
	p++
	if p == pe { goto _test_eof330 }
	fallthrough
case 330:
// line 4319 "zparse.go"
	switch data[p] {
		case 9: goto st40
		case 10: goto tr189
		case 32: goto st40
		case 34: goto st0
		case 40: goto tr190
		case 41: goto tr191
		case 59: goto tr193
		case 65: goto tr901
		case 67: goto tr902
		case 72: goto tr903
		case 73: goto tr904
		case 77: goto tr905
		case 78: goto tr906
		case 92: goto st0
		case 97: goto tr901
		case 99: goto tr902
		case 104: goto tr903
		case 105: goto tr904
		case 109: goto tr905
		case 110: goto tr906
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr900 }
	goto tr899
tr899:
// line 95 "zparse.rl"
	{ mark = p }
	goto st42
st42:
	p++
	if p == pe { goto _test_eof42 }
	fallthrough
case 42:
// line 4353 "zparse.go"
	switch data[p] {
		case 9: goto tr207
		case 10: goto tr208
		case 32: goto tr207
		case 34: goto st0
		case 40: goto tr209
		case 41: goto tr210
		case 59: goto tr211
		case 92: goto st0
	}
	goto st42
tr900:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st43
st43:
	p++
	if p == pe { goto _test_eof43 }
	fallthrough
case 43:
// line 4376 "zparse.go"
	switch data[p] {
		case 9: goto tr212
		case 10: goto tr213
		case 32: goto tr212
		case 34: goto st0
		case 40: goto tr214
		case 41: goto tr215
		case 59: goto tr217
		case 92: goto st0
	}
	if 48 <= data[p] && data[p] <= 57 { goto st43 }
	goto st42
tr193:
// line 95 "zparse.rl"
	{ mark = p }
	goto st44
tr186:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st44
tr233:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st44
tr281:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st44
tr526:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st44
st44:
	p++
	if p == pe { goto _test_eof44 }
	fallthrough
case 44:
// line 4462 "zparse.go"
	if data[p] == 10 { goto tr219 }
	goto st44
tr901:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st45
st45:
	p++
	if p == pe { goto _test_eof45 }
	fallthrough
case 45:
// line 4476 "zparse.go"
	switch data[p] {
		case 9: goto tr220
		case 10: goto tr221
		case 32: goto tr220
		case 34: goto st0
		case 40: goto tr222
		case 41: goto tr223
		case 59: goto tr224
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
		case 9: goto tr207
		case 10: goto tr208
		case 32: goto tr207
		case 34: goto st0
		case 40: goto tr209
		case 41: goto tr210
		case 59: goto tr211
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
		case 9: goto tr207
		case 10: goto tr208
		case 32: goto tr207
		case 34: goto st0
		case 40: goto tr209
		case 41: goto tr210
		case 59: goto tr211
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
		case 9: goto tr229
		case 10: goto tr230
		case 32: goto tr229
		case 34: goto st0
		case 40: goto tr231
		case 41: goto tr232
		case 59: goto tr233
		case 92: goto st0
	}
	goto st42
st49:
	p++
	if p == pe { goto _test_eof49 }
	fallthrough
case 49:
	switch data[p] {
		case 9: goto tr207
		case 10: goto tr208
		case 32: goto tr207
		case 34: goto st0
		case 40: goto tr209
		case 41: goto tr210
		case 59: goto tr211
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
		case 9: goto tr235
		case 10: goto tr236
		case 32: goto tr235
		case 34: goto st0
		case 40: goto tr237
		case 41: goto tr238
		case 59: goto tr239
		case 92: goto st0
	}
	goto st42
tr902:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st51
st51:
	p++
	if p == pe { goto _test_eof51 }
	fallthrough
case 51:
// line 4589 "zparse.go"
	switch data[p] {
		case 9: goto tr207
		case 10: goto tr208
		case 32: goto tr207
		case 34: goto st0
		case 40: goto tr209
		case 41: goto tr210
		case 59: goto tr211
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
		case 9: goto tr207
		case 10: goto tr208
		case 32: goto tr207
		case 34: goto st0
		case 40: goto tr209
		case 41: goto tr210
		case 59: goto tr211
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
		case 9: goto tr207
		case 10: goto tr208
		case 32: goto tr207
		case 34: goto st0
		case 40: goto tr209
		case 41: goto tr210
		case 59: goto tr211
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
		case 9: goto tr207
		case 10: goto tr208
		case 32: goto tr207
		case 34: goto st0
		case 40: goto tr209
		case 41: goto tr210
		case 59: goto tr211
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
		case 9: goto tr244
		case 10: goto tr245
		case 32: goto tr244
		case 34: goto st0
		case 40: goto tr246
		case 41: goto tr247
		case 59: goto tr248
		case 92: goto st0
	}
	goto st42
tr251:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st56
tr252:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st56
tr801:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st56
tr803:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st56
tr804:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st56
tr244:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st56
tr246:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st56
tr247:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st56
tr292:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st56
tr294:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st56
tr295:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st56
tr537:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st56
tr539:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st56
tr540:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st56
st56:
	p++
	if p == pe { goto _test_eof56 }
	fallthrough
case 56:
// line 4898 "zparse.go"
	switch data[p] {
		case 9: goto st56
		case 10: goto tr250
		case 32: goto st56
		case 34: goto st0
		case 40: goto tr251
		case 41: goto tr252
		case 59: goto tr253
		case 65: goto tr120
		case 67: goto tr121
		case 72: goto tr122
		case 73: goto tr123
		case 77: goto tr124
		case 78: goto tr125
		case 92: goto st0
		case 97: goto tr120
		case 99: goto tr121
		case 104: goto tr122
		case 105: goto tr123
		case 109: goto tr124
		case 110: goto tr125
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr118 }
	goto tr113
tr267:
// line 106 "zparse.rl"
	{ lines++ }
	goto st331
tr250:
// line 106 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ mark = p }
	goto st331
tr802:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st331
tr245:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st331
tr293:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st331
tr538:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st331
st331:
	p++
	if p == pe { goto _test_eof331 }
	fallthrough
case 331:
// line 5010 "zparse.go"
	switch data[p] {
		case 9: goto st56
		case 10: goto tr250
		case 32: goto st56
		case 34: goto st0
		case 40: goto tr251
		case 41: goto tr252
		case 59: goto tr253
		case 65: goto tr909
		case 67: goto tr910
		case 72: goto tr911
		case 73: goto tr912
		case 77: goto tr913
		case 78: goto tr914
		case 92: goto st0
		case 97: goto tr909
		case 99: goto tr910
		case 104: goto tr911
		case 105: goto tr912
		case 109: goto tr913
		case 110: goto tr914
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr908 }
	goto tr907
tr907:
// line 95 "zparse.rl"
	{ mark = p }
	goto st57
st57:
	p++
	if p == pe { goto _test_eof57 }
	fallthrough
case 57:
// line 5044 "zparse.go"
	switch data[p] {
		case 9: goto tr255
		case 10: goto tr256
		case 32: goto tr255
		case 34: goto st0
		case 40: goto tr257
		case 41: goto tr258
		case 59: goto tr259
		case 92: goto st0
	}
	goto st57
tr908:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st58
st58:
	p++
	if p == pe { goto _test_eof58 }
	fallthrough
case 58:
// line 5067 "zparse.go"
	switch data[p] {
		case 9: goto tr260
		case 10: goto tr261
		case 32: goto tr260
		case 34: goto st0
		case 40: goto tr262
		case 41: goto tr263
		case 59: goto tr265
		case 92: goto st0
	}
	if 48 <= data[p] && data[p] <= 57 { goto st58 }
	goto st57
tr253:
// line 95 "zparse.rl"
	{ mark = p }
	goto st59
tr805:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st59
tr248:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st59
tr296:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st59
tr541:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st59
st59:
	p++
	if p == pe { goto _test_eof59 }
	fallthrough
case 59:
// line 5153 "zparse.go"
	if data[p] == 10 { goto tr267 }
	goto st59
tr909:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st60
st60:
	p++
	if p == pe { goto _test_eof60 }
	fallthrough
case 60:
// line 5167 "zparse.go"
	switch data[p] {
		case 9: goto tr268
		case 10: goto tr269
		case 32: goto tr268
		case 34: goto st0
		case 40: goto tr270
		case 41: goto tr271
		case 59: goto tr272
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
		case 9: goto tr255
		case 10: goto tr256
		case 32: goto tr255
		case 34: goto st0
		case 40: goto tr257
		case 41: goto tr258
		case 59: goto tr259
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
		case 9: goto tr255
		case 10: goto tr256
		case 32: goto tr255
		case 34: goto st0
		case 40: goto tr257
		case 41: goto tr258
		case 59: goto tr259
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
		case 9: goto tr277
		case 10: goto tr278
		case 32: goto tr277
		case 34: goto st0
		case 40: goto tr279
		case 41: goto tr280
		case 59: goto tr281
		case 92: goto st0
	}
	goto st57
st64:
	p++
	if p == pe { goto _test_eof64 }
	fallthrough
case 64:
	switch data[p] {
		case 9: goto tr255
		case 10: goto tr256
		case 32: goto tr255
		case 34: goto st0
		case 40: goto tr257
		case 41: goto tr258
		case 59: goto tr259
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
		case 9: goto tr283
		case 10: goto tr284
		case 32: goto tr283
		case 34: goto st0
		case 40: goto tr285
		case 41: goto tr286
		case 59: goto tr287
		case 92: goto st0
	}
	goto st57
tr910:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st66
st66:
	p++
	if p == pe { goto _test_eof66 }
	fallthrough
case 66:
// line 5280 "zparse.go"
	switch data[p] {
		case 9: goto tr255
		case 10: goto tr256
		case 32: goto tr255
		case 34: goto st0
		case 40: goto tr257
		case 41: goto tr258
		case 59: goto tr259
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
		case 9: goto tr255
		case 10: goto tr256
		case 32: goto tr255
		case 34: goto st0
		case 40: goto tr257
		case 41: goto tr258
		case 59: goto tr259
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
		case 9: goto tr255
		case 10: goto tr256
		case 32: goto tr255
		case 34: goto st0
		case 40: goto tr257
		case 41: goto tr258
		case 59: goto tr259
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
		case 9: goto tr255
		case 10: goto tr256
		case 32: goto tr255
		case 34: goto st0
		case 40: goto tr257
		case 41: goto tr258
		case 59: goto tr259
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
		case 9: goto tr292
		case 10: goto tr293
		case 32: goto tr292
		case 34: goto st0
		case 40: goto tr294
		case 41: goto tr295
		case 59: goto tr296
		case 92: goto st0
	}
	goto st57
tr911:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st71
st71:
	p++
	if p == pe { goto _test_eof71 }
	fallthrough
case 71:
// line 5379 "zparse.go"
	switch data[p] {
		case 9: goto tr255
		case 10: goto tr256
		case 32: goto tr255
		case 34: goto st0
		case 40: goto tr257
		case 41: goto tr258
		case 59: goto tr259
		case 83: goto st65
		case 92: goto st0
		case 115: goto st65
	}
	goto st57
tr912:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st72
st72:
	p++
	if p == pe { goto _test_eof72 }
	fallthrough
case 72:
// line 5404 "zparse.go"
	switch data[p] {
		case 9: goto tr255
		case 10: goto tr256
		case 32: goto tr255
		case 34: goto st0
		case 40: goto tr257
		case 41: goto tr258
		case 59: goto tr259
		case 78: goto st65
		case 92: goto st0
		case 110: goto st65
	}
	goto st57
tr913:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st73
st73:
	p++
	if p == pe { goto _test_eof73 }
	fallthrough
case 73:
// line 5429 "zparse.go"
	switch data[p] {
		case 9: goto tr255
		case 10: goto tr256
		case 32: goto tr255
		case 34: goto st0
		case 40: goto tr257
		case 41: goto tr258
		case 59: goto tr259
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
		case 9: goto tr298
		case 10: goto tr299
		case 32: goto tr298
		case 34: goto st0
		case 40: goto tr300
		case 41: goto tr301
		case 59: goto tr302
		case 92: goto st0
	}
	goto st57
tr305:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st75
tr306:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st75
tr807:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st75
tr809:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st75
tr810:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st75
tr778:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st75
tr780:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st75
tr781:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st75
tr298:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st75
tr300:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st75
tr301:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st75
tr543:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st75
tr545:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st75
tr546:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st75
st75:
	p++
	if p == pe { goto _test_eof75 }
	fallthrough
case 75:
// line 5680 "zparse.go"
	switch data[p] {
		case 9: goto st75
		case 10: goto tr304
		case 32: goto st75
		case 40: goto tr305
		case 41: goto tr306
		case 59: goto tr308
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
	if 48 <= data[p] && data[p] <= 57 { goto tr307 }
	goto st0
tr453:
// line 106 "zparse.rl"
	{ lines++ }
	goto st332
tr304:
// line 106 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ mark = p }
	goto st332
tr808:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st332
tr779:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st332
tr299:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st332
tr544:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st332
st332:
	p++
	if p == pe { goto _test_eof332 }
	fallthrough
case 332:
// line 5790 "zparse.go"
	switch data[p] {
		case 9: goto st75
		case 10: goto tr304
		case 32: goto st75
		case 34: goto st0
		case 40: goto tr305
		case 41: goto tr306
		case 59: goto tr308
		case 65: goto tr879
		case 67: goto tr880
		case 72: goto tr881
		case 73: goto tr882
		case 77: goto tr883
		case 78: goto tr884
		case 92: goto st0
		case 97: goto tr879
		case 99: goto tr880
		case 104: goto tr881
		case 105: goto tr882
		case 109: goto tr883
		case 110: goto tr884
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr915 }
	goto st1
tr915:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st76
st76:
	p++
	if p == pe { goto _test_eof76 }
	fallthrough
case 76:
// line 5826 "zparse.go"
	switch data[p] {
		case 9: goto tr309
		case 10: goto tr310
		case 32: goto tr309
		case 34: goto st0
		case 40: goto tr311
		case 41: goto tr312
		case 59: goto tr314
		case 92: goto st0
	}
	if 48 <= data[p] && data[p] <= 57 { goto st76 }
	goto st1
tr317:
// line 106 "zparse.rl"
	{ lines++ }
	goto st77
tr318:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st77
tr319:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st77
tr309:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 100 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st77
tr310:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 106 "zparse.rl"
	{ lines++ }
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 100 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st77
tr311:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 100 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st77
tr312:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 100 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st77
tr446:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 100 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st77
tr447:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 106 "zparse.rl"
	{ lines++ }
// line 100 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st77
tr448:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 100 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st77
tr449:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 100 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st77
st77:
	p++
	if p == pe { goto _test_eof77 }
	fallthrough
case 77:
// line 5924 "zparse.go"
	switch data[p] {
		case 9: goto st77
		case 10: goto tr317
		case 32: goto st77
		case 34: goto st0
		case 40: goto tr318
		case 41: goto tr319
		case 59: goto st80
		case 65: goto tr322
		case 67: goto tr323
		case 72: goto tr324
		case 73: goto tr325
		case 77: goto tr326
		case 78: goto tr327
		case 92: goto st0
		case 97: goto tr322
		case 99: goto tr323
		case 104: goto tr324
		case 105: goto tr325
		case 109: goto tr326
		case 110: goto tr327
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr320 }
	goto tr315
tr315:
// line 95 "zparse.rl"
	{ mark = p }
	goto st78
st78:
	p++
	if p == pe { goto _test_eof78 }
	fallthrough
case 78:
// line 5958 "zparse.go"
	switch data[p] {
		case 9: goto tr329
		case 10: goto tr330
		case 32: goto tr329
		case 34: goto st0
		case 40: goto tr331
		case 41: goto tr332
		case 59: goto tr333
		case 92: goto st0
	}
	goto st78
tr320:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st79
st79:
	p++
	if p == pe { goto _test_eof79 }
	fallthrough
case 79:
// line 5981 "zparse.go"
	switch data[p] {
		case 9: goto tr334
		case 10: goto tr335
		case 32: goto tr334
		case 34: goto st0
		case 40: goto tr336
		case 41: goto tr337
		case 59: goto tr339
		case 92: goto st0
	}
	if 48 <= data[p] && data[p] <= 57 { goto st79 }
	goto st78
tr314:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 100 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st80
tr451:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 100 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st80
st80:
	p++
	if p == pe { goto _test_eof80 }
	fallthrough
case 80:
// line 6013 "zparse.go"
	if data[p] == 10 { goto tr317 }
	goto st80
tr322:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st81
st81:
	p++
	if p == pe { goto _test_eof81 }
	fallthrough
case 81:
// line 6027 "zparse.go"
	switch data[p] {
		case 9: goto tr340
		case 10: goto tr341
		case 32: goto tr340
		case 34: goto st0
		case 40: goto tr342
		case 41: goto tr343
		case 59: goto tr344
		case 65: goto st83
		case 78: goto st88
		case 92: goto st0
		case 97: goto st83
		case 110: goto st88
	}
	goto st78
tr153:
// line 95 "zparse.rl"
	{ mark = p }
	goto st82
tr824:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st82
tr146:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st82
tr400:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st82
tr344:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr = new(RR_MX)
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeMX
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st82
tr566:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st82
st82:
	p++
	if p == pe { goto _test_eof82 }
	fallthrough
case 82:
// line 6123 "zparse.go"
	if data[p] == 10 { goto tr348 }
	goto st82
st83:
	p++
	if p == pe { goto _test_eof83 }
	fallthrough
case 83:
	switch data[p] {
		case 9: goto tr329
		case 10: goto tr330
		case 32: goto tr329
		case 34: goto st0
		case 40: goto tr331
		case 41: goto tr332
		case 59: goto tr333
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
		case 9: goto tr329
		case 10: goto tr330
		case 32: goto tr329
		case 34: goto st0
		case 40: goto tr331
		case 41: goto tr332
		case 59: goto tr333
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
		case 9: goto tr351
		case 10: goto tr352
		case 32: goto tr351
		case 34: goto st0
		case 40: goto tr353
		case 41: goto tr354
		case 59: goto tr355
		case 92: goto st0
	}
	goto st78
tr358:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st86
tr359:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st86
tr829:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st86
tr865:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st86
tr867:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st86
tr868:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st86
tr405:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st86
tr351:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr = new(RR_MX)
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeMX
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st86
tr353:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr = new(RR_MX)
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeMX
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st86
tr354:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr = new(RR_MX)
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeMX
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st86
tr407:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st86
tr408:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st86
tr571:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st86
tr573:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st86
tr574:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st86
tr831:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st86
tr832:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st86
st86:
	p++
	if p == pe { goto _test_eof86 }
	fallthrough
case 86:
// line 6424 "zparse.go"
	switch data[p] {
		case 9: goto st86
		case 10: goto tr357
		case 32: goto st86
		case 34: goto st0
		case 40: goto tr358
		case 41: goto tr359
		case 59: goto tr360
		case 92: goto st0
	}
	goto tr187
tr362:
// line 106 "zparse.rl"
	{ lines++ }
	goto st333
tr357:
// line 106 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ mark = p }
	goto st333
tr866:
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st333
tr352:
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr = new(RR_MX)
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeMX
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st333
tr406:
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st333
tr572:
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st333
tr830:
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st333
st333:
	p++
	if p == pe { goto _test_eof333 }
	fallthrough
case 333:
// line 6532 "zparse.go"
	switch data[p] {
		case 9: goto st40
		case 10: goto tr189
		case 32: goto st40
		case 34: goto st0
		case 40: goto tr190
		case 41: goto tr191
		case 59: goto tr193
		case 92: goto st0
	}
	goto tr899
tr360:
// line 95 "zparse.rl"
	{ mark = p }
	goto st87
tr833:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st87
tr869:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st87
tr409:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st87
tr355:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr = new(RR_MX)
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeMX
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st87
tr575:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st87
st87:
	p++
	if p == pe { goto _test_eof87 }
	fallthrough
case 87:
// line 6624 "zparse.go"
	if data[p] == 10 { goto tr362 }
	goto st87
st88:
	p++
	if p == pe { goto _test_eof88 }
	fallthrough
case 88:
	switch data[p] {
		case 9: goto tr329
		case 10: goto tr330
		case 32: goto tr329
		case 34: goto st0
		case 40: goto tr331
		case 41: goto tr332
		case 59: goto tr333
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
		case 9: goto tr364
		case 10: goto tr365
		case 32: goto tr364
		case 34: goto st0
		case 40: goto tr366
		case 41: goto tr367
		case 59: goto tr368
		case 92: goto st0
	}
	goto st78
tr371:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st90
tr372:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st90
tr364:
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr = new(RR_MX)
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeMX
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st90
tr366:
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr = new(RR_MX)
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeMX
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st90
tr367:
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr = new(RR_MX)
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeMX
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st90
tr411:
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st90
tr413:
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st90
tr414:
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st90
tr577:
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st90
tr579:
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st90
tr580:
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st90
tr750:
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st90
tr752:
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st90
tr753:
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st90
tr835:
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st90
tr837:
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st90
tr838:
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st90
st90:
	p++
	if p == pe { goto _test_eof90 }
	fallthrough
case 90:
// line 6937 "zparse.go"
	switch data[p] {
		case 9: goto st90
		case 10: goto tr370
		case 32: goto st90
		case 40: goto tr371
		case 41: goto tr372
		case 59: goto tr374
		case 65: goto tr375
		case 67: goto tr376
		case 77: goto tr34
		case 78: goto tr377
		case 97: goto tr375
		case 99: goto tr376
		case 109: goto tr34
		case 110: goto tr377
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr373 }
	goto st0
tr417:
// line 106 "zparse.rl"
	{ lines++ }
	goto st334
tr370:
// line 106 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ mark = p }
	goto st334
tr365:
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr = new(RR_MX)
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeMX
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st334
tr412:
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st334
tr578:
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st334
tr751:
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st334
tr836:
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st334
st334:
	p++
	if p == pe { goto _test_eof334 }
	fallthrough
case 334:
// line 7062 "zparse.go"
	switch data[p] {
		case 9: goto st10
		case 10: goto tr56
		case 32: goto st10
		case 34: goto st0
		case 40: goto tr57
		case 41: goto tr58
		case 59: goto tr59
		case 65: goto tr917
		case 67: goto tr918
		case 77: goto tr889
		case 78: goto tr919
		case 92: goto st0
		case 97: goto tr917
		case 99: goto tr918
		case 109: goto tr889
		case 110: goto tr919
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr916 }
	goto st1
tr917:
// line 95 "zparse.rl"
	{ mark = p }
	goto st91
st91:
	p++
	if p == pe { goto _test_eof91 }
	fallthrough
case 91:
// line 7092 "zparse.go"
	switch data[p] {
		case 9: goto tr68
		case 10: goto tr69
		case 32: goto tr68
		case 34: goto st0
		case 40: goto tr70
		case 41: goto tr71
		case 59: goto tr72
		case 65: goto st93
		case 92: goto st0
		case 97: goto st93
	}
	goto st1
tr72:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
	goto st92
st92:
	p++
	if p == pe { goto _test_eof92 }
	fallthrough
case 92:
// line 7115 "zparse.go"
	if data[p] == 10 { goto tr76 }
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
		case 9: goto tr380
		case 10: goto tr381
		case 32: goto tr380
		case 34: goto st0
		case 40: goto tr382
		case 41: goto tr383
		case 59: goto tr384
		case 92: goto st0
	}
	goto st1
tr380:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
	goto st96
tr381:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 106 "zparse.rl"
	{ lines++ }
	goto st96
tr382:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st96
tr383:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st96
tr386:
// line 106 "zparse.rl"
	{ lines++ }
	goto st96
tr387:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st96
tr388:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st96
st96:
	p++
	if p == pe { goto _test_eof96 }
	fallthrough
case 96:
// line 7209 "zparse.go"
	switch data[p] {
		case 9: goto st96
		case 10: goto tr386
		case 32: goto st96
		case 34: goto st0
		case 40: goto tr387
		case 41: goto tr388
		case 59: goto st98
		case 65: goto tr194
		case 67: goto tr195
		case 72: goto tr196
		case 73: goto tr197
		case 77: goto tr198
		case 78: goto tr199
		case 92: goto st0
		case 97: goto tr194
		case 99: goto tr195
		case 104: goto tr196
		case 105: goto tr197
		case 109: goto tr198
		case 110: goto tr199
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr192 }
	goto tr187
tr192:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st97
st97:
	p++
	if p == pe { goto _test_eof97 }
	fallthrough
case 97:
// line 7245 "zparse.go"
	switch data[p] {
		case 9: goto tr390
		case 10: goto tr391
		case 32: goto tr390
		case 34: goto st0
		case 40: goto tr392
		case 41: goto tr393
		case 59: goto tr395
		case 92: goto st0
	}
	if 48 <= data[p] && data[p] <= 57 { goto st97 }
	goto st41
tr384:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
	goto st98
st98:
	p++
	if p == pe { goto _test_eof98 }
	fallthrough
case 98:
// line 7267 "zparse.go"
	if data[p] == 10 { goto tr386 }
	goto st98
tr194:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st99
st99:
	p++
	if p == pe { goto _test_eof99 }
	fallthrough
case 99:
// line 7281 "zparse.go"
	switch data[p] {
		case 9: goto tr396
		case 10: goto tr397
		case 32: goto tr396
		case 34: goto st0
		case 40: goto tr398
		case 41: goto tr399
		case 59: goto tr400
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
		case 9: goto tr201
		case 10: goto tr202
		case 32: goto tr201
		case 34: goto st0
		case 40: goto tr203
		case 41: goto tr204
		case 59: goto tr205
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
		case 9: goto tr201
		case 10: goto tr202
		case 32: goto tr201
		case 34: goto st0
		case 40: goto tr203
		case 41: goto tr204
		case 59: goto tr205
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
		case 9: goto tr405
		case 10: goto tr406
		case 32: goto tr405
		case 34: goto st0
		case 40: goto tr407
		case 41: goto tr408
		case 59: goto tr409
		case 92: goto st0
	}
	goto st41
st103:
	p++
	if p == pe { goto _test_eof103 }
	fallthrough
case 103:
	switch data[p] {
		case 9: goto tr201
		case 10: goto tr202
		case 32: goto tr201
		case 34: goto st0
		case 40: goto tr203
		case 41: goto tr204
		case 59: goto tr205
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
		case 9: goto tr411
		case 10: goto tr412
		case 32: goto tr411
		case 34: goto st0
		case 40: goto tr413
		case 41: goto tr414
		case 59: goto tr415
		case 92: goto st0
	}
	goto st41
tr374:
// line 95 "zparse.rl"
	{ mark = p }
	goto st105
tr368:
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr = new(RR_MX)
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeMX
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st105
tr415:
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st105
tr581:
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st105
tr754:
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st105
tr839:
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st105
st105:
	p++
	if p == pe { goto _test_eof105 }
	fallthrough
case 105:
// line 7473 "zparse.go"
	if data[p] == 10 { goto tr417 }
	goto st105
tr195:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st106
st106:
	p++
	if p == pe { goto _test_eof106 }
	fallthrough
case 106:
// line 7487 "zparse.go"
	switch data[p] {
		case 9: goto tr201
		case 10: goto tr202
		case 32: goto tr201
		case 34: goto st0
		case 40: goto tr203
		case 41: goto tr204
		case 59: goto tr205
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
		case 9: goto tr201
		case 10: goto tr202
		case 32: goto tr201
		case 34: goto st0
		case 40: goto tr203
		case 41: goto tr204
		case 59: goto tr205
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
		case 9: goto tr201
		case 10: goto tr202
		case 32: goto tr201
		case 34: goto st0
		case 40: goto tr203
		case 41: goto tr204
		case 59: goto tr205
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
		case 9: goto tr201
		case 10: goto tr202
		case 32: goto tr201
		case 34: goto st0
		case 40: goto tr203
		case 41: goto tr204
		case 59: goto tr205
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
		case 9: goto tr422
		case 10: goto tr423
		case 32: goto tr422
		case 34: goto st0
		case 40: goto tr424
		case 41: goto tr425
		case 59: goto tr426
		case 92: goto st0
	}
	goto st41
tr429:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st111
tr430:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st111
tr844:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st111
tr758:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st111
tr760:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st111
tr761:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st111
tr422:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st111
tr692:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr = new(RR_MX)
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeMX
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st111
tr694:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr = new(RR_MX)
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeMX
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st111
tr695:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr = new(RR_MX)
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeMX
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st111
tr424:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st111
tr425:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st111
tr586:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st111
tr588:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st111
tr589:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st111
tr846:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st111
tr847:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st111
st111:
	p++
	if p == pe { goto _test_eof111 }
	fallthrough
case 111:
// line 7821 "zparse.go"
	switch data[p] {
		case 9: goto st111
		case 10: goto tr428
		case 32: goto st111
		case 34: goto st0
		case 40: goto tr429
		case 41: goto tr430
		case 59: goto tr431
		case 92: goto st0
	}
	goto tr113
tr433:
// line 106 "zparse.rl"
	{ lines++ }
	goto st335
tr428:
// line 106 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ mark = p }
	goto st335
tr759:
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st335
tr693:
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr = new(RR_MX)
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeMX
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st335
tr423:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 106 "zparse.rl"
	{ lines++ }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st335
tr587:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 106 "zparse.rl"
	{ lines++ }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st335
tr845:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 106 "zparse.rl"
	{ lines++ }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st335
st335:
	p++
	if p == pe { goto _test_eof335 }
	fallthrough
case 335:
// line 7929 "zparse.go"
	switch data[p] {
		case 9: goto st56
		case 10: goto tr250
		case 32: goto st56
		case 34: goto st0
		case 40: goto tr251
		case 41: goto tr252
		case 59: goto tr253
		case 92: goto st0
	}
	goto tr907
tr431:
// line 95 "zparse.rl"
	{ mark = p }
	goto st112
tr848:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st112
tr762:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st112
tr426:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st112
tr696:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr = new(RR_MX)
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeMX
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st112
tr590:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st112
st112:
	p++
	if p == pe { goto _test_eof112 }
	fallthrough
case 112:
// line 8021 "zparse.go"
	if data[p] == 10 { goto tr433 }
	goto st112
tr196:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st113
st113:
	p++
	if p == pe { goto _test_eof113 }
	fallthrough
case 113:
// line 8035 "zparse.go"
	switch data[p] {
		case 9: goto tr201
		case 10: goto tr202
		case 32: goto tr201
		case 34: goto st0
		case 40: goto tr203
		case 41: goto tr204
		case 59: goto tr205
		case 83: goto st104
		case 92: goto st0
		case 115: goto st104
	}
	goto st41
tr197:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st114
st114:
	p++
	if p == pe { goto _test_eof114 }
	fallthrough
case 114:
// line 8060 "zparse.go"
	switch data[p] {
		case 9: goto tr201
		case 10: goto tr202
		case 32: goto tr201
		case 34: goto st0
		case 40: goto tr203
		case 41: goto tr204
		case 59: goto tr205
		case 78: goto st104
		case 92: goto st0
		case 110: goto st104
	}
	goto st41
tr198:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st115
st115:
	p++
	if p == pe { goto _test_eof115 }
	fallthrough
case 115:
// line 8085 "zparse.go"
	switch data[p] {
		case 9: goto tr201
		case 10: goto tr202
		case 32: goto tr201
		case 34: goto st0
		case 40: goto tr203
		case 41: goto tr204
		case 59: goto tr205
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
		case 9: goto tr435
		case 10: goto tr436
		case 32: goto tr435
		case 34: goto st0
		case 40: goto tr437
		case 41: goto tr438
		case 59: goto tr439
		case 92: goto st0
	}
	goto st41
tr442:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st117
tr443:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st117
tr850:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st117
tr764:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st117
tr435:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st117
tr698:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr = new(RR_MX)
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeMX
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st117
tr700:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr = new(RR_MX)
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeMX
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st117
tr701:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr = new(RR_MX)
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeMX
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st117
tr437:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st117
tr438:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st117
tr592:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st117
tr594:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st117
tr595:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st117
tr766:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st117
tr767:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st117
tr852:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st117
tr853:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st117
st117:
	p++
	if p == pe { goto _test_eof117 }
	fallthrough
case 117:
// line 8361 "zparse.go"
	switch data[p] {
		case 9: goto st117
		case 10: goto tr441
		case 32: goto st117
		case 40: goto tr442
		case 41: goto tr443
		case 59: goto tr445
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr444 }
	goto st0
tr466:
// line 106 "zparse.rl"
	{ lines++ }
	goto st336
tr441:
// line 106 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ mark = p }
	goto st336
tr699:
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr = new(RR_MX)
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeMX
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st336
tr436:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 106 "zparse.rl"
	{ lines++ }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st336
tr593:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 106 "zparse.rl"
	{ lines++ }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st336
tr765:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 106 "zparse.rl"
	{ lines++ }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st336
tr851:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 106 "zparse.rl"
	{ lines++ }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st336
st336:
	p++
	if p == pe { goto _test_eof336 }
	fallthrough
case 336:
// line 8468 "zparse.go"
	switch data[p] {
		case 9: goto st75
		case 10: goto tr304
		case 32: goto st75
		case 34: goto st0
		case 40: goto tr305
		case 41: goto tr306
		case 59: goto tr308
		case 92: goto st0
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr920 }
	goto st1
tr920:
// line 95 "zparse.rl"
	{ mark = p }
	goto st118
st118:
	p++
	if p == pe { goto _test_eof118 }
	fallthrough
case 118:
// line 8490 "zparse.go"
	switch data[p] {
		case 9: goto tr446
		case 10: goto tr447
		case 32: goto tr446
		case 34: goto st0
		case 40: goto tr448
		case 41: goto tr449
		case 59: goto tr451
		case 92: goto st0
	}
	if 48 <= data[p] && data[p] <= 57 { goto st118 }
	goto st1
tr308:
// line 95 "zparse.rl"
	{ mark = p }
	goto st119
tr811:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st119
tr782:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st119
tr302:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st119
tr547:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st119
st119:
	p++
	if p == pe { goto _test_eof119 }
	fallthrough
case 119:
// line 8576 "zparse.go"
	if data[p] == 10 { goto tr453 }
	goto st119
tr444:
// line 95 "zparse.rl"
	{ mark = p }
	goto st120
st120:
	p++
	if p == pe { goto _test_eof120 }
	fallthrough
case 120:
// line 8588 "zparse.go"
	switch data[p] {
		case 9: goto tr454
		case 10: goto tr455
		case 32: goto tr454
		case 40: goto tr456
		case 41: goto tr457
		case 59: goto tr459
	}
	if 48 <= data[p] && data[p] <= 57 { goto st120 }
	goto st0
tr461:
// line 106 "zparse.rl"
	{ lines++ }
	goto st121
tr462:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st121
tr463:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st121
tr454:
// line 100 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st121
tr455:
// line 100 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 106 "zparse.rl"
	{ lines++ }
	goto st121
tr456:
// line 100 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st121
tr457:
// line 100 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st121
st121:
	p++
	if p == pe { goto _test_eof121 }
	fallthrough
case 121:
// line 8638 "zparse.go"
	switch data[p] {
		case 9: goto st121
		case 10: goto tr461
		case 32: goto st121
		case 34: goto st0
		case 40: goto tr462
		case 41: goto tr463
		case 59: goto st122
		case 92: goto st0
	}
	goto tr315
tr459:
// line 100 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st122
st122:
	p++
	if p == pe { goto _test_eof122 }
	fallthrough
case 122:
// line 8659 "zparse.go"
	if data[p] == 10 { goto tr461 }
	goto st122
tr445:
// line 95 "zparse.rl"
	{ mark = p }
	goto st123
tr854:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st123
tr768:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st123
tr439:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st123
tr702:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr = new(RR_MX)
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeMX
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st123
tr596:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st123
st123:
	p++
	if p == pe { goto _test_eof123 }
	fallthrough
case 123:
// line 8742 "zparse.go"
	if data[p] == 10 { goto tr466 }
	goto st123
tr199:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st124
st124:
	p++
	if p == pe { goto _test_eof124 }
	fallthrough
case 124:
// line 8756 "zparse.go"
	switch data[p] {
		case 9: goto tr201
		case 10: goto tr202
		case 32: goto tr201
		case 34: goto st0
		case 40: goto tr203
		case 41: goto tr204
		case 59: goto tr205
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
		case 9: goto tr201
		case 10: goto tr202
		case 32: goto tr201
		case 34: goto st0
		case 40: goto tr203
		case 41: goto tr204
		case 59: goto tr205
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
		case 9: goto tr201
		case 10: goto tr202
		case 32: goto tr201
		case 34: goto st0
		case 40: goto tr203
		case 41: goto tr204
		case 59: goto tr205
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
		case 9: goto tr470
		case 10: goto tr471
		case 32: goto tr470
		case 34: goto st0
		case 40: goto tr472
		case 41: goto tr473
		case 59: goto tr474
		case 92: goto st0
	}
	goto st41
tr478:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st128
tr479:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st128
tr858:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st128
tr772:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st128
tr774:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st128
tr775:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st128
tr470:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st128
tr706:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr = new(RR_MX)
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeMX
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st128
tr708:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr = new(RR_MX)
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeMX
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st128
tr709:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr = new(RR_MX)
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeMX
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st128
tr472:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st128
tr473:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st128
tr600:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st128
tr602:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st128
tr603:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st128
tr860:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st128
tr861:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st128
st128:
	p++
	if p == pe { goto _test_eof128 }
	fallthrough
case 128:
// line 9070 "zparse.go"
	switch data[p] {
		case 9: goto st128
		case 10: goto tr477
		case 32: goto st128
		case 34: goto st0
		case 40: goto tr478
		case 41: goto tr479
		case 59: goto tr480
		case 92: goto st0
	}
	goto tr475
tr475:
// line 95 "zparse.rl"
	{ mark = p }
	goto st129
st129:
	p++
	if p == pe { goto _test_eof129 }
	fallthrough
case 129:
// line 9091 "zparse.go"
	switch data[p] {
		case 9: goto tr482
		case 10: goto tr483
		case 32: goto tr482
		case 34: goto st0
		case 40: goto tr484
		case 41: goto tr485
		case 59: goto tr486
		case 92: goto st0
	}
	goto st129
tr606:
// line 106 "zparse.rl"
	{ lines++ }
	goto st337
tr477:
// line 106 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ mark = p }
	goto st337
tr773:
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st337
tr707:
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr = new(RR_MX)
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeMX
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st337
tr471:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 106 "zparse.rl"
	{ lines++ }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st337
tr601:
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st337
tr859:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 106 "zparse.rl"
	{ lines++ }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st337
st337:
	p++
	if p == pe { goto _test_eof337 }
	fallthrough
case 337:
// line 9199 "zparse.go"
	switch data[p] {
		case 9: goto st131
		case 10: goto tr494
		case 32: goto st131
		case 34: goto st0
		case 40: goto tr495
		case 41: goto tr496
		case 59: goto tr498
		case 92: goto st0
	}
	goto tr921
tr921:
// line 95 "zparse.rl"
	{ mark = p }
	goto st130
st130:
	p++
	if p == pe { goto _test_eof130 }
	fallthrough
case 130:
// line 9220 "zparse.go"
	switch data[p] {
		case 9: goto tr488
		case 10: goto tr489
		case 32: goto tr488
		case 34: goto st0
		case 40: goto tr490
		case 41: goto tr491
		case 59: goto tr492
		case 92: goto st0
	}
	goto st130
tr495:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st131
tr496:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st131
tr815:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st131
tr817:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st131
tr818:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st131
tr786:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st131
tr788:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st131
tr789:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st131
tr743:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st131
tr745:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st131
tr746:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st131
tr551:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st131
tr553:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st131
tr554:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st131
st131:
	p++
	if p == pe { goto _test_eof131 }
	fallthrough
case 131:
// line 9453 "zparse.go"
	switch data[p] {
		case 9: goto st131
		case 10: goto tr494
		case 32: goto st131
		case 34: goto st0
		case 40: goto tr495
		case 41: goto tr496
		case 59: goto tr498
		case 65: goto tr499
		case 67: goto tr500
		case 72: goto tr501
		case 73: goto tr502
		case 77: goto tr503
		case 78: goto tr504
		case 92: goto st0
		case 97: goto tr499
		case 99: goto tr500
		case 104: goto tr501
		case 105: goto tr502
		case 109: goto tr503
		case 110: goto tr504
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr497 }
	goto tr475
tr512:
// line 106 "zparse.rl"
	{ lines++ }
	goto st338
tr494:
// line 106 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ mark = p }
	goto st338
tr816:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st338
tr787:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st338
tr744:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st338
tr552:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st338
st338:
	p++
	if p == pe { goto _test_eof338 }
	fallthrough
case 338:
// line 9565 "zparse.go"
	switch data[p] {
		case 9: goto st131
		case 10: goto tr494
		case 32: goto st131
		case 34: goto st0
		case 40: goto tr495
		case 41: goto tr496
		case 59: goto tr498
		case 65: goto tr923
		case 67: goto tr924
		case 72: goto tr925
		case 73: goto tr926
		case 77: goto tr927
		case 78: goto tr928
		case 92: goto st0
		case 97: goto tr923
		case 99: goto tr924
		case 104: goto tr925
		case 105: goto tr926
		case 109: goto tr927
		case 110: goto tr928
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr922 }
	goto tr921
tr922:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st132
st132:
	p++
	if p == pe { goto _test_eof132 }
	fallthrough
case 132:
// line 9601 "zparse.go"
	switch data[p] {
		case 9: goto tr505
		case 10: goto tr506
		case 32: goto tr505
		case 34: goto st0
		case 40: goto tr507
		case 41: goto tr508
		case 59: goto tr510
		case 92: goto st0
	}
	if 48 <= data[p] && data[p] <= 57 { goto st132 }
	goto st130
tr498:
// line 95 "zparse.rl"
	{ mark = p }
	goto st133
tr819:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st133
tr790:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st133
tr747:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st133
tr555:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st133
st133:
	p++
	if p == pe { goto _test_eof133 }
	fallthrough
case 133:
// line 9687 "zparse.go"
	if data[p] == 10 { goto tr512 }
	goto st133
tr923:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st134
st134:
	p++
	if p == pe { goto _test_eof134 }
	fallthrough
case 134:
// line 9701 "zparse.go"
	switch data[p] {
		case 9: goto tr513
		case 10: goto tr514
		case 32: goto tr513
		case 34: goto st0
		case 40: goto tr515
		case 41: goto tr516
		case 59: goto tr517
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
		case 9: goto tr488
		case 10: goto tr489
		case 32: goto tr488
		case 34: goto st0
		case 40: goto tr490
		case 41: goto tr491
		case 59: goto tr492
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
		case 9: goto tr488
		case 10: goto tr489
		case 32: goto tr488
		case 34: goto st0
		case 40: goto tr490
		case 41: goto tr491
		case 59: goto tr492
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
		case 9: goto tr522
		case 10: goto tr523
		case 32: goto tr522
		case 34: goto st0
		case 40: goto tr524
		case 41: goto tr525
		case 59: goto tr526
		case 92: goto st0
	}
	goto st130
st138:
	p++
	if p == pe { goto _test_eof138 }
	fallthrough
case 138:
	switch data[p] {
		case 9: goto tr488
		case 10: goto tr489
		case 32: goto tr488
		case 34: goto st0
		case 40: goto tr490
		case 41: goto tr491
		case 59: goto tr492
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
		case 9: goto tr528
		case 10: goto tr529
		case 32: goto tr528
		case 34: goto st0
		case 40: goto tr530
		case 41: goto tr531
		case 59: goto tr532
		case 92: goto st0
	}
	goto st130
tr924:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st140
st140:
	p++
	if p == pe { goto _test_eof140 }
	fallthrough
case 140:
// line 9814 "zparse.go"
	switch data[p] {
		case 9: goto tr488
		case 10: goto tr489
		case 32: goto tr488
		case 34: goto st0
		case 40: goto tr490
		case 41: goto tr491
		case 59: goto tr492
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
		case 9: goto tr488
		case 10: goto tr489
		case 32: goto tr488
		case 34: goto st0
		case 40: goto tr490
		case 41: goto tr491
		case 59: goto tr492
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
		case 9: goto tr488
		case 10: goto tr489
		case 32: goto tr488
		case 34: goto st0
		case 40: goto tr490
		case 41: goto tr491
		case 59: goto tr492
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
		case 9: goto tr488
		case 10: goto tr489
		case 32: goto tr488
		case 34: goto st0
		case 40: goto tr490
		case 41: goto tr491
		case 59: goto tr492
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
		case 9: goto tr537
		case 10: goto tr538
		case 32: goto tr537
		case 34: goto st0
		case 40: goto tr539
		case 41: goto tr540
		case 59: goto tr541
		case 92: goto st0
	}
	goto st130
tr925:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st145
st145:
	p++
	if p == pe { goto _test_eof145 }
	fallthrough
case 145:
// line 9913 "zparse.go"
	switch data[p] {
		case 9: goto tr488
		case 10: goto tr489
		case 32: goto tr488
		case 34: goto st0
		case 40: goto tr490
		case 41: goto tr491
		case 59: goto tr492
		case 83: goto st139
		case 92: goto st0
		case 115: goto st139
	}
	goto st130
tr926:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st146
st146:
	p++
	if p == pe { goto _test_eof146 }
	fallthrough
case 146:
// line 9938 "zparse.go"
	switch data[p] {
		case 9: goto tr488
		case 10: goto tr489
		case 32: goto tr488
		case 34: goto st0
		case 40: goto tr490
		case 41: goto tr491
		case 59: goto tr492
		case 78: goto st139
		case 92: goto st0
		case 110: goto st139
	}
	goto st130
tr927:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st147
st147:
	p++
	if p == pe { goto _test_eof147 }
	fallthrough
case 147:
// line 9963 "zparse.go"
	switch data[p] {
		case 9: goto tr488
		case 10: goto tr489
		case 32: goto tr488
		case 34: goto st0
		case 40: goto tr490
		case 41: goto tr491
		case 59: goto tr492
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
		case 9: goto tr543
		case 10: goto tr544
		case 32: goto tr543
		case 34: goto st0
		case 40: goto tr545
		case 41: goto tr546
		case 59: goto tr547
		case 92: goto st0
	}
	goto st130
tr928:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st149
st149:
	p++
	if p == pe { goto _test_eof149 }
	fallthrough
case 149:
// line 10004 "zparse.go"
	switch data[p] {
		case 9: goto tr488
		case 10: goto tr489
		case 32: goto tr488
		case 34: goto st0
		case 40: goto tr490
		case 41: goto tr491
		case 59: goto tr492
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
		case 9: goto tr488
		case 10: goto tr489
		case 32: goto tr488
		case 34: goto st0
		case 40: goto tr490
		case 41: goto tr491
		case 59: goto tr492
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
		case 9: goto tr488
		case 10: goto tr489
		case 32: goto tr488
		case 34: goto st0
		case 40: goto tr490
		case 41: goto tr491
		case 59: goto tr492
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
		case 9: goto tr551
		case 10: goto tr552
		case 32: goto tr551
		case 34: goto st0
		case 40: goto tr553
		case 41: goto tr554
		case 59: goto tr555
		case 92: goto st0
	}
	goto st130
tr497:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st153
st153:
	p++
	if p == pe { goto _test_eof153 }
	fallthrough
case 153:
// line 10083 "zparse.go"
	switch data[p] {
		case 9: goto tr556
		case 10: goto tr557
		case 32: goto tr556
		case 34: goto st0
		case 40: goto tr558
		case 41: goto tr559
		case 59: goto tr561
		case 92: goto st0
	}
	if 48 <= data[p] && data[p] <= 57 { goto st153 }
	goto st129
tr499:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st154
st154:
	p++
	if p == pe { goto _test_eof154 }
	fallthrough
case 154:
// line 10107 "zparse.go"
	switch data[p] {
		case 9: goto tr562
		case 10: goto tr563
		case 32: goto tr562
		case 34: goto st0
		case 40: goto tr564
		case 41: goto tr565
		case 59: goto tr566
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
		case 9: goto tr482
		case 10: goto tr483
		case 32: goto tr482
		case 34: goto st0
		case 40: goto tr484
		case 41: goto tr485
		case 59: goto tr486
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
		case 9: goto tr482
		case 10: goto tr483
		case 32: goto tr482
		case 34: goto st0
		case 40: goto tr484
		case 41: goto tr485
		case 59: goto tr486
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
		case 9: goto tr571
		case 10: goto tr572
		case 32: goto tr571
		case 34: goto st0
		case 40: goto tr573
		case 41: goto tr574
		case 59: goto tr575
		case 92: goto st0
	}
	goto st129
st158:
	p++
	if p == pe { goto _test_eof158 }
	fallthrough
case 158:
	switch data[p] {
		case 9: goto tr482
		case 10: goto tr483
		case 32: goto tr482
		case 34: goto st0
		case 40: goto tr484
		case 41: goto tr485
		case 59: goto tr486
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
		case 9: goto tr577
		case 10: goto tr578
		case 32: goto tr577
		case 34: goto st0
		case 40: goto tr579
		case 41: goto tr580
		case 59: goto tr581
		case 92: goto st0
	}
	goto st129
tr500:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st160
st160:
	p++
	if p == pe { goto _test_eof160 }
	fallthrough
case 160:
// line 10220 "zparse.go"
	switch data[p] {
		case 9: goto tr482
		case 10: goto tr483
		case 32: goto tr482
		case 34: goto st0
		case 40: goto tr484
		case 41: goto tr485
		case 59: goto tr486
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
		case 9: goto tr482
		case 10: goto tr483
		case 32: goto tr482
		case 34: goto st0
		case 40: goto tr484
		case 41: goto tr485
		case 59: goto tr486
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
		case 9: goto tr482
		case 10: goto tr483
		case 32: goto tr482
		case 34: goto st0
		case 40: goto tr484
		case 41: goto tr485
		case 59: goto tr486
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
		case 9: goto tr482
		case 10: goto tr483
		case 32: goto tr482
		case 34: goto st0
		case 40: goto tr484
		case 41: goto tr485
		case 59: goto tr486
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
		case 9: goto tr586
		case 10: goto tr587
		case 32: goto tr586
		case 34: goto st0
		case 40: goto tr588
		case 41: goto tr589
		case 59: goto tr590
		case 92: goto st0
	}
	goto st129
tr501:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st165
st165:
	p++
	if p == pe { goto _test_eof165 }
	fallthrough
case 165:
// line 10319 "zparse.go"
	switch data[p] {
		case 9: goto tr482
		case 10: goto tr483
		case 32: goto tr482
		case 34: goto st0
		case 40: goto tr484
		case 41: goto tr485
		case 59: goto tr486
		case 83: goto st159
		case 92: goto st0
		case 115: goto st159
	}
	goto st129
tr502:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st166
st166:
	p++
	if p == pe { goto _test_eof166 }
	fallthrough
case 166:
// line 10344 "zparse.go"
	switch data[p] {
		case 9: goto tr482
		case 10: goto tr483
		case 32: goto tr482
		case 34: goto st0
		case 40: goto tr484
		case 41: goto tr485
		case 59: goto tr486
		case 78: goto st159
		case 92: goto st0
		case 110: goto st159
	}
	goto st129
tr503:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st167
st167:
	p++
	if p == pe { goto _test_eof167 }
	fallthrough
case 167:
// line 10369 "zparse.go"
	switch data[p] {
		case 9: goto tr482
		case 10: goto tr483
		case 32: goto tr482
		case 34: goto st0
		case 40: goto tr484
		case 41: goto tr485
		case 59: goto tr486
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
		case 9: goto tr592
		case 10: goto tr593
		case 32: goto tr592
		case 34: goto st0
		case 40: goto tr594
		case 41: goto tr595
		case 59: goto tr596
		case 92: goto st0
	}
	goto st129
tr504:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st169
st169:
	p++
	if p == pe { goto _test_eof169 }
	fallthrough
case 169:
// line 10410 "zparse.go"
	switch data[p] {
		case 9: goto tr482
		case 10: goto tr483
		case 32: goto tr482
		case 34: goto st0
		case 40: goto tr484
		case 41: goto tr485
		case 59: goto tr486
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
		case 9: goto tr482
		case 10: goto tr483
		case 32: goto tr482
		case 34: goto st0
		case 40: goto tr484
		case 41: goto tr485
		case 59: goto tr486
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
		case 9: goto tr482
		case 10: goto tr483
		case 32: goto tr482
		case 34: goto st0
		case 40: goto tr484
		case 41: goto tr485
		case 59: goto tr486
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
		case 9: goto tr600
		case 10: goto tr601
		case 32: goto tr600
		case 34: goto st0
		case 40: goto tr602
		case 41: goto tr603
		case 59: goto tr604
		case 92: goto st0
	}
	goto st129
tr480:
// line 95 "zparse.rl"
	{ mark = p }
	goto st173
tr862:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 4 "types.rl"
	{
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st173
tr776:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 25 "types.rl"
	{
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st173
tr474:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 11 "types.rl"
	{
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st173
tr710:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr = new(RR_MX)
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeMX
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st173
tr604:
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 18 "types.rl"
	{
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st173
st173:
	p++
	if p == pe { goto _test_eof173 }
	fallthrough
case 173:
// line 10558 "zparse.go"
	if data[p] == 10 { goto tr606 }
	goto st173
tr918:
// line 95 "zparse.rl"
	{ mark = p }
	goto st174
st174:
	p++
	if p == pe { goto _test_eof174 }
	fallthrough
case 174:
// line 10570 "zparse.go"
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
tr883:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st175
tr889:
// line 95 "zparse.rl"
	{ mark = p }
	goto st175
st175:
	p++
	if p == pe { goto _test_eof175 }
	fallthrough
case 175:
// line 10599 "zparse.go"
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
		case 9: goto tr608
		case 10: goto tr609
		case 32: goto tr608
		case 34: goto st0
		case 40: goto tr610
		case 41: goto tr611
		case 59: goto tr612
		case 92: goto st0
	}
	goto st1
tr608:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
	goto st177
tr609:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 106 "zparse.rl"
	{ lines++ }
	goto st177
tr610:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st177
tr611:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st177
tr614:
// line 106 "zparse.rl"
	{ lines++ }
	goto st177
tr615:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st177
tr616:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st177
st177:
	p++
	if p == pe { goto _test_eof177 }
	fallthrough
case 177:
// line 10668 "zparse.go"
	switch data[p] {
		case 9: goto st177
		case 10: goto tr614
		case 32: goto st177
		case 40: goto tr615
		case 41: goto tr616
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
	if 48 <= data[p] && data[p] <= 57 { goto tr307 }
	goto st0
tr307:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st178
st178:
	p++
	if p == pe { goto _test_eof178 }
	fallthrough
case 178:
// line 10702 "zparse.go"
	switch data[p] {
		case 9: goto tr618
		case 10: goto tr619
		case 32: goto tr618
		case 40: goto tr620
		case 41: goto tr621
		case 59: goto tr623
	}
	if 48 <= data[p] && data[p] <= 57 { goto st178 }
	goto st0
tr625:
// line 106 "zparse.rl"
	{ lines++ }
	goto st179
tr626:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st179
tr627:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st179
tr618:
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 100 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st179
tr619:
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 106 "zparse.rl"
	{ lines++ }
// line 100 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st179
tr620:
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 100 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st179
tr621:
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 100 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st179
st179:
	p++
	if p == pe { goto _test_eof179 }
	fallthrough
case 179:
// line 10760 "zparse.go"
	switch data[p] {
		case 9: goto st179
		case 10: goto tr625
		case 32: goto st179
		case 34: goto st0
		case 40: goto tr626
		case 41: goto tr627
		case 59: goto st180
		case 65: goto tr629
		case 67: goto tr630
		case 72: goto tr631
		case 73: goto tr632
		case 77: goto tr633
		case 78: goto tr634
		case 92: goto st0
		case 97: goto tr629
		case 99: goto tr630
		case 104: goto tr631
		case 105: goto tr632
		case 109: goto tr633
		case 110: goto tr634
	}
	goto tr315
tr623:
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 100 "zparse.rl"
	{ tok.pushInt(data[mark:p]) }
	goto st180
st180:
	p++
	if p == pe { goto _test_eof180 }
	fallthrough
case 180:
// line 10795 "zparse.go"
	if data[p] == 10 { goto tr625 }
	goto st180
tr629:
// line 95 "zparse.rl"
	{ mark = p }
	goto st181
st181:
	p++
	if p == pe { goto _test_eof181 }
	fallthrough
case 181:
// line 10807 "zparse.go"
	switch data[p] {
		case 9: goto tr340
		case 10: goto tr341
		case 32: goto tr340
		case 34: goto st0
		case 40: goto tr342
		case 41: goto tr343
		case 59: goto tr344
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
		case 9: goto tr329
		case 10: goto tr330
		case 32: goto tr329
		case 34: goto st0
		case 40: goto tr331
		case 41: goto tr332
		case 59: goto tr333
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
		case 9: goto tr637
		case 10: goto tr638
		case 32: goto tr637
		case 34: goto st0
		case 40: goto tr639
		case 41: goto tr640
		case 59: goto tr641
		case 92: goto st0
	}
	goto st78
tr644:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st184
tr645:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st184
tr637:
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr = new(RR_MX)
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeMX
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st184
tr639:
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr = new(RR_MX)
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeMX
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st184
tr640:
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr = new(RR_MX)
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeMX
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st184
st184:
	p++
	if p == pe { goto _test_eof184 }
	fallthrough
case 184:
// line 10925 "zparse.go"
	switch data[p] {
		case 9: goto st184
		case 10: goto tr643
		case 32: goto st184
		case 40: goto tr644
		case 41: goto tr645
		case 59: goto tr646
		case 65: goto tr375
		case 67: goto tr376
		case 77: goto tr34
		case 78: goto tr377
		case 97: goto tr375
		case 99: goto tr376
		case 109: goto tr34
		case 110: goto tr377
	}
	goto st0
tr659:
// line 106 "zparse.rl"
	{ lines++ }
	goto st339
tr643:
// line 106 "zparse.rl"
	{ lines++ }
// line 95 "zparse.rl"
	{ mark = p }
	goto st339
tr638:
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 106 "zparse.rl"
	{ lines++ }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr = new(RR_MX)
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeMX
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st339
st339:
	p++
	if p == pe { goto _test_eof339 }
	fallthrough
case 339:
// line 10977 "zparse.go"
	switch data[p] {
		case 9: goto st10
		case 10: goto tr56
		case 32: goto st10
		case 34: goto st0
		case 40: goto tr57
		case 41: goto tr58
		case 59: goto tr59
		case 65: goto tr917
		case 67: goto tr918
		case 77: goto tr889
		case 78: goto tr919
		case 92: goto st0
		case 97: goto tr917
		case 99: goto tr918
		case 109: goto tr889
		case 110: goto tr919
	}
	goto st1
tr919:
// line 95 "zparse.rl"
	{ mark = p }
	goto st185
st185:
	p++
	if p == pe { goto _test_eof185 }
	fallthrough
case 185:
// line 11006 "zparse.go"
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
		case 9: goto tr648
		case 10: goto tr649
		case 32: goto tr648
		case 34: goto st0
		case 40: goto tr650
		case 41: goto tr651
		case 59: goto tr652
		case 92: goto st0
	}
	goto st1
tr648:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
	goto st187
tr649:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 106 "zparse.rl"
	{ lines++ }
	goto st187
tr650:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st187
tr651:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st187
tr654:
// line 106 "zparse.rl"
	{ lines++ }
	goto st187
tr655:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st187
tr656:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st187
st187:
	p++
	if p == pe { goto _test_eof187 }
	fallthrough
case 187:
// line 11075 "zparse.go"
	switch data[p] {
		case 9: goto st187
		case 10: goto tr654
		case 32: goto st187
		case 34: goto st0
		case 40: goto tr655
		case 41: goto tr656
		case 59: goto st188
		case 65: goto tr499
		case 67: goto tr500
		case 72: goto tr501
		case 73: goto tr502
		case 77: goto tr503
		case 78: goto tr504
		case 92: goto st0
		case 97: goto tr499
		case 99: goto tr500
		case 104: goto tr501
		case 105: goto tr502
		case 109: goto tr503
		case 110: goto tr504
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr497 }
	goto tr475
tr652:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
	goto st188
st188:
	p++
	if p == pe { goto _test_eof188 }
	fallthrough
case 188:
// line 11109 "zparse.go"
	if data[p] == 10 { goto tr654 }
	goto st188
tr646:
// line 95 "zparse.rl"
	{ mark = p }
	goto st189
tr641:
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 101 "zparse.rl"
	{ tok.pushString(data[mark:p]) }
// line 45 "types.rl"
	{
            rr = new(RR_MX)
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeMX
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
// line 102 "zparse.rl"
	{ z.Push(rr); tok.reset(); println("Setting") }
	goto st189
st189:
	p++
	if p == pe { goto _test_eof189 }
	fallthrough
case 189:
// line 11138 "zparse.go"
	if data[p] == 10 { goto tr659 }
	goto st189
tr375:
// line 95 "zparse.rl"
	{ mark = p }
	goto st190
st190:
	p++
	if p == pe { goto _test_eof190 }
	fallthrough
case 190:
// line 11150 "zparse.go"
	switch data[p] {
		case 9: goto st7
		case 10: goto tr37
		case 32: goto st7
		case 40: goto tr38
		case 41: goto tr39
		case 59: goto st191
		case 65: goto st192
		case 97: goto st192
	}
	goto st0
st191:
	p++
	if p == pe { goto _test_eof191 }
	fallthrough
case 191:
	if data[p] == 10 { goto tr37 }
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
		case 9: goto st195
		case 10: goto tr663
		case 32: goto st195
		case 40: goto tr664
		case 41: goto tr665
		case 59: goto st196
	}
	goto st0
tr663:
// line 106 "zparse.rl"
	{ lines++ }
	goto st195
tr664:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st195
tr665:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st195
st195:
	p++
	if p == pe { goto _test_eof195 }
	fallthrough
case 195:
// line 11220 "zparse.go"
	switch data[p] {
		case 9: goto st195
		case 10: goto tr663
		case 32: goto st195
		case 34: goto st0
		case 40: goto tr664
		case 41: goto tr665
		case 59: goto st196
		case 92: goto st0
	}
	goto tr187
st196:
	p++
	if p == pe { goto _test_eof196 }
	fallthrough
case 196:
	if data[p] == 10 { goto tr663 }
	goto st196
tr376:
// line 95 "zparse.rl"
	{ mark = p }
	goto st197
st197:
	p++
	if p == pe { goto _test_eof197 }
	fallthrough
case 197:
// line 11248 "zparse.go"
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
		case 9: goto st202
		case 10: goto tr672
		case 32: goto st202
		case 40: goto tr673
		case 41: goto tr674
		case 59: goto st203
	}
	goto st0
tr672:
// line 106 "zparse.rl"
	{ lines++ }
	goto st202
tr673:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st202
tr674:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st202
st202:
	p++
	if p == pe { goto _test_eof202 }
	fallthrough
case 202:
// line 11315 "zparse.go"
	switch data[p] {
		case 9: goto st202
		case 10: goto tr672
		case 32: goto st202
		case 34: goto st0
		case 40: goto tr673
		case 41: goto tr674
		case 59: goto st203
		case 92: goto st0
	}
	goto tr113
st203:
	p++
	if p == pe { goto _test_eof203 }
	fallthrough
case 203:
	if data[p] == 10 { goto tr672 }
	goto st203
tr17:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st204
tr34:
// line 95 "zparse.rl"
	{ mark = p }
	goto st204
st204:
	p++
	if p == pe { goto _test_eof204 }
	fallthrough
case 204:
// line 11349 "zparse.go"
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
		case 9: goto st206
		case 10: goto tr678
		case 32: goto st206
		case 40: goto tr679
		case 41: goto tr680
		case 59: goto st207
	}
	goto st0
tr678:
// line 106 "zparse.rl"
	{ lines++ }
	goto st206
tr679:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st206
tr680:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st206
st206:
	p++
	if p == pe { goto _test_eof206 }
	fallthrough
case 206:
// line 11386 "zparse.go"
	switch data[p] {
		case 9: goto st206
		case 10: goto tr678
		case 32: goto st206
		case 40: goto tr679
		case 41: goto tr680
		case 59: goto st207
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr444 }
	goto st0
st207:
	p++
	if p == pe { goto _test_eof207 }
	fallthrough
case 207:
	if data[p] == 10 { goto tr678 }
	goto st207
tr377:
// line 95 "zparse.rl"
	{ mark = p }
	goto st208
st208:
	p++
	if p == pe { goto _test_eof208 }
	fallthrough
case 208:
// line 11413 "zparse.go"
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
		case 9: goto st210
		case 10: goto tr684
		case 32: goto st210
		case 40: goto tr685
		case 41: goto tr686
		case 59: goto st211
	}
	goto st0
tr684:
// line 106 "zparse.rl"
	{ lines++ }
	goto st210
tr685:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st210
tr686:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st210
st210:
	p++
	if p == pe { goto _test_eof210 }
	fallthrough
case 210:
// line 11450 "zparse.go"
	switch data[p] {
		case 9: goto st210
		case 10: goto tr684
		case 32: goto st210
		case 34: goto st0
		case 40: goto tr685
		case 41: goto tr686
		case 59: goto st211
		case 92: goto st0
	}
	goto tr475
st211:
	p++
	if p == pe { goto _test_eof211 }
	fallthrough
case 211:
	if data[p] == 10 { goto tr684 }
	goto st211
tr630:
// line 95 "zparse.rl"
	{ mark = p }
	goto st212
st212:
	p++
	if p == pe { goto _test_eof212 }
	fallthrough
case 212:
// line 11478 "zparse.go"
	switch data[p] {
		case 9: goto tr329
		case 10: goto tr330
		case 32: goto tr329
		case 34: goto st0
		case 40: goto tr331
		case 41: goto tr332
		case 59: goto tr333
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
		case 9: goto tr329
		case 10: goto tr330
		case 32: goto tr329
		case 34: goto st0
		case 40: goto tr331
		case 41: goto tr332
		case 59: goto tr333
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
		case 9: goto tr329
		case 10: goto tr330
		case 32: goto tr329
		case 34: goto st0
		case 40: goto tr331
		case 41: goto tr332
		case 59: goto tr333
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
		case 9: goto tr329
		case 10: goto tr330
		case 32: goto tr329
		case 34: goto st0
		case 40: goto tr331
		case 41: goto tr332
		case 59: goto tr333
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
		case 9: goto tr692
		case 10: goto tr693
		case 32: goto tr692
		case 34: goto st0
		case 40: goto tr694
		case 41: goto tr695
		case 59: goto tr696
		case 92: goto st0
	}
	goto st78
tr631:
// line 95 "zparse.rl"
	{ mark = p }
	goto st217
st217:
	p++
	if p == pe { goto _test_eof217 }
	fallthrough
case 217:
// line 11575 "zparse.go"
	switch data[p] {
		case 9: goto tr329
		case 10: goto tr330
		case 32: goto tr329
		case 34: goto st0
		case 40: goto tr331
		case 41: goto tr332
		case 59: goto tr333
		case 83: goto st183
		case 92: goto st0
		case 115: goto st183
	}
	goto st78
tr632:
// line 95 "zparse.rl"
	{ mark = p }
	goto st218
st218:
	p++
	if p == pe { goto _test_eof218 }
	fallthrough
case 218:
// line 11598 "zparse.go"
	switch data[p] {
		case 9: goto tr329
		case 10: goto tr330
		case 32: goto tr329
		case 34: goto st0
		case 40: goto tr331
		case 41: goto tr332
		case 59: goto tr333
		case 78: goto st183
		case 92: goto st0
		case 110: goto st183
	}
	goto st78
tr326:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st219
tr633:
// line 95 "zparse.rl"
	{ mark = p }
	goto st219
st219:
	p++
	if p == pe { goto _test_eof219 }
	fallthrough
case 219:
// line 11627 "zparse.go"
	switch data[p] {
		case 9: goto tr329
		case 10: goto tr330
		case 32: goto tr329
		case 34: goto st0
		case 40: goto tr331
		case 41: goto tr332
		case 59: goto tr333
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
		case 9: goto tr698
		case 10: goto tr699
		case 32: goto tr698
		case 34: goto st0
		case 40: goto tr700
		case 41: goto tr701
		case 59: goto tr702
		case 92: goto st0
	}
	goto st78
tr634:
// line 95 "zparse.rl"
	{ mark = p }
	goto st221
st221:
	p++
	if p == pe { goto _test_eof221 }
	fallthrough
case 221:
// line 11666 "zparse.go"
	switch data[p] {
		case 9: goto tr329
		case 10: goto tr330
		case 32: goto tr329
		case 34: goto st0
		case 40: goto tr331
		case 41: goto tr332
		case 59: goto tr333
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
		case 9: goto tr329
		case 10: goto tr330
		case 32: goto tr329
		case 34: goto st0
		case 40: goto tr331
		case 41: goto tr332
		case 59: goto tr333
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
		case 9: goto tr329
		case 10: goto tr330
		case 32: goto tr329
		case 34: goto st0
		case 40: goto tr331
		case 41: goto tr332
		case 59: goto tr333
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
		case 9: goto tr706
		case 10: goto tr707
		case 32: goto tr706
		case 34: goto st0
		case 40: goto tr708
		case 41: goto tr709
		case 59: goto tr710
		case 92: goto st0
	}
	goto st78
tr612:
// line 96 "zparse.rl"
	{ hdr.Name = data[mark:p] }
	goto st225
st225:
	p++
	if p == pe { goto _test_eof225 }
	fallthrough
case 225:
// line 11743 "zparse.go"
	if data[p] == 10 { goto tr614 }
	goto st225
tr13:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st226
st226:
	p++
	if p == pe { goto _test_eof226 }
	fallthrough
case 226:
// line 11757 "zparse.go"
	switch data[p] {
		case 9: goto st7
		case 10: goto tr37
		case 32: goto st7
		case 40: goto tr38
		case 41: goto tr39
		case 59: goto st191
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
		case 9: goto tr713
		case 10: goto tr714
		case 32: goto tr713
		case 40: goto tr715
		case 41: goto tr716
		case 59: goto tr717
	}
	goto st0
tr719:
// line 106 "zparse.rl"
	{ lines++ }
	goto st229
tr720:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st229
tr721:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st229
tr713:
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st229
tr714:
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 106 "zparse.rl"
	{ lines++ }
	goto st229
tr715:
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st229
tr716:
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st229
st229:
	p++
	if p == pe { goto _test_eof229 }
	fallthrough
case 229:
// line 11834 "zparse.go"
	switch data[p] {
		case 9: goto st229
		case 10: goto tr719
		case 32: goto st229
		case 40: goto tr720
		case 41: goto tr721
		case 59: goto st233
		case 65: goto tr375
		case 67: goto tr376
		case 77: goto tr34
		case 78: goto tr377
		case 97: goto tr375
		case 99: goto tr376
		case 109: goto tr34
		case 110: goto tr377
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr373 }
	goto st0
tr373:
// line 95 "zparse.rl"
	{ mark = p }
	goto st230
st230:
	p++
	if p == pe { goto _test_eof230 }
	fallthrough
case 230:
// line 11862 "zparse.go"
	switch data[p] {
		case 9: goto tr723
		case 10: goto tr724
		case 32: goto tr723
		case 40: goto tr725
		case 41: goto tr726
		case 59: goto tr728
	}
	if 48 <= data[p] && data[p] <= 57 { goto st230 }
	goto st0
tr730:
// line 106 "zparse.rl"
	{ lines++ }
	goto st231
tr731:
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st231
tr732:
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st231
tr723:
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st231
tr724:
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 106 "zparse.rl"
	{ lines++ }
	goto st231
tr725:
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st231
tr726:
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st231
tr871:
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st231
tr872:
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 106 "zparse.rl"
	{ lines++ }
	goto st231
tr873:
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 103 "zparse.rl"
	{ if brace { println("Brace already open")} ; brace = true }
	goto st231
tr874:
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 104 "zparse.rl"
	{ if !brace { println("Brace already closed")}; brace = false }
	goto st231
st231:
	p++
	if p == pe { goto _test_eof231 }
	fallthrough
case 231:
// line 11934 "zparse.go"
	switch data[p] {
		case 9: goto st231
		case 10: goto tr730
		case 32: goto st231
		case 40: goto tr731
		case 41: goto tr732
		case 59: goto st232
		case 65: goto tr375
		case 67: goto tr376
		case 77: goto tr34
		case 78: goto tr377
		case 97: goto tr375
		case 99: goto tr376
		case 109: goto tr34
		case 110: goto tr377
	}
	goto st0
tr728:
// line 99 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st232
tr875:
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st232
st232:
	p++
	if p == pe { goto _test_eof232 }
	fallthrough
case 232:
// line 11965 "zparse.go"
	if data[p] == 10 { goto tr730 }
	goto st232
tr717:
// line 97 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st233
st233:
	p++
	if p == pe { goto _test_eof233 }
	fallthrough
case 233:
// line 11977 "zparse.go"
	if data[p] == 10 { goto tr719 }
	goto st233
tr14:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st234
st234:
	p++
	if p == pe { goto _test_eof234 }
	fallthrough
case 234:
// line 11991 "zparse.go"
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
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st235
st235:
	p++
	if p == pe { goto _test_eof235 }
	fallthrough
case 235:
// line 12012 "zparse.go"
	switch data[p] {
		case 83: goto st228
		case 115: goto st228
	}
	goto st0
tr16:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st236
st236:
	p++
	if p == pe { goto _test_eof236 }
	fallthrough
case 236:
// line 12029 "zparse.go"
	switch data[p] {
		case 78: goto st228
		case 110: goto st228
	}
	goto st0
tr18:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st237
st237:
	p++
	if p == pe { goto _test_eof237 }
	fallthrough
case 237:
// line 12046 "zparse.go"
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
tr323:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st240
st240:
	p++
	if p == pe { goto _test_eof240 }
	fallthrough
case 240:
// line 12085 "zparse.go"
	switch data[p] {
		case 9: goto tr329
		case 10: goto tr330
		case 32: goto tr329
		case 34: goto st0
		case 40: goto tr331
		case 41: goto tr332
		case 59: goto tr333
		case 72: goto st89
		case 78: goto st213
		case 83: goto st89
		case 92: goto st0
		case 104: goto st89
		case 110: goto st213
		case 115: goto st89
	}
	goto st78
tr324:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st241
st241:
	p++
	if p == pe { goto _test_eof241 }
	fallthrough
case 241:
// line 12114 "zparse.go"
	switch data[p] {
		case 9: goto tr329
		case 10: goto tr330
		case 32: goto tr329
		case 34: goto st0
		case 40: goto tr331
		case 41: goto tr332
		case 59: goto tr333
		case 83: goto st89
		case 92: goto st0
		case 115: goto st89
	}
	goto st78
tr325:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st242
st242:
	p++
	if p == pe { goto _test_eof242 }
	fallthrough
case 242:
// line 12139 "zparse.go"
	switch data[p] {
		case 9: goto tr329
		case 10: goto tr330
		case 32: goto tr329
		case 34: goto st0
		case 40: goto tr331
		case 41: goto tr332
		case 59: goto tr333
		case 78: goto st89
		case 92: goto st0
		case 110: goto st89
	}
	goto st78
tr327:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st243
st243:
	p++
	if p == pe { goto _test_eof243 }
	fallthrough
case 243:
// line 12164 "zparse.go"
	switch data[p] {
		case 9: goto tr329
		case 10: goto tr330
		case 32: goto tr329
		case 34: goto st0
		case 40: goto tr331
		case 41: goto tr332
		case 59: goto tr333
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
		case 9: goto tr329
		case 10: goto tr330
		case 32: goto tr329
		case 34: goto st0
		case 40: goto tr331
		case 41: goto tr332
		case 59: goto tr333
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
		case 9: goto tr329
		case 10: goto tr330
		case 32: goto tr329
		case 34: goto st0
		case 40: goto tr331
		case 41: goto tr332
		case 59: goto tr333
		case 69: goto st89
		case 92: goto st0
		case 101: goto st89
	}
	goto st78
tr881:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st246
tr887:
// line 95 "zparse.rl"
	{ mark = p }
	goto st246
st246:
	p++
	if p == pe { goto _test_eof246 }
	fallthrough
case 246:
// line 12231 "zparse.go"
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
tr882:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st247
tr888:
// line 95 "zparse.rl"
	{ mark = p }
	goto st247
st247:
	p++
	if p == pe { goto _test_eof247 }
	fallthrough
case 247:
// line 12260 "zparse.go"
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
tr884:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st248
tr890:
// line 95 "zparse.rl"
	{ mark = p }
	goto st248
st248:
	p++
	if p == pe { goto _test_eof248 }
	fallthrough
case 248:
// line 12289 "zparse.go"
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
tr914:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st251
st251:
	p++
	if p == pe { goto _test_eof251 }
	fallthrough
case 251:
// line 12352 "zparse.go"
	switch data[p] {
		case 9: goto tr255
		case 10: goto tr256
		case 32: goto tr255
		case 34: goto st0
		case 40: goto tr257
		case 41: goto tr258
		case 59: goto tr259
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
		case 9: goto tr255
		case 10: goto tr256
		case 32: goto tr255
		case 34: goto st0
		case 40: goto tr257
		case 41: goto tr258
		case 59: goto tr259
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
		case 9: goto tr255
		case 10: goto tr256
		case 32: goto tr255
		case 34: goto st0
		case 40: goto tr257
		case 41: goto tr258
		case 59: goto tr259
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
		case 9: goto tr743
		case 10: goto tr744
		case 32: goto tr743
		case 34: goto st0
		case 40: goto tr745
		case 41: goto tr746
		case 59: goto tr747
		case 92: goto st0
	}
	goto st57
tr121:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st255
st255:
	p++
	if p == pe { goto _test_eof255 }
	fallthrough
case 255:
// line 12431 "zparse.go"
	switch data[p] {
		case 9: goto tr127
		case 10: goto tr128
		case 32: goto tr127
		case 34: goto st0
		case 40: goto tr129
		case 41: goto tr130
		case 59: goto tr131
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
		case 9: goto tr750
		case 10: goto tr751
		case 32: goto tr750
		case 34: goto st0
		case 40: goto tr752
		case 41: goto tr753
		case 59: goto tr754
		case 92: goto st0
	}
	goto st25
st257:
	p++
	if p == pe { goto _test_eof257 }
	fallthrough
case 257:
	switch data[p] {
		case 9: goto tr127
		case 10: goto tr128
		case 32: goto tr127
		case 34: goto st0
		case 40: goto tr129
		case 41: goto tr130
		case 59: goto tr131
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
		case 9: goto tr127
		case 10: goto tr128
		case 32: goto tr127
		case 34: goto st0
		case 40: goto tr129
		case 41: goto tr130
		case 59: goto tr131
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
		case 9: goto tr127
		case 10: goto tr128
		case 32: goto tr127
		case 34: goto st0
		case 40: goto tr129
		case 41: goto tr130
		case 59: goto tr131
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
		case 9: goto tr758
		case 10: goto tr759
		case 32: goto tr758
		case 34: goto st0
		case 40: goto tr760
		case 41: goto tr761
		case 59: goto tr762
		case 92: goto st0
	}
	goto st25
tr122:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st261
st261:
	p++
	if p == pe { goto _test_eof261 }
	fallthrough
case 261:
// line 12546 "zparse.go"
	switch data[p] {
		case 9: goto tr127
		case 10: goto tr128
		case 32: goto tr127
		case 34: goto st0
		case 40: goto tr129
		case 41: goto tr130
		case 59: goto tr131
		case 83: goto st256
		case 92: goto st0
		case 115: goto st256
	}
	goto st25
tr123:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st262
st262:
	p++
	if p == pe { goto _test_eof262 }
	fallthrough
case 262:
// line 12571 "zparse.go"
	switch data[p] {
		case 9: goto tr127
		case 10: goto tr128
		case 32: goto tr127
		case 34: goto st0
		case 40: goto tr129
		case 41: goto tr130
		case 59: goto tr131
		case 78: goto st256
		case 92: goto st0
		case 110: goto st256
	}
	goto st25
tr124:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st263
st263:
	p++
	if p == pe { goto _test_eof263 }
	fallthrough
case 263:
// line 12596 "zparse.go"
	switch data[p] {
		case 9: goto tr127
		case 10: goto tr128
		case 32: goto tr127
		case 34: goto st0
		case 40: goto tr129
		case 41: goto tr130
		case 59: goto tr131
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
		case 9: goto tr764
		case 10: goto tr765
		case 32: goto tr764
		case 34: goto st0
		case 40: goto tr766
		case 41: goto tr767
		case 59: goto tr768
		case 92: goto st0
	}
	goto st25
tr125:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st265
st265:
	p++
	if p == pe { goto _test_eof265 }
	fallthrough
case 265:
// line 12637 "zparse.go"
	switch data[p] {
		case 9: goto tr127
		case 10: goto tr128
		case 32: goto tr127
		case 34: goto st0
		case 40: goto tr129
		case 41: goto tr130
		case 59: goto tr131
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
		case 9: goto tr127
		case 10: goto tr128
		case 32: goto tr127
		case 34: goto st0
		case 40: goto tr129
		case 41: goto tr130
		case 59: goto tr131
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
		case 9: goto tr127
		case 10: goto tr128
		case 32: goto tr127
		case 34: goto st0
		case 40: goto tr129
		case 41: goto tr130
		case 59: goto tr131
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
		case 9: goto tr772
		case 10: goto tr773
		case 32: goto tr772
		case 34: goto st0
		case 40: goto tr774
		case 41: goto tr775
		case 59: goto tr776
		case 92: goto st0
	}
	goto st25
tr903:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st269
st269:
	p++
	if p == pe { goto _test_eof269 }
	fallthrough
case 269:
// line 12716 "zparse.go"
	switch data[p] {
		case 9: goto tr207
		case 10: goto tr208
		case 32: goto tr207
		case 34: goto st0
		case 40: goto tr209
		case 41: goto tr210
		case 59: goto tr211
		case 83: goto st50
		case 92: goto st0
		case 115: goto st50
	}
	goto st42
tr904:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st270
st270:
	p++
	if p == pe { goto _test_eof270 }
	fallthrough
case 270:
// line 12741 "zparse.go"
	switch data[p] {
		case 9: goto tr207
		case 10: goto tr208
		case 32: goto tr207
		case 34: goto st0
		case 40: goto tr209
		case 41: goto tr210
		case 59: goto tr211
		case 78: goto st50
		case 92: goto st0
		case 110: goto st50
	}
	goto st42
tr905:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st271
st271:
	p++
	if p == pe { goto _test_eof271 }
	fallthrough
case 271:
// line 12766 "zparse.go"
	switch data[p] {
		case 9: goto tr207
		case 10: goto tr208
		case 32: goto tr207
		case 34: goto st0
		case 40: goto tr209
		case 41: goto tr210
		case 59: goto tr211
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
		case 9: goto tr778
		case 10: goto tr779
		case 32: goto tr778
		case 34: goto st0
		case 40: goto tr780
		case 41: goto tr781
		case 59: goto tr782
		case 92: goto st0
	}
	goto st42
tr906:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st273
st273:
	p++
	if p == pe { goto _test_eof273 }
	fallthrough
case 273:
// line 12807 "zparse.go"
	switch data[p] {
		case 9: goto tr207
		case 10: goto tr208
		case 32: goto tr207
		case 34: goto st0
		case 40: goto tr209
		case 41: goto tr210
		case 59: goto tr211
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
		case 9: goto tr207
		case 10: goto tr208
		case 32: goto tr207
		case 34: goto st0
		case 40: goto tr209
		case 41: goto tr210
		case 59: goto tr211
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
		case 9: goto tr207
		case 10: goto tr208
		case 32: goto tr207
		case 34: goto st0
		case 40: goto tr209
		case 41: goto tr210
		case 59: goto tr211
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
		case 9: goto tr786
		case 10: goto tr787
		case 32: goto tr786
		case 34: goto st0
		case 40: goto tr788
		case 41: goto tr789
		case 59: goto tr790
		case 92: goto st0
	}
	goto st42
st277:
	p++
	if p == pe { goto _test_eof277 }
	fallthrough
case 277:
	switch data[p] {
		case 9: goto tr155
		case 10: goto tr156
		case 32: goto tr155
		case 34: goto st0
		case 40: goto tr157
		case 41: goto tr158
		case 59: goto tr159
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
		case 9: goto tr792
		case 10: goto tr793
		case 32: goto tr792
		case 34: goto st0
		case 40: goto tr794
		case 41: goto tr795
		case 59: goto tr796
		case 92: goto st0
	}
	goto st32
tr894:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st279
st279:
	p++
	if p == pe { goto _test_eof279 }
	fallthrough
case 279:
// line 12920 "zparse.go"
	switch data[p] {
		case 9: goto tr155
		case 10: goto tr156
		case 32: goto tr155
		case 34: goto st0
		case 40: goto tr157
		case 41: goto tr158
		case 59: goto tr159
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
		case 9: goto tr155
		case 10: goto tr156
		case 32: goto tr155
		case 34: goto st0
		case 40: goto tr157
		case 41: goto tr158
		case 59: goto tr159
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
		case 9: goto tr155
		case 10: goto tr156
		case 32: goto tr155
		case 34: goto st0
		case 40: goto tr157
		case 41: goto tr158
		case 59: goto tr159
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
		case 9: goto tr155
		case 10: goto tr156
		case 32: goto tr155
		case 34: goto st0
		case 40: goto tr157
		case 41: goto tr158
		case 59: goto tr159
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
		case 9: goto tr801
		case 10: goto tr802
		case 32: goto tr801
		case 34: goto st0
		case 40: goto tr803
		case 41: goto tr804
		case 59: goto tr805
		case 92: goto st0
	}
	goto st32
tr895:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st284
st284:
	p++
	if p == pe { goto _test_eof284 }
	fallthrough
case 284:
// line 13019 "zparse.go"
	switch data[p] {
		case 9: goto tr155
		case 10: goto tr156
		case 32: goto tr155
		case 34: goto st0
		case 40: goto tr157
		case 41: goto tr158
		case 59: goto tr159
		case 83: goto st278
		case 92: goto st0
		case 115: goto st278
	}
	goto st32
tr896:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st285
st285:
	p++
	if p == pe { goto _test_eof285 }
	fallthrough
case 285:
// line 13044 "zparse.go"
	switch data[p] {
		case 9: goto tr155
		case 10: goto tr156
		case 32: goto tr155
		case 34: goto st0
		case 40: goto tr157
		case 41: goto tr158
		case 59: goto tr159
		case 78: goto st278
		case 92: goto st0
		case 110: goto st278
	}
	goto st32
tr897:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st286
st286:
	p++
	if p == pe { goto _test_eof286 }
	fallthrough
case 286:
// line 13069 "zparse.go"
	switch data[p] {
		case 9: goto tr155
		case 10: goto tr156
		case 32: goto tr155
		case 34: goto st0
		case 40: goto tr157
		case 41: goto tr158
		case 59: goto tr159
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
		case 9: goto tr807
		case 10: goto tr808
		case 32: goto tr807
		case 34: goto st0
		case 40: goto tr809
		case 41: goto tr810
		case 59: goto tr811
		case 92: goto st0
	}
	goto st32
tr898:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st288
st288:
	p++
	if p == pe { goto _test_eof288 }
	fallthrough
case 288:
// line 13110 "zparse.go"
	switch data[p] {
		case 9: goto tr155
		case 10: goto tr156
		case 32: goto tr155
		case 34: goto st0
		case 40: goto tr157
		case 41: goto tr158
		case 59: goto tr159
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
		case 9: goto tr155
		case 10: goto tr156
		case 32: goto tr155
		case 34: goto st0
		case 40: goto tr157
		case 41: goto tr158
		case 59: goto tr159
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
		case 9: goto tr155
		case 10: goto tr156
		case 32: goto tr155
		case 34: goto st0
		case 40: goto tr157
		case 41: goto tr158
		case 59: goto tr159
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
		case 9: goto tr815
		case 10: goto tr816
		case 32: goto tr815
		case 34: goto st0
		case 40: goto tr817
		case 41: goto tr818
		case 59: goto tr819
		case 92: goto st0
	}
	goto st32
tr81:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st292
st292:
	p++
	if p == pe { goto _test_eof292 }
	fallthrough
case 292:
// line 13189 "zparse.go"
	switch data[p] {
		case 9: goto tr820
		case 10: goto tr821
		case 32: goto tr820
		case 34: goto st0
		case 40: goto tr822
		case 41: goto tr823
		case 59: goto tr824
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
		case 9: goto tr45
		case 10: goto tr46
		case 32: goto tr45
		case 34: goto st0
		case 40: goto tr47
		case 41: goto tr48
		case 59: goto tr49
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
		case 9: goto tr45
		case 10: goto tr46
		case 32: goto tr45
		case 34: goto st0
		case 40: goto tr47
		case 41: goto tr48
		case 59: goto tr49
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
		case 9: goto tr829
		case 10: goto tr830
		case 32: goto tr829
		case 34: goto st0
		case 40: goto tr831
		case 41: goto tr832
		case 59: goto tr833
		case 92: goto st0
	}
	goto st8
st296:
	p++
	if p == pe { goto _test_eof296 }
	fallthrough
case 296:
	switch data[p] {
		case 9: goto tr45
		case 10: goto tr46
		case 32: goto tr45
		case 34: goto st0
		case 40: goto tr47
		case 41: goto tr48
		case 59: goto tr49
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
		case 9: goto tr835
		case 10: goto tr836
		case 32: goto tr835
		case 34: goto st0
		case 40: goto tr837
		case 41: goto tr838
		case 59: goto tr839
		case 92: goto st0
	}
	goto st8
tr82:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st298
st298:
	p++
	if p == pe { goto _test_eof298 }
	fallthrough
case 298:
// line 13302 "zparse.go"
	switch data[p] {
		case 9: goto tr45
		case 10: goto tr46
		case 32: goto tr45
		case 34: goto st0
		case 40: goto tr47
		case 41: goto tr48
		case 59: goto tr49
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
		case 9: goto tr45
		case 10: goto tr46
		case 32: goto tr45
		case 34: goto st0
		case 40: goto tr47
		case 41: goto tr48
		case 59: goto tr49
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
		case 9: goto tr45
		case 10: goto tr46
		case 32: goto tr45
		case 34: goto st0
		case 40: goto tr47
		case 41: goto tr48
		case 59: goto tr49
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
		case 9: goto tr45
		case 10: goto tr46
		case 32: goto tr45
		case 34: goto st0
		case 40: goto tr47
		case 41: goto tr48
		case 59: goto tr49
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
		case 9: goto tr844
		case 10: goto tr845
		case 32: goto tr844
		case 34: goto st0
		case 40: goto tr846
		case 41: goto tr847
		case 59: goto tr848
		case 92: goto st0
	}
	goto st8
tr83:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st303
st303:
	p++
	if p == pe { goto _test_eof303 }
	fallthrough
case 303:
// line 13401 "zparse.go"
	switch data[p] {
		case 9: goto tr45
		case 10: goto tr46
		case 32: goto tr45
		case 34: goto st0
		case 40: goto tr47
		case 41: goto tr48
		case 59: goto tr49
		case 83: goto st297
		case 92: goto st0
		case 115: goto st297
	}
	goto st8
tr84:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st304
st304:
	p++
	if p == pe { goto _test_eof304 }
	fallthrough
case 304:
// line 13426 "zparse.go"
	switch data[p] {
		case 9: goto tr45
		case 10: goto tr46
		case 32: goto tr45
		case 34: goto st0
		case 40: goto tr47
		case 41: goto tr48
		case 59: goto tr49
		case 78: goto st297
		case 92: goto st0
		case 110: goto st297
	}
	goto st8
tr85:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st305
st305:
	p++
	if p == pe { goto _test_eof305 }
	fallthrough
case 305:
// line 13451 "zparse.go"
	switch data[p] {
		case 9: goto tr45
		case 10: goto tr46
		case 32: goto tr45
		case 34: goto st0
		case 40: goto tr47
		case 41: goto tr48
		case 59: goto tr49
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
		case 9: goto tr850
		case 10: goto tr851
		case 32: goto tr850
		case 34: goto st0
		case 40: goto tr852
		case 41: goto tr853
		case 59: goto tr854
		case 92: goto st0
	}
	goto st8
tr86:
// line 95 "zparse.rl"
	{ mark = p }
// line 98 "zparse.rl"
	{ /* ... */ }
	goto st307
st307:
	p++
	if p == pe { goto _test_eof307 }
	fallthrough
case 307:
// line 13492 "zparse.go"
	switch data[p] {
		case 9: goto tr45
		case 10: goto tr46
		case 32: goto tr45
		case 34: goto st0
		case 40: goto tr47
		case 41: goto tr48
		case 59: goto tr49
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
		case 9: goto tr45
		case 10: goto tr46
		case 32: goto tr45
		case 34: goto st0
		case 40: goto tr47
		case 41: goto tr48
		case 59: goto tr49
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
		case 9: goto tr45
		case 10: goto tr46
		case 32: goto tr45
		case 34: goto st0
		case 40: goto tr47
		case 41: goto tr48
		case 59: goto tr49
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
		case 9: goto tr858
		case 10: goto tr859
		case 32: goto tr858
		case 34: goto st0
		case 40: goto tr860
		case 41: goto tr861
		case 59: goto tr862
		case 92: goto st0
	}
	goto st8
st311:
	p++
	if p == pe { goto _test_eof311 }
	fallthrough
case 311:
	switch data[p] {
		case 9: goto tr127
		case 10: goto tr128
		case 32: goto tr127
		case 34: goto st0
		case 40: goto tr129
		case 41: goto tr130
		case 59: goto tr131
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
		case 9: goto tr127
		case 10: goto tr128
		case 32: goto tr127
		case 34: goto st0
		case 40: goto tr129
		case 41: goto tr130
		case 59: goto tr131
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
		case 9: goto tr865
		case 10: goto tr866
		case 32: goto tr865
		case 34: goto st0
		case 40: goto tr867
		case 41: goto tr868
		case 59: goto tr869
		case 92: goto st0
	}
	goto st25
st314:
	p++
	if p == pe { goto _test_eof314 }
	fallthrough
case 314:
	switch data[p] {
		case 9: goto tr127
		case 10: goto tr128
		case 32: goto tr127
		case 34: goto st0
		case 40: goto tr129
		case 41: goto tr130
		case 59: goto tr131
		case 89: goto st256
		case 92: goto st0
		case 121: goto st256
	}
	goto st25
tr31:
// line 95 "zparse.rl"
	{ mark = p }
	goto st315
st315:
	p++
	if p == pe { goto _test_eof315 }
	fallthrough
case 315:
// line 13639 "zparse.go"
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
		case 9: goto tr871
		case 10: goto tr872
		case 32: goto tr871
		case 40: goto tr873
		case 41: goto tr874
		case 59: goto tr875
	}
	goto st0
tr32:
// line 95 "zparse.rl"
	{ mark = p }
	goto st317
st317:
	p++
	if p == pe { goto _test_eof317 }
	fallthrough
case 317:
// line 13672 "zparse.go"
	switch data[p] {
		case 83: goto st316
		case 115: goto st316
	}
	goto st0
tr33:
// line 95 "zparse.rl"
	{ mark = p }
	goto st318
st318:
	p++
	if p == pe { goto _test_eof318 }
	fallthrough
case 318:
// line 13687 "zparse.go"
	switch data[p] {
		case 78: goto st316
		case 110: goto st316
	}
	goto st0
tr35:
// line 95 "zparse.rl"
	{ mark = p }
	goto st319
st319:
	p++
	if p == pe { goto _test_eof319 }
	fallthrough
case 319:
// line 13702 "zparse.go"
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

// line 154 "zparse.rl"

        
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
