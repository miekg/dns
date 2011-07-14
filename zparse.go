
// line 1 "zparse.rl"
package dns

// Parse RRs
// With the thankful help of gdnsd and the Go examples for Ragel 

import (
    "os"
    "fmt"
    "net"
    "strconv"
)


// line 17 "zparse.go"
var z_start int = 1
var z_first_final int = 36
var z_error int = 0

var z_en_main int = 1


// line 16 "zparse.rl"


func zparse(data string) (r RR, err os.Error) {
        cs, p, pe := 0, 0, len(data)
        mark := 0
        eof := len(data)
        hdr := new(RR_Header)

        
// line 35 "zparse.go"
	cs = z_start

// line 38 "zparse.go"
	{
	if p == pe { goto _test_eof }
	switch cs {
	case -666: // i am a hack D:
	fallthrough
case 1:
	switch data[p] {
		case 9: goto st2
		case 32: goto st2
		case 46: goto st18
		case 92: goto st18
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st18 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st18 }
	} else {
		goto st18
	}
	goto st0
st0:
cs = 0;
	goto _out;
tr34:
// line 29 "zparse.rl"
	{ hdr.Name = data[mark:p] }
	goto st2
st2:
	p++
	if p == pe { goto _test_eof2 }
	fallthrough
case 2:
// line 71 "zparse.go"
	switch data[p] {
		case 9: goto st2
		case 32: goto st2
		case 65: goto tr4
		case 67: goto tr5
		case 68: goto tr6
		case 72: goto tr7
		case 73: goto tr8
		case 78: goto tr9
		case 97: goto tr4
		case 99: goto tr5
		case 100: goto tr6
		case 104: goto tr7
		case 105: goto tr8
		case 110: goto tr9
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr3 }
	goto st0
tr3:
// line 28 "zparse.rl"
	{ mark = p }
// line 32 "zparse.rl"
	{ fmt.Printf("defttl {%s}\n", data[mark:p]) }
	goto st3
st3:
	p++
	if p == pe { goto _test_eof3 }
	fallthrough
case 3:
// line 101 "zparse.go"
	switch data[p] {
		case 9: goto tr10
		case 32: goto tr10
	}
	if 48 <= data[p] && data[p] <= 57 { goto st3 }
	goto st0
tr10:
// line 33 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st4
st4:
	p++
	if p == pe { goto _test_eof4 }
	fallthrough
case 4:
// line 117 "zparse.go"
	switch data[p] {
		case 9: goto st4
		case 32: goto st4
		case 65: goto tr13
		case 67: goto tr14
		case 68: goto tr15
		case 72: goto tr16
		case 73: goto tr17
		case 78: goto tr18
		case 97: goto tr13
		case 99: goto tr14
		case 100: goto tr15
		case 104: goto tr16
		case 105: goto tr17
		case 110: goto tr18
	}
	goto st0
tr13:
// line 28 "zparse.rl"
	{ mark = p }
	goto st5
st5:
	p++
	if p == pe { goto _test_eof5 }
	fallthrough
case 5:
// line 144 "zparse.go"
	switch data[p] {
		case 9: goto st6
		case 32: goto st6
		case 78: goto st7
		case 110: goto st7
	}
	goto st0
st6:
	p++
	if p == pe { goto _test_eof6 }
	fallthrough
case 6:
	switch data[p] {
		case 9: goto tr22
		case 32: goto tr22
	}
	goto tr21
tr21:
// line 28 "zparse.rl"
	{ mark = p }
	goto st36
st36:
	p++
	if p == pe { goto _test_eof36 }
	fallthrough
case 36:
// line 171 "zparse.go"
	goto st36
tr22:
// line 28 "zparse.rl"
	{ mark = p }
	goto st37
st37:
	p++
	if p == pe { goto _test_eof37 }
	fallthrough
case 37:
// line 182 "zparse.go"
	switch data[p] {
		case 9: goto tr22
		case 32: goto tr22
	}
	goto tr21
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
		case 9: goto tr24
		case 32: goto tr24
	}
	goto st0
tr42:
// line 33 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st9
tr24:
// line 30 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st9
st9:
	p++
	if p == pe { goto _test_eof9 }
	fallthrough
case 9:
// line 221 "zparse.go"
	switch data[p] {
		case 9: goto st9
		case 32: goto st9
		case 65: goto tr26
		case 68: goto tr15
		case 97: goto tr26
		case 100: goto tr15
	}
	goto st0
tr26:
// line 28 "zparse.rl"
	{ mark = p }
	goto st10
st10:
	p++
	if p == pe { goto _test_eof10 }
	fallthrough
case 10:
// line 240 "zparse.go"
	switch data[p] {
		case 9: goto st6
		case 32: goto st6
	}
	goto st0
tr6:
// line 28 "zparse.rl"
	{ mark = p }
// line 32 "zparse.rl"
	{ fmt.Printf("defttl {%s}\n", data[mark:p]) }
	goto st11
tr15:
// line 28 "zparse.rl"
	{ mark = p }
	goto st11
st11:
	p++
	if p == pe { goto _test_eof11 }
	fallthrough
case 11:
// line 261 "zparse.go"
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
		case 83: goto st13
		case 115: goto st13
	}
	goto st0
st13:
	p++
	if p == pe { goto _test_eof13 }
	fallthrough
case 13:
	switch data[p] {
		case 75: goto st14
		case 107: goto st14
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
		case 9: goto st17
		case 32: goto st17
	}
	goto st0
st17:
	p++
	if p == pe { goto _test_eof17 }
	fallthrough
case 17:
	switch data[p] {
		case 9: goto st17
		case 32: goto st17
		case 46: goto tr33
		case 92: goto tr33
	}
	if data[p] > 57 {
		if 97 <= data[p] && data[p] <= 122 { goto tr33 }
	} else if data[p] >= 48 {
		goto tr33
	}
	goto st0
tr33:
// line 28 "zparse.rl"
	{ mark = p }
	goto st38
st38:
	p++
	if p == pe { goto _test_eof38 }
	fallthrough
case 38:
// line 343 "zparse.go"
	switch data[p] {
		case 9: goto st2
		case 32: goto st2
		case 46: goto st39
		case 92: goto st39
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st39 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st39 }
	} else {
		goto st18
	}
	goto st0
st39:
	p++
	if p == pe { goto _test_eof39 }
	fallthrough
case 39:
	switch data[p] {
		case 9: goto tr34
		case 32: goto tr34
		case 46: goto st39
		case 92: goto st39
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st39 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st39 }
	} else {
		goto st18
	}
	goto st0
st18:
	p++
	if p == pe { goto _test_eof18 }
	fallthrough
case 18:
	switch data[p] {
		case 9: goto tr34
		case 32: goto tr34
		case 46: goto st18
		case 92: goto st18
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st18 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st18 }
	} else {
		goto st18
	}
	goto st0
tr14:
// line 28 "zparse.rl"
	{ mark = p }
	goto st19
st19:
	p++
	if p == pe { goto _test_eof19 }
	fallthrough
case 19:
// line 405 "zparse.go"
	switch data[p] {
		case 72: goto st8
		case 83: goto st8
		case 104: goto st8
		case 115: goto st8
	}
	goto st0
tr16:
// line 28 "zparse.rl"
	{ mark = p }
	goto st20
st20:
	p++
	if p == pe { goto _test_eof20 }
	fallthrough
case 20:
// line 422 "zparse.go"
	switch data[p] {
		case 83: goto st8
		case 115: goto st8
	}
	goto st0
tr17:
// line 28 "zparse.rl"
	{ mark = p }
	goto st21
st21:
	p++
	if p == pe { goto _test_eof21 }
	fallthrough
case 21:
// line 437 "zparse.go"
	switch data[p] {
		case 78: goto st8
		case 110: goto st8
	}
	goto st0
tr18:
// line 28 "zparse.rl"
	{ mark = p }
	goto st22
st22:
	p++
	if p == pe { goto _test_eof22 }
	fallthrough
case 22:
// line 452 "zparse.go"
	switch data[p] {
		case 79: goto st23
		case 111: goto st23
	}
	goto st0
st23:
	p++
	if p == pe { goto _test_eof23 }
	fallthrough
case 23:
	switch data[p] {
		case 78: goto st24
		case 110: goto st24
	}
	goto st0
st24:
	p++
	if p == pe { goto _test_eof24 }
	fallthrough
case 24:
	switch data[p] {
		case 69: goto st8
		case 101: goto st8
	}
	goto st0
tr4:
// line 28 "zparse.rl"
	{ mark = p }
// line 32 "zparse.rl"
	{ fmt.Printf("defttl {%s}\n", data[mark:p]) }
	goto st25
st25:
	p++
	if p == pe { goto _test_eof25 }
	fallthrough
case 25:
// line 489 "zparse.go"
	switch data[p] {
		case 9: goto st6
		case 32: goto st6
		case 78: goto st26
		case 110: goto st26
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
		case 9: goto tr39
		case 32: goto tr39
	}
	goto st0
tr39:
// line 30 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st28
st28:
	p++
	if p == pe { goto _test_eof28 }
	fallthrough
case 28:
// line 526 "zparse.go"
	switch data[p] {
		case 9: goto st28
		case 32: goto st28
		case 65: goto tr26
		case 68: goto tr15
		case 97: goto tr26
		case 100: goto tr15
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr41 }
	goto st0
tr41:
// line 28 "zparse.rl"
	{ mark = p }
	goto st29
st29:
	p++
	if p == pe { goto _test_eof29 }
	fallthrough
case 29:
// line 546 "zparse.go"
	switch data[p] {
		case 9: goto tr42
		case 32: goto tr42
	}
	if 48 <= data[p] && data[p] <= 57 { goto st29 }
	goto st0
tr5:
// line 28 "zparse.rl"
	{ mark = p }
// line 32 "zparse.rl"
	{ fmt.Printf("defttl {%s}\n", data[mark:p]) }
	goto st30
st30:
	p++
	if p == pe { goto _test_eof30 }
	fallthrough
case 30:
// line 564 "zparse.go"
	switch data[p] {
		case 72: goto st27
		case 83: goto st27
		case 104: goto st27
		case 115: goto st27
	}
	goto st0
tr7:
// line 28 "zparse.rl"
	{ mark = p }
// line 32 "zparse.rl"
	{ fmt.Printf("defttl {%s}\n", data[mark:p]) }
	goto st31
st31:
	p++
	if p == pe { goto _test_eof31 }
	fallthrough
case 31:
// line 583 "zparse.go"
	switch data[p] {
		case 83: goto st27
		case 115: goto st27
	}
	goto st0
tr8:
// line 28 "zparse.rl"
	{ mark = p }
// line 32 "zparse.rl"
	{ fmt.Printf("defttl {%s}\n", data[mark:p]) }
	goto st32
st32:
	p++
	if p == pe { goto _test_eof32 }
	fallthrough
case 32:
// line 600 "zparse.go"
	switch data[p] {
		case 78: goto st27
		case 110: goto st27
	}
	goto st0
tr9:
// line 28 "zparse.rl"
	{ mark = p }
// line 32 "zparse.rl"
	{ fmt.Printf("defttl {%s}\n", data[mark:p]) }
	goto st33
st33:
	p++
	if p == pe { goto _test_eof33 }
	fallthrough
case 33:
// line 617 "zparse.go"
	switch data[p] {
		case 79: goto st34
		case 111: goto st34
	}
	goto st0
st34:
	p++
	if p == pe { goto _test_eof34 }
	fallthrough
case 34:
	switch data[p] {
		case 78: goto st35
		case 110: goto st35
	}
	goto st0
st35:
	p++
	if p == pe { goto _test_eof35 }
	fallthrough
case 35:
	switch data[p] {
		case 69: goto st27
		case 101: goto st27
	}
	goto st0
	}
	_test_eof2: cs = 2; goto _test_eof; 
	_test_eof3: cs = 3; goto _test_eof; 
	_test_eof4: cs = 4; goto _test_eof; 
	_test_eof5: cs = 5; goto _test_eof; 
	_test_eof6: cs = 6; goto _test_eof; 
	_test_eof36: cs = 36; goto _test_eof; 
	_test_eof37: cs = 37; goto _test_eof; 
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
	_test_eof38: cs = 38; goto _test_eof; 
	_test_eof39: cs = 39; goto _test_eof; 
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

	_test_eof: {}
	if p == eof {
	switch cs {
	case 36, 37:
// line 35 "zparse.rl"
	{
                    r = new(RR_A)
                    r.(*RR_A).Hdr = *hdr
                    r.(*RR_A).Hdr.Rrtype = TypeA
                    r.(*RR_A).A = net.ParseIP(data[mark:p])
                }
	break
// line 695 "zparse.go"
	}
	}

	_out: {}
	}

// line 68 "zparse.rl"


        if cs < z_first_final {
                // No clue what I'm doing what so ever
                if p == pe {
                        return nil, os.ErrorString("unexpected eof")
                } else {
                        return nil, os.ErrorString(fmt.Sprintf("error at position %d", p))
                }
        }
        return r ,nil
}
