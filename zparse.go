
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
var z_first_final int = 59
var z_error int = 0

var z_en_main int = 1


// line 16 "zparse.rl"


func zparse(data string) (r RR, err os.Error) {
        cs, p, pe, eof := 0, 0, len(data), len(data)
        j := 0; j = j // Needed for compile.
        k := 0; k = k // "
        mark := 0
        hdr := new(RR_Header)
        txt := make([]string, 10)
        num := make([]int, 10)

        
// line 38 "zparse.go"
	cs = z_start

// line 41 "zparse.go"
	{
	if p == pe { goto _test_eof }
	switch cs {
	case -666: // i am a hack D:
	fallthrough
case 1:
	switch data[p] {
		case 9: goto st2
		case 32: goto st2
		case 46: goto st41
		case 92: goto st41
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st41 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st41 }
	} else {
		goto st41
	}
	goto st0
st0:
cs = 0;
	goto _out;
tr79:
// line 29 "zparse.rl"
	{ hdr.Name = data[mark:p] }
	goto st2
tr91:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 4 "types.rl"
	{
            r.(*RR_A).Hdr = *hdr
            r.(*RR_A).A = net.ParseIP(data[mark:p])
        }
	goto st2
tr93:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 12 "types.rl"
	{
            r.(*RR_CNAME).Hdr = *hdr
            r.(*RR_CNAME).Cname = txt[0]
        }
	goto st2
tr95:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 26 "types.rl"
	{
            r.(*RR_MX).Hdr = *hdr;
            r.(*RR_MX).Pref = uint16(num[0])
            r.(*RR_MX).Mx = txt[0]
        }
	goto st2
tr97:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 8 "types.rl"
	{
            r.(*RR_NS).Hdr = *hdr
            r.(*RR_NS).Ns = txt[0]
        }
	goto st2
tr99:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
// line 16 "types.rl"
	{
            r.(*RR_SOA).Hdr = *hdr
            r.(*RR_SOA).Ns = txt[0]
            r.(*RR_SOA).Mbox = txt[1]
            r.(*RR_SOA).Serial = uint32(num[0])
            r.(*RR_SOA).Refresh = uint32(num[1])
            r.(*RR_SOA).Retry = uint32(num[2])
            r.(*RR_SOA).Expire = uint32(num[3])
            r.(*RR_SOA).Minttl = uint32(num[4])
        }
	goto st2
st2:
	p++
	if p == pe { goto _test_eof2 }
	fallthrough
case 2:
// line 126 "zparse.go"
	switch data[p] {
		case 9: goto st2
		case 32: goto st2
		case 65: goto tr4
		case 67: goto tr5
		case 72: goto tr6
		case 73: goto tr7
		case 77: goto tr8
		case 78: goto tr9
		case 83: goto tr10
		case 97: goto tr4
		case 99: goto tr5
		case 104: goto tr6
		case 105: goto tr7
		case 109: goto tr8
		case 110: goto tr9
		case 115: goto tr10
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr3 }
	goto st0
tr3:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st3
st3:
	p++
	if p == pe { goto _test_eof3 }
	fallthrough
case 3:
// line 158 "zparse.go"
	switch data[p] {
		case 9: goto tr11
		case 32: goto tr11
	}
	if 48 <= data[p] && data[p] <= 57 { goto st3 }
	goto st0
tr11:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st4
st4:
	p++
	if p == pe { goto _test_eof4 }
	fallthrough
case 4:
// line 174 "zparse.go"
	switch data[p] {
		case 9: goto st4
		case 32: goto st4
		case 65: goto tr14
		case 67: goto tr15
		case 72: goto tr16
		case 73: goto tr17
		case 77: goto tr18
		case 78: goto tr19
		case 83: goto tr20
		case 97: goto tr14
		case 99: goto tr15
		case 104: goto tr16
		case 105: goto tr17
		case 109: goto tr18
		case 110: goto tr19
		case 115: goto tr20
	}
	goto st0
tr14:
// line 28 "zparse.rl"
	{ mark = p }
	goto st5
st5:
	p++
	if p == pe { goto _test_eof5 }
	fallthrough
case 5:
// line 203 "zparse.go"
	switch data[p] {
		case 9: goto tr21
		case 32: goto tr21
		case 78: goto st7
		case 110: goto st7
	}
	goto st0
tr21:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st6
st6:
	p++
	if p == pe { goto _test_eof6 }
	fallthrough
case 6:
// line 228 "zparse.go"
	switch data[p] {
		case 9: goto st6
		case 32: goto st6
		case 46: goto tr24
		case 92: goto tr24
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr24 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr24 }
	} else {
		goto tr24
	}
	goto st0
tr24:
// line 28 "zparse.rl"
	{ mark = p }
	goto st59
st59:
	p++
	if p == pe { goto _test_eof59 }
	fallthrough
case 59:
// line 252 "zparse.go"
	switch data[p] {
		case 9: goto tr91
		case 32: goto tr91
		case 46: goto st59
		case 92: goto st59
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st59 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st59 }
	} else {
		goto st59
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
		case 9: goto tr26
		case 32: goto tr26
	}
	goto st0
tr87:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st9
tr26:
// line 33 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st9
st9:
	p++
	if p == pe { goto _test_eof9 }
	fallthrough
case 9:
// line 300 "zparse.go"
	switch data[p] {
		case 9: goto st9
		case 32: goto st9
		case 65: goto tr28
		case 67: goto tr29
		case 77: goto tr18
		case 78: goto tr30
		case 83: goto tr20
		case 97: goto tr28
		case 99: goto tr29
		case 109: goto tr18
		case 110: goto tr30
		case 115: goto tr20
	}
	goto st0
tr28:
// line 28 "zparse.rl"
	{ mark = p }
	goto st10
st10:
	p++
	if p == pe { goto _test_eof10 }
	fallthrough
case 10:
// line 325 "zparse.go"
	switch data[p] {
		case 9: goto tr21
		case 32: goto tr21
	}
	goto st0
tr29:
// line 28 "zparse.rl"
	{ mark = p }
	goto st11
st11:
	p++
	if p == pe { goto _test_eof11 }
	fallthrough
case 11:
// line 340 "zparse.go"
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
		case 9: goto tr35
		case 32: goto tr35
	}
	goto st0
tr35:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st16
st16:
	p++
	if p == pe { goto _test_eof16 }
	fallthrough
case 16:
// line 403 "zparse.go"
	switch data[p] {
		case 9: goto st16
		case 32: goto st16
		case 46: goto tr37
		case 92: goto tr37
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr37 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr37 }
	} else {
		goto tr37
	}
	goto st0
tr37:
// line 28 "zparse.rl"
	{ mark = p }
	goto st60
st60:
	p++
	if p == pe { goto _test_eof60 }
	fallthrough
case 60:
// line 427 "zparse.go"
	switch data[p] {
		case 9: goto tr93
		case 32: goto tr93
		case 46: goto st60
		case 92: goto st60
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st60 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st60 }
	} else {
		goto st60
	}
	goto st0
tr8:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st17
tr18:
// line 28 "zparse.rl"
	{ mark = p }
	goto st17
st17:
	p++
	if p == pe { goto _test_eof17 }
	fallthrough
case 17:
// line 457 "zparse.go"
	switch data[p] {
		case 88: goto st18
		case 120: goto st18
	}
	goto st0
st18:
	p++
	if p == pe { goto _test_eof18 }
	fallthrough
case 18:
	switch data[p] {
		case 9: goto tr39
		case 32: goto tr39
	}
	goto st0
tr39:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st19
st19:
	p++
	if p == pe { goto _test_eof19 }
	fallthrough
case 19:
// line 490 "zparse.go"
	switch data[p] {
		case 9: goto st19
		case 32: goto st19
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr41 }
	goto st0
tr41:
// line 28 "zparse.rl"
	{ mark = p }
	goto st20
st20:
	p++
	if p == pe { goto _test_eof20 }
	fallthrough
case 20:
// line 506 "zparse.go"
	switch data[p] {
		case 9: goto tr42
		case 32: goto tr42
	}
	if 48 <= data[p] && data[p] <= 57 { goto st20 }
	goto st0
tr42:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st21
st21:
	p++
	if p == pe { goto _test_eof21 }
	fallthrough
case 21:
// line 522 "zparse.go"
	switch data[p] {
		case 9: goto st21
		case 32: goto st21
		case 46: goto tr45
		case 92: goto tr45
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr45 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr45 }
	} else {
		goto tr45
	}
	goto st0
tr45:
// line 28 "zparse.rl"
	{ mark = p }
	goto st61
st61:
	p++
	if p == pe { goto _test_eof61 }
	fallthrough
case 61:
// line 546 "zparse.go"
	switch data[p] {
		case 9: goto tr95
		case 32: goto tr95
		case 46: goto st61
		case 92: goto st61
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st61 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st61 }
	} else {
		goto st61
	}
	goto st0
tr30:
// line 28 "zparse.rl"
	{ mark = p }
	goto st22
st22:
	p++
	if p == pe { goto _test_eof22 }
	fallthrough
case 22:
// line 570 "zparse.go"
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
		case 9: goto tr47
		case 32: goto tr47
	}
	goto st0
tr47:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st24
st24:
	p++
	if p == pe { goto _test_eof24 }
	fallthrough
case 24:
// line 603 "zparse.go"
	switch data[p] {
		case 9: goto st24
		case 32: goto st24
		case 46: goto tr49
		case 92: goto tr49
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr49 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr49 }
	} else {
		goto tr49
	}
	goto st0
tr49:
// line 28 "zparse.rl"
	{ mark = p }
	goto st62
st62:
	p++
	if p == pe { goto _test_eof62 }
	fallthrough
case 62:
// line 627 "zparse.go"
	switch data[p] {
		case 9: goto tr97
		case 32: goto tr97
		case 46: goto st62
		case 92: goto st62
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st62 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st62 }
	} else {
		goto st62
	}
	goto st0
tr10:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st25
tr20:
// line 28 "zparse.rl"
	{ mark = p }
	goto st25
st25:
	p++
	if p == pe { goto _test_eof25 }
	fallthrough
case 25:
// line 657 "zparse.go"
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
	switch data[p] {
		case 9: goto tr52
		case 32: goto tr52
	}
	goto st0
tr52:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st28
st28:
	p++
	if p == pe { goto _test_eof28 }
	fallthrough
case 28:
// line 700 "zparse.go"
	switch data[p] {
		case 9: goto st28
		case 32: goto st28
		case 46: goto tr54
		case 92: goto tr54
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr54 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr54 }
	} else {
		goto tr54
	}
	goto st0
tr54:
// line 28 "zparse.rl"
	{ mark = p }
	goto st29
st29:
	p++
	if p == pe { goto _test_eof29 }
	fallthrough
case 29:
// line 724 "zparse.go"
	switch data[p] {
		case 9: goto tr55
		case 32: goto tr55
		case 46: goto st29
		case 92: goto st29
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st29 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st29 }
	} else {
		goto st29
	}
	goto st0
tr55:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
	goto st30
st30:
	p++
	if p == pe { goto _test_eof30 }
	fallthrough
case 30:
// line 748 "zparse.go"
	switch data[p] {
		case 9: goto st30
		case 32: goto st30
		case 46: goto tr58
		case 92: goto tr58
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr58 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr58 }
	} else {
		goto tr58
	}
	goto st0
tr58:
// line 28 "zparse.rl"
	{ mark = p }
	goto st31
st31:
	p++
	if p == pe { goto _test_eof31 }
	fallthrough
case 31:
// line 772 "zparse.go"
	switch data[p] {
		case 9: goto tr59
		case 32: goto tr59
		case 46: goto st31
		case 92: goto st31
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st31 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st31 }
	} else {
		goto st31
	}
	goto st0
tr59:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
	goto st32
st32:
	p++
	if p == pe { goto _test_eof32 }
	fallthrough
case 32:
// line 796 "zparse.go"
	switch data[p] {
		case 9: goto st32
		case 32: goto st32
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr62 }
	goto st0
tr62:
// line 28 "zparse.rl"
	{ mark = p }
	goto st33
st33:
	p++
	if p == pe { goto _test_eof33 }
	fallthrough
case 33:
// line 812 "zparse.go"
	switch data[p] {
		case 9: goto tr63
		case 32: goto tr63
	}
	if 48 <= data[p] && data[p] <= 57 { goto st33 }
	goto st0
tr63:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st34
st34:
	p++
	if p == pe { goto _test_eof34 }
	fallthrough
case 34:
// line 828 "zparse.go"
	switch data[p] {
		case 9: goto st34
		case 32: goto st34
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr66 }
	goto st0
tr66:
// line 28 "zparse.rl"
	{ mark = p }
	goto st35
st35:
	p++
	if p == pe { goto _test_eof35 }
	fallthrough
case 35:
// line 844 "zparse.go"
	switch data[p] {
		case 9: goto tr67
		case 32: goto tr67
	}
	if 48 <= data[p] && data[p] <= 57 { goto st35 }
	goto st0
tr67:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st36
st36:
	p++
	if p == pe { goto _test_eof36 }
	fallthrough
case 36:
// line 860 "zparse.go"
	switch data[p] {
		case 9: goto st36
		case 32: goto st36
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr70 }
	goto st0
tr70:
// line 28 "zparse.rl"
	{ mark = p }
	goto st37
st37:
	p++
	if p == pe { goto _test_eof37 }
	fallthrough
case 37:
// line 876 "zparse.go"
	switch data[p] {
		case 9: goto tr71
		case 32: goto tr71
	}
	if 48 <= data[p] && data[p] <= 57 { goto st37 }
	goto st0
tr71:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st38
st38:
	p++
	if p == pe { goto _test_eof38 }
	fallthrough
case 38:
// line 892 "zparse.go"
	switch data[p] {
		case 9: goto st38
		case 32: goto st38
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr74 }
	goto st0
tr74:
// line 28 "zparse.rl"
	{ mark = p }
	goto st39
st39:
	p++
	if p == pe { goto _test_eof39 }
	fallthrough
case 39:
// line 908 "zparse.go"
	switch data[p] {
		case 9: goto tr75
		case 32: goto tr75
	}
	if 48 <= data[p] && data[p] <= 57 { goto st39 }
	goto st0
tr75:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st40
st40:
	p++
	if p == pe { goto _test_eof40 }
	fallthrough
case 40:
// line 924 "zparse.go"
	switch data[p] {
		case 9: goto st40
		case 32: goto st40
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr78 }
	goto st0
tr78:
// line 28 "zparse.rl"
	{ mark = p }
	goto st63
st63:
	p++
	if p == pe { goto _test_eof63 }
	fallthrough
case 63:
// line 940 "zparse.go"
	switch data[p] {
		case 9: goto tr99
		case 32: goto tr99
		case 46: goto tr100
		case 92: goto tr100
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st63 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr100 }
	} else {
		goto tr100
	}
	goto st0
tr100:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
// line 16 "types.rl"
	{
            r.(*RR_SOA).Hdr = *hdr
            r.(*RR_SOA).Ns = txt[0]
            r.(*RR_SOA).Mbox = txt[1]
            r.(*RR_SOA).Serial = uint32(num[0])
            r.(*RR_SOA).Refresh = uint32(num[1])
            r.(*RR_SOA).Retry = uint32(num[2])
            r.(*RR_SOA).Expire = uint32(num[3])
            r.(*RR_SOA).Minttl = uint32(num[4])
        }
	goto st41
st41:
	p++
	if p == pe { goto _test_eof41 }
	fallthrough
case 41:
// line 975 "zparse.go"
	switch data[p] {
		case 9: goto tr79
		case 32: goto tr79
		case 46: goto st41
		case 92: goto st41
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st41 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st41 }
	} else {
		goto st41
	}
	goto st0
tr15:
// line 28 "zparse.rl"
	{ mark = p }
	goto st42
st42:
	p++
	if p == pe { goto _test_eof42 }
	fallthrough
case 42:
// line 999 "zparse.go"
	switch data[p] {
		case 72: goto st8
		case 78: goto st12
		case 83: goto st8
		case 104: goto st8
		case 110: goto st12
		case 115: goto st8
	}
	goto st0
tr16:
// line 28 "zparse.rl"
	{ mark = p }
	goto st43
st43:
	p++
	if p == pe { goto _test_eof43 }
	fallthrough
case 43:
// line 1018 "zparse.go"
	switch data[p] {
		case 83: goto st8
		case 115: goto st8
	}
	goto st0
tr17:
// line 28 "zparse.rl"
	{ mark = p }
	goto st44
st44:
	p++
	if p == pe { goto _test_eof44 }
	fallthrough
case 44:
// line 1033 "zparse.go"
	switch data[p] {
		case 78: goto st8
		case 110: goto st8
	}
	goto st0
tr19:
// line 28 "zparse.rl"
	{ mark = p }
	goto st45
st45:
	p++
	if p == pe { goto _test_eof45 }
	fallthrough
case 45:
// line 1048 "zparse.go"
	switch data[p] {
		case 79: goto st46
		case 83: goto st23
		case 111: goto st46
		case 115: goto st23
	}
	goto st0
st46:
	p++
	if p == pe { goto _test_eof46 }
	fallthrough
case 46:
	switch data[p] {
		case 78: goto st47
		case 110: goto st47
	}
	goto st0
st47:
	p++
	if p == pe { goto _test_eof47 }
	fallthrough
case 47:
	switch data[p] {
		case 69: goto st8
		case 101: goto st8
	}
	goto st0
tr4:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st48
st48:
	p++
	if p == pe { goto _test_eof48 }
	fallthrough
case 48:
// line 1087 "zparse.go"
	switch data[p] {
		case 9: goto tr21
		case 32: goto tr21
		case 78: goto st49
		case 110: goto st49
	}
	goto st0
st49:
	p++
	if p == pe { goto _test_eof49 }
	fallthrough
case 49:
	switch data[p] {
		case 89: goto st50
		case 121: goto st50
	}
	goto st0
st50:
	p++
	if p == pe { goto _test_eof50 }
	fallthrough
case 50:
	switch data[p] {
		case 9: goto tr84
		case 32: goto tr84
	}
	goto st0
tr84:
// line 33 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st51
st51:
	p++
	if p == pe { goto _test_eof51 }
	fallthrough
case 51:
// line 1124 "zparse.go"
	switch data[p] {
		case 9: goto st51
		case 32: goto st51
		case 65: goto tr28
		case 67: goto tr29
		case 77: goto tr18
		case 78: goto tr30
		case 83: goto tr20
		case 97: goto tr28
		case 99: goto tr29
		case 109: goto tr18
		case 110: goto tr30
		case 115: goto tr20
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr86 }
	goto st0
tr86:
// line 28 "zparse.rl"
	{ mark = p }
	goto st52
st52:
	p++
	if p == pe { goto _test_eof52 }
	fallthrough
case 52:
// line 1150 "zparse.go"
	switch data[p] {
		case 9: goto tr87
		case 32: goto tr87
	}
	if 48 <= data[p] && data[p] <= 57 { goto st52 }
	goto st0
tr5:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st53
st53:
	p++
	if p == pe { goto _test_eof53 }
	fallthrough
case 53:
// line 1168 "zparse.go"
	switch data[p] {
		case 72: goto st50
		case 78: goto st12
		case 83: goto st50
		case 104: goto st50
		case 110: goto st12
		case 115: goto st50
	}
	goto st0
tr6:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st54
st54:
	p++
	if p == pe { goto _test_eof54 }
	fallthrough
case 54:
// line 1189 "zparse.go"
	switch data[p] {
		case 83: goto st50
		case 115: goto st50
	}
	goto st0
tr7:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st55
st55:
	p++
	if p == pe { goto _test_eof55 }
	fallthrough
case 55:
// line 1206 "zparse.go"
	switch data[p] {
		case 78: goto st50
		case 110: goto st50
	}
	goto st0
tr9:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st56
st56:
	p++
	if p == pe { goto _test_eof56 }
	fallthrough
case 56:
// line 1223 "zparse.go"
	switch data[p] {
		case 79: goto st57
		case 83: goto st23
		case 111: goto st57
		case 115: goto st23
	}
	goto st0
st57:
	p++
	if p == pe { goto _test_eof57 }
	fallthrough
case 57:
	switch data[p] {
		case 78: goto st58
		case 110: goto st58
	}
	goto st0
st58:
	p++
	if p == pe { goto _test_eof58 }
	fallthrough
case 58:
	switch data[p] {
		case 69: goto st50
		case 101: goto st50
	}
	goto st0
	}
	_test_eof2: cs = 2; goto _test_eof; 
	_test_eof3: cs = 3; goto _test_eof; 
	_test_eof4: cs = 4; goto _test_eof; 
	_test_eof5: cs = 5; goto _test_eof; 
	_test_eof6: cs = 6; goto _test_eof; 
	_test_eof59: cs = 59; goto _test_eof; 
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
	_test_eof60: cs = 60; goto _test_eof; 
	_test_eof17: cs = 17; goto _test_eof; 
	_test_eof18: cs = 18; goto _test_eof; 
	_test_eof19: cs = 19; goto _test_eof; 
	_test_eof20: cs = 20; goto _test_eof; 
	_test_eof21: cs = 21; goto _test_eof; 
	_test_eof61: cs = 61; goto _test_eof; 
	_test_eof22: cs = 22; goto _test_eof; 
	_test_eof23: cs = 23; goto _test_eof; 
	_test_eof24: cs = 24; goto _test_eof; 
	_test_eof62: cs = 62; goto _test_eof; 
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
	_test_eof63: cs = 63; goto _test_eof; 
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
	_test_eof58: cs = 58; goto _test_eof; 

	_test_eof: {}
	if p == eof {
	switch cs {
	case 63:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
// line 16 "types.rl"
	{
            r.(*RR_SOA).Hdr = *hdr
            r.(*RR_SOA).Ns = txt[0]
            r.(*RR_SOA).Mbox = txt[1]
            r.(*RR_SOA).Serial = uint32(num[0])
            r.(*RR_SOA).Refresh = uint32(num[1])
            r.(*RR_SOA).Retry = uint32(num[2])
            r.(*RR_SOA).Expire = uint32(num[3])
            r.(*RR_SOA).Minttl = uint32(num[4])
        }
	break
	case 59:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 4 "types.rl"
	{
            r.(*RR_A).Hdr = *hdr
            r.(*RR_A).A = net.ParseIP(data[mark:p])
        }
	break
	case 62:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 8 "types.rl"
	{
            r.(*RR_NS).Hdr = *hdr
            r.(*RR_NS).Ns = txt[0]
        }
	break
	case 60:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 12 "types.rl"
	{
            r.(*RR_CNAME).Hdr = *hdr
            r.(*RR_CNAME).Cname = txt[0]
        }
	break
	case 61:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 26 "types.rl"
	{
            r.(*RR_MX).Hdr = *hdr;
            r.(*RR_MX).Pref = uint16(num[0])
            r.(*RR_MX).Mx = txt[0]
        }
	break
// line 1370 "zparse.go"
	}
	}

	_out: {}
	}

// line 77 "zparse.rl"


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
