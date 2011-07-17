
// line 1 "kparse.rl"
package dns

// Parse private key files

import (
    "os"
    "io"
    "bufio"
    "strings"
)


// line 16 "kparse.go"
var k_start int = 111
var k_first_final int = 111
var k_error int = 0

var k_en_main int = 111


// line 15 "kparse.rl"


// Parse a private key file as defined in XXX.
// A map[string]string is returned with the values. All the keys
// are in lowercase. The algorithm is returned as m[algorithm] = "RSASHA1"
func Kparse(q io.Reader) (m map[string]string, err os.Error) {
        r := bufio.NewReader(q)

        m = make(map[string]string)
        k := ""
        data, err := r.ReadString('\n')
        for err == nil {
            cs, p, pe := 0, 0, len(data)
            mark := 0

        
// line 41 "kparse.go"
	cs = k_start

// line 44 "kparse.go"
	{
	if p == pe { goto _test_eof }
	switch cs {
	case -666: // i am a hack D:
tr13:
// line 33 "kparse.rl"
	{ m[k] = data[mark:p] }
	goto st111
tr28:
// line 34 "kparse.rl"
	{ m[k] = strings.ToUpper(data[mark:p-1]) }
	goto st111
tr40:
// line 33 "kparse.rl"
	{ m[k] = data[mark:p] }
// line 34 "kparse.rl"
	{ m[k] = strings.ToUpper(data[mark:p-1]) }
	goto st111
st111:
	p++
	if p == pe { goto _test_eof111 }
	fallthrough
case 111:
// line 68 "kparse.go"
	switch data[p] {
		case 65: goto tr110
		case 67: goto tr111
		case 69: goto tr112
		case 71: goto tr113
		case 77: goto tr114
		case 80: goto tr115
		case 94: goto st109
		case 97: goto tr110
		case 99: goto tr111
		case 101: goto tr112
		case 103: goto tr113
		case 109: goto tr114
		case 112: goto tr115
	}
	goto st0
st0:
cs = 0;
	goto _out;
tr110:
// line 31 "kparse.rl"
	{ mark = p }
	goto st1
st1:
	p++
	if p == pe { goto _test_eof1 }
	fallthrough
case 1:
// line 97 "kparse.go"
	switch data[p] {
		case 67: goto st2
		case 76: goto st37
		case 99: goto st2
		case 108: goto st37
	}
	goto st0
st2:
	p++
	if p == pe { goto _test_eof2 }
	fallthrough
case 2:
	switch data[p] {
		case 84: goto st3
		case 116: goto st3
	}
	goto st0
st3:
	p++
	if p == pe { goto _test_eof3 }
	fallthrough
case 3:
	switch data[p] {
		case 73: goto st4
		case 105: goto st4
	}
	goto st0
st4:
	p++
	if p == pe { goto _test_eof4 }
	fallthrough
case 4:
	switch data[p] {
		case 86: goto st5
		case 118: goto st5
	}
	goto st0
st5:
	p++
	if p == pe { goto _test_eof5 }
	fallthrough
case 5:
	switch data[p] {
		case 65: goto st6
		case 97: goto st6
	}
	goto st0
st6:
	p++
	if p == pe { goto _test_eof6 }
	fallthrough
case 6:
	switch data[p] {
		case 84: goto st7
		case 116: goto st7
	}
	goto st0
st7:
	p++
	if p == pe { goto _test_eof7 }
	fallthrough
case 7:
	switch data[p] {
		case 69: goto st8
		case 101: goto st8
	}
	goto st0
st8:
	p++
	if p == pe { goto _test_eof8 }
	fallthrough
case 8:
	if data[p] == 58 { goto tr9 }
	goto st0
tr9:
// line 32 "kparse.rl"
	{ k = strings.ToLower(data[mark:p]) }
	goto st9
st9:
	p++
	if p == pe { goto _test_eof9 }
	fallthrough
case 9:
// line 181 "kparse.go"
	if data[p] == 32 { goto st10 }
	goto st0
st10:
	p++
	if p == pe { goto _test_eof10 }
	fallthrough
case 10:
	switch data[p] {
		case 32: goto tr11
		case 43: goto tr11
		case 61: goto tr11
		case 92: goto tr11
	}
	if data[p] < 48 {
		if data[p] > 41 {
			if 46 <= data[p] && data[p] <= 47 { goto tr11 }
		} else if data[p] >= 40 {
			goto tr11
		}
	} else if data[p] > 57 {
		if data[p] > 90 {
			if 97 <= data[p] && data[p] <= 122 { goto tr11 }
		} else if data[p] >= 65 {
			goto tr11
		}
	} else {
		goto tr12
	}
	goto st0
tr11:
// line 31 "kparse.rl"
	{ mark = p }
	goto st11
st11:
	p++
	if p == pe { goto _test_eof11 }
	fallthrough
case 11:
// line 220 "kparse.go"
	switch data[p] {
		case 10: goto tr13
		case 32: goto st11
		case 43: goto st11
		case 61: goto st11
		case 92: goto st11
	}
	if data[p] < 46 {
		if 40 <= data[p] && data[p] <= 41 { goto st11 }
	} else if data[p] > 57 {
		if data[p] > 90 {
			if 97 <= data[p] && data[p] <= 122 { goto st11 }
		} else if data[p] >= 65 {
			goto st11
		}
	} else {
		goto st11
	}
	goto st0
tr12:
// line 31 "kparse.rl"
	{ mark = p }
	goto st12
st12:
	p++
	if p == pe { goto _test_eof12 }
	fallthrough
case 12:
// line 249 "kparse.go"
	switch data[p] {
		case 9: goto st13
		case 10: goto tr13
		case 32: goto st25
		case 43: goto st11
		case 61: goto st11
		case 92: goto st11
	}
	if data[p] < 48 {
		if data[p] > 41 {
			if 46 <= data[p] && data[p] <= 47 { goto st11 }
		} else if data[p] >= 40 {
			goto st11
		}
	} else if data[p] > 57 {
		if data[p] > 90 {
			if 97 <= data[p] && data[p] <= 122 { goto st11 }
		} else if data[p] >= 65 {
			goto st11
		}
	} else {
		goto st12
	}
	goto st0
st13:
	p++
	if p == pe { goto _test_eof13 }
	fallthrough
case 13:
	switch data[p] {
		case 9: goto st13
		case 32: goto st13
		case 40: goto st14
	}
	goto st0
st14:
	p++
	if p == pe { goto _test_eof14 }
	fallthrough
case 14:
	switch data[p] {
		case 82: goto tr19
		case 114: goto tr19
	}
	goto st0
tr19:
// line 31 "kparse.rl"
	{ mark = p }
	goto st15
st15:
	p++
	if p == pe { goto _test_eof15 }
	fallthrough
case 15:
// line 304 "kparse.go"
	switch data[p] {
		case 83: goto st16
		case 115: goto st16
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
		case 83: goto st18
		case 115: goto st18
	}
	goto st0
st18:
	p++
	if p == pe { goto _test_eof18 }
	fallthrough
case 18:
	switch data[p] {
		case 72: goto st19
		case 104: goto st19
	}
	goto st0
st19:
	p++
	if p == pe { goto _test_eof19 }
	fallthrough
case 19:
	switch data[p] {
		case 65: goto st20
		case 97: goto st20
	}
	goto st0
st20:
	p++
	if p == pe { goto _test_eof20 }
	fallthrough
case 20:
	switch data[p] {
		case 49: goto st21
		case 50: goto st23
	}
	goto st0
st21:
	p++
	if p == pe { goto _test_eof21 }
	fallthrough
case 21:
	if data[p] == 41 { goto st22 }
	goto st0
st22:
	p++
	if p == pe { goto _test_eof22 }
	fallthrough
case 22:
	if data[p] == 10 { goto tr28 }
	goto st0
st23:
	p++
	if p == pe { goto _test_eof23 }
	fallthrough
case 23:
	if data[p] == 53 { goto st24 }
	goto st0
st24:
	p++
	if p == pe { goto _test_eof24 }
	fallthrough
case 24:
	if data[p] == 54 { goto st21 }
	goto st0
st25:
	p++
	if p == pe { goto _test_eof25 }
	fallthrough
case 25:
	switch data[p] {
		case 9: goto st13
		case 10: goto tr13
		case 32: goto st25
		case 40: goto st26
		case 41: goto st11
		case 43: goto st11
		case 61: goto st11
		case 92: goto st11
	}
	if data[p] < 65 {
		if 46 <= data[p] && data[p] <= 57 { goto st11 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st11 }
	} else {
		goto st11
	}
	goto st0
st26:
	p++
	if p == pe { goto _test_eof26 }
	fallthrough
case 26:
	switch data[p] {
		case 10: goto tr13
		case 32: goto st11
		case 43: goto st11
		case 61: goto st11
		case 82: goto tr31
		case 92: goto st11
		case 114: goto tr31
	}
	if data[p] < 46 {
		if 40 <= data[p] && data[p] <= 41 { goto st11 }
	} else if data[p] > 57 {
		if data[p] > 90 {
			if 97 <= data[p] && data[p] <= 122 { goto st11 }
		} else if data[p] >= 65 {
			goto st11
		}
	} else {
		goto st11
	}
	goto st0
tr31:
// line 31 "kparse.rl"
	{ mark = p }
	goto st27
st27:
	p++
	if p == pe { goto _test_eof27 }
	fallthrough
case 27:
// line 446 "kparse.go"
	switch data[p] {
		case 10: goto tr13
		case 32: goto st11
		case 43: goto st11
		case 61: goto st11
		case 83: goto st28
		case 92: goto st11
		case 115: goto st28
	}
	if data[p] < 46 {
		if 40 <= data[p] && data[p] <= 41 { goto st11 }
	} else if data[p] > 57 {
		if data[p] > 90 {
			if 97 <= data[p] && data[p] <= 122 { goto st11 }
		} else if data[p] >= 65 {
			goto st11
		}
	} else {
		goto st11
	}
	goto st0
st28:
	p++
	if p == pe { goto _test_eof28 }
	fallthrough
case 28:
	switch data[p] {
		case 10: goto tr13
		case 32: goto st11
		case 43: goto st11
		case 61: goto st11
		case 65: goto st29
		case 92: goto st11
		case 97: goto st29
	}
	if data[p] < 46 {
		if 40 <= data[p] && data[p] <= 41 { goto st11 }
	} else if data[p] > 57 {
		if data[p] > 90 {
			if 98 <= data[p] && data[p] <= 122 { goto st11 }
		} else if data[p] >= 66 {
			goto st11
		}
	} else {
		goto st11
	}
	goto st0
st29:
	p++
	if p == pe { goto _test_eof29 }
	fallthrough
case 29:
	switch data[p] {
		case 10: goto tr13
		case 32: goto st11
		case 43: goto st11
		case 61: goto st11
		case 83: goto st30
		case 92: goto st11
		case 115: goto st30
	}
	if data[p] < 46 {
		if 40 <= data[p] && data[p] <= 41 { goto st11 }
	} else if data[p] > 57 {
		if data[p] > 90 {
			if 97 <= data[p] && data[p] <= 122 { goto st11 }
		} else if data[p] >= 65 {
			goto st11
		}
	} else {
		goto st11
	}
	goto st0
st30:
	p++
	if p == pe { goto _test_eof30 }
	fallthrough
case 30:
	switch data[p] {
		case 10: goto tr13
		case 32: goto st11
		case 43: goto st11
		case 61: goto st11
		case 72: goto st31
		case 92: goto st11
		case 104: goto st31
	}
	if data[p] < 46 {
		if 40 <= data[p] && data[p] <= 41 { goto st11 }
	} else if data[p] > 57 {
		if data[p] > 90 {
			if 97 <= data[p] && data[p] <= 122 { goto st11 }
		} else if data[p] >= 65 {
			goto st11
		}
	} else {
		goto st11
	}
	goto st0
st31:
	p++
	if p == pe { goto _test_eof31 }
	fallthrough
case 31:
	switch data[p] {
		case 10: goto tr13
		case 32: goto st11
		case 43: goto st11
		case 61: goto st11
		case 65: goto st32
		case 92: goto st11
		case 97: goto st32
	}
	if data[p] < 46 {
		if 40 <= data[p] && data[p] <= 41 { goto st11 }
	} else if data[p] > 57 {
		if data[p] > 90 {
			if 98 <= data[p] && data[p] <= 122 { goto st11 }
		} else if data[p] >= 66 {
			goto st11
		}
	} else {
		goto st11
	}
	goto st0
st32:
	p++
	if p == pe { goto _test_eof32 }
	fallthrough
case 32:
	switch data[p] {
		case 10: goto tr13
		case 32: goto st11
		case 43: goto st11
		case 49: goto st33
		case 50: goto st35
		case 61: goto st11
		case 92: goto st11
	}
	if data[p] < 46 {
		if 40 <= data[p] && data[p] <= 41 { goto st11 }
	} else if data[p] > 57 {
		if data[p] > 90 {
			if 97 <= data[p] && data[p] <= 122 { goto st11 }
		} else if data[p] >= 65 {
			goto st11
		}
	} else {
		goto st11
	}
	goto st0
st33:
	p++
	if p == pe { goto _test_eof33 }
	fallthrough
case 33:
	switch data[p] {
		case 10: goto tr13
		case 32: goto st11
		case 40: goto st11
		case 41: goto st34
		case 43: goto st11
		case 61: goto st11
		case 92: goto st11
	}
	if data[p] < 65 {
		if 46 <= data[p] && data[p] <= 57 { goto st11 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st11 }
	} else {
		goto st11
	}
	goto st0
st34:
	p++
	if p == pe { goto _test_eof34 }
	fallthrough
case 34:
	switch data[p] {
		case 10: goto tr40
		case 32: goto st11
		case 43: goto st11
		case 61: goto st11
		case 92: goto st11
	}
	if data[p] < 46 {
		if 40 <= data[p] && data[p] <= 41 { goto st11 }
	} else if data[p] > 57 {
		if data[p] > 90 {
			if 97 <= data[p] && data[p] <= 122 { goto st11 }
		} else if data[p] >= 65 {
			goto st11
		}
	} else {
		goto st11
	}
	goto st0
st35:
	p++
	if p == pe { goto _test_eof35 }
	fallthrough
case 35:
	switch data[p] {
		case 10: goto tr13
		case 32: goto st11
		case 43: goto st11
		case 53: goto st36
		case 61: goto st11
		case 92: goto st11
	}
	if data[p] < 46 {
		if 40 <= data[p] && data[p] <= 41 { goto st11 }
	} else if data[p] > 57 {
		if data[p] > 90 {
			if 97 <= data[p] && data[p] <= 122 { goto st11 }
		} else if data[p] >= 65 {
			goto st11
		}
	} else {
		goto st11
	}
	goto st0
st36:
	p++
	if p == pe { goto _test_eof36 }
	fallthrough
case 36:
	switch data[p] {
		case 10: goto tr13
		case 32: goto st11
		case 43: goto st11
		case 54: goto st33
		case 61: goto st11
		case 92: goto st11
	}
	if data[p] < 46 {
		if 40 <= data[p] && data[p] <= 41 { goto st11 }
	} else if data[p] > 57 {
		if data[p] > 90 {
			if 97 <= data[p] && data[p] <= 122 { goto st11 }
		} else if data[p] >= 65 {
			goto st11
		}
	} else {
		goto st11
	}
	goto st0
st37:
	p++
	if p == pe { goto _test_eof37 }
	fallthrough
case 37:
	switch data[p] {
		case 71: goto st38
		case 103: goto st38
	}
	goto st0
st38:
	p++
	if p == pe { goto _test_eof38 }
	fallthrough
case 38:
	switch data[p] {
		case 79: goto st39
		case 111: goto st39
	}
	goto st0
st39:
	p++
	if p == pe { goto _test_eof39 }
	fallthrough
case 39:
	switch data[p] {
		case 82: goto st40
		case 114: goto st40
	}
	goto st0
st40:
	p++
	if p == pe { goto _test_eof40 }
	fallthrough
case 40:
	switch data[p] {
		case 73: goto st41
		case 105: goto st41
	}
	goto st0
st41:
	p++
	if p == pe { goto _test_eof41 }
	fallthrough
case 41:
	switch data[p] {
		case 84: goto st42
		case 116: goto st42
	}
	goto st0
st42:
	p++
	if p == pe { goto _test_eof42 }
	fallthrough
case 42:
	switch data[p] {
		case 72: goto st43
		case 104: goto st43
	}
	goto st0
st43:
	p++
	if p == pe { goto _test_eof43 }
	fallthrough
case 43:
	switch data[p] {
		case 77: goto st8
		case 109: goto st8
	}
	goto st0
tr111:
// line 31 "kparse.rl"
	{ mark = p }
	goto st44
st44:
	p++
	if p == pe { goto _test_eof44 }
	fallthrough
case 44:
// line 773 "kparse.go"
	switch data[p] {
		case 79: goto st45
		case 82: goto st54
		case 111: goto st45
		case 114: goto st54
	}
	goto st0
st45:
	p++
	if p == pe { goto _test_eof45 }
	fallthrough
case 45:
	switch data[p] {
		case 69: goto st46
		case 101: goto st46
	}
	goto st0
st46:
	p++
	if p == pe { goto _test_eof46 }
	fallthrough
case 46:
	switch data[p] {
		case 70: goto st47
		case 102: goto st47
	}
	goto st0
st47:
	p++
	if p == pe { goto _test_eof47 }
	fallthrough
case 47:
	switch data[p] {
		case 70: goto st48
		case 102: goto st48
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
		case 67: goto st50
		case 99: goto st50
	}
	goto st0
st50:
	p++
	if p == pe { goto _test_eof50 }
	fallthrough
case 50:
	switch data[p] {
		case 73: goto st51
		case 105: goto st51
	}
	goto st0
st51:
	p++
	if p == pe { goto _test_eof51 }
	fallthrough
case 51:
	switch data[p] {
		case 69: goto st52
		case 101: goto st52
	}
	goto st0
st52:
	p++
	if p == pe { goto _test_eof52 }
	fallthrough
case 52:
	switch data[p] {
		case 78: goto st53
		case 110: goto st53
	}
	goto st0
st53:
	p++
	if p == pe { goto _test_eof53 }
	fallthrough
case 53:
	switch data[p] {
		case 84: goto st8
		case 116: goto st8
	}
	goto st0
st54:
	p++
	if p == pe { goto _test_eof54 }
	fallthrough
case 54:
	switch data[p] {
		case 69: goto st55
		case 101: goto st55
	}
	goto st0
st55:
	p++
	if p == pe { goto _test_eof55 }
	fallthrough
case 55:
	switch data[p] {
		case 65: goto st56
		case 97: goto st56
	}
	goto st0
st56:
	p++
	if p == pe { goto _test_eof56 }
	fallthrough
case 56:
	switch data[p] {
		case 84: goto st57
		case 116: goto st57
	}
	goto st0
st57:
	p++
	if p == pe { goto _test_eof57 }
	fallthrough
case 57:
	switch data[p] {
		case 69: goto st58
		case 101: goto st58
	}
	goto st0
st58:
	p++
	if p == pe { goto _test_eof58 }
	fallthrough
case 58:
	switch data[p] {
		case 68: goto st8
		case 100: goto st8
	}
	goto st0
tr112:
// line 31 "kparse.rl"
	{ mark = p }
	goto st59
st59:
	p++
	if p == pe { goto _test_eof59 }
	fallthrough
case 59:
// line 930 "kparse.go"
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
		case 80: goto st61
		case 112: goto st61
	}
	goto st0
st61:
	p++
	if p == pe { goto _test_eof61 }
	fallthrough
case 61:
	switch data[p] {
		case 79: goto st62
		case 111: goto st62
	}
	goto st0
st62:
	p++
	if p == pe { goto _test_eof62 }
	fallthrough
case 62:
	switch data[p] {
		case 78: goto st63
		case 110: goto st63
	}
	goto st0
st63:
	p++
	if p == pe { goto _test_eof63 }
	fallthrough
case 63:
	switch data[p] {
		case 69: goto st64
		case 101: goto st64
	}
	goto st0
st64:
	p++
	if p == pe { goto _test_eof64 }
	fallthrough
case 64:
	switch data[p] {
		case 78: goto st65
		case 110: goto st65
	}
	goto st0
st65:
	p++
	if p == pe { goto _test_eof65 }
	fallthrough
case 65:
	switch data[p] {
		case 84: goto st66
		case 116: goto st66
	}
	goto st0
st66:
	p++
	if p == pe { goto _test_eof66 }
	fallthrough
case 66:
	if 49 <= data[p] && data[p] <= 50 { goto st8 }
	goto st0
tr113:
// line 31 "kparse.rl"
	{ mark = p }
	goto st67
st67:
	p++
	if p == pe { goto _test_eof67 }
	fallthrough
case 67:
// line 1012 "kparse.go"
	switch data[p] {
		case 79: goto st68
		case 111: goto st68
	}
	goto st0
st68:
	p++
	if p == pe { goto _test_eof68 }
	fallthrough
case 68:
	switch data[p] {
		case 83: goto st69
		case 115: goto st69
	}
	goto st0
st69:
	p++
	if p == pe { goto _test_eof69 }
	fallthrough
case 69:
	switch data[p] {
		case 84: goto st70
		case 116: goto st70
	}
	goto st0
st70:
	p++
	if p == pe { goto _test_eof70 }
	fallthrough
case 70:
	switch data[p] {
		case 65: goto st71
		case 97: goto st71
	}
	goto st0
st71:
	p++
	if p == pe { goto _test_eof71 }
	fallthrough
case 71:
	switch data[p] {
		case 83: goto st72
		case 115: goto st72
	}
	goto st0
st72:
	p++
	if p == pe { goto _test_eof72 }
	fallthrough
case 72:
	switch data[p] {
		case 78: goto st73
		case 110: goto st73
	}
	goto st0
st73:
	p++
	if p == pe { goto _test_eof73 }
	fallthrough
case 73:
	if data[p] == 49 { goto st8 }
	goto st0
tr114:
// line 31 "kparse.rl"
	{ mark = p }
	goto st74
st74:
	p++
	if p == pe { goto _test_eof74 }
	fallthrough
case 74:
// line 1084 "kparse.go"
	switch data[p] {
		case 79: goto st75
		case 111: goto st75
	}
	goto st0
st75:
	p++
	if p == pe { goto _test_eof75 }
	fallthrough
case 75:
	switch data[p] {
		case 68: goto st76
		case 100: goto st76
	}
	goto st0
st76:
	p++
	if p == pe { goto _test_eof76 }
	fallthrough
case 76:
	switch data[p] {
		case 85: goto st77
		case 117: goto st77
	}
	goto st0
st77:
	p++
	if p == pe { goto _test_eof77 }
	fallthrough
case 77:
	switch data[p] {
		case 76: goto st78
		case 108: goto st78
	}
	goto st0
st78:
	p++
	if p == pe { goto _test_eof78 }
	fallthrough
case 78:
	switch data[p] {
		case 85: goto st79
		case 117: goto st79
	}
	goto st0
st79:
	p++
	if p == pe { goto _test_eof79 }
	fallthrough
case 79:
	switch data[p] {
		case 83: goto st8
		case 115: goto st8
	}
	goto st0
tr115:
// line 31 "kparse.rl"
	{ mark = p }
	goto st80
st80:
	p++
	if p == pe { goto _test_eof80 }
	fallthrough
case 80:
// line 1149 "kparse.go"
	switch data[p] {
		case 82: goto st81
		case 85: goto st103
		case 114: goto st81
		case 117: goto st103
	}
	goto st0
st81:
	p++
	if p == pe { goto _test_eof81 }
	fallthrough
case 81:
	switch data[p] {
		case 73: goto st82
		case 105: goto st82
	}
	goto st0
st82:
	p++
	if p == pe { goto _test_eof82 }
	fallthrough
case 82:
	switch data[p] {
		case 77: goto st83
		case 86: goto st84
		case 109: goto st83
		case 118: goto st84
	}
	goto st0
st83:
	p++
	if p == pe { goto _test_eof83 }
	fallthrough
case 83:
	switch data[p] {
		case 69: goto st66
		case 101: goto st66
	}
	goto st0
st84:
	p++
	if p == pe { goto _test_eof84 }
	fallthrough
case 84:
	switch data[p] {
		case 65: goto st85
		case 97: goto st85
	}
	goto st0
st85:
	p++
	if p == pe { goto _test_eof85 }
	fallthrough
case 85:
	switch data[p] {
		case 84: goto st86
		case 116: goto st86
	}
	goto st0
st86:
	p++
	if p == pe { goto _test_eof86 }
	fallthrough
case 86:
	switch data[p] {
		case 69: goto st87
		case 101: goto st87
	}
	goto st0
st87:
	p++
	if p == pe { goto _test_eof87 }
	fallthrough
case 87:
	switch data[p] {
		case 45: goto st88
		case 69: goto st97
		case 75: goto st101
		case 101: goto st97
		case 107: goto st101
	}
	goto st0
st88:
	p++
	if p == pe { goto _test_eof88 }
	fallthrough
case 88:
	switch data[p] {
		case 75: goto st89
		case 107: goto st89
	}
	goto st0
st89:
	p++
	if p == pe { goto _test_eof89 }
	fallthrough
case 89:
	switch data[p] {
		case 69: goto st90
		case 101: goto st90
	}
	goto st0
st90:
	p++
	if p == pe { goto _test_eof90 }
	fallthrough
case 90:
	switch data[p] {
		case 89: goto st91
		case 121: goto st91
	}
	goto st0
st91:
	p++
	if p == pe { goto _test_eof91 }
	fallthrough
case 91:
	if data[p] == 45 { goto st92 }
	goto st0
st92:
	p++
	if p == pe { goto _test_eof92 }
	fallthrough
case 92:
	switch data[p] {
		case 70: goto st93
		case 102: goto st93
	}
	goto st0
st93:
	p++
	if p == pe { goto _test_eof93 }
	fallthrough
case 93:
	switch data[p] {
		case 79: goto st94
		case 111: goto st94
	}
	goto st0
st94:
	p++
	if p == pe { goto _test_eof94 }
	fallthrough
case 94:
	switch data[p] {
		case 82: goto st95
		case 114: goto st95
	}
	goto st0
st95:
	p++
	if p == pe { goto _test_eof95 }
	fallthrough
case 95:
	switch data[p] {
		case 77: goto st96
		case 109: goto st96
	}
	goto st0
st96:
	p++
	if p == pe { goto _test_eof96 }
	fallthrough
case 96:
	switch data[p] {
		case 65: goto st53
		case 97: goto st53
	}
	goto st0
st97:
	p++
	if p == pe { goto _test_eof97 }
	fallthrough
case 97:
	switch data[p] {
		case 88: goto st98
		case 120: goto st98
	}
	goto st0
st98:
	p++
	if p == pe { goto _test_eof98 }
	fallthrough
case 98:
	switch data[p] {
		case 80: goto st99
		case 112: goto st99
	}
	goto st0
st99:
	p++
	if p == pe { goto _test_eof99 }
	fallthrough
case 99:
	switch data[p] {
		case 79: goto st100
		case 111: goto st100
	}
	goto st0
st100:
	p++
	if p == pe { goto _test_eof100 }
	fallthrough
case 100:
	switch data[p] {
		case 78: goto st51
		case 110: goto st51
	}
	goto st0
st101:
	p++
	if p == pe { goto _test_eof101 }
	fallthrough
case 101:
	switch data[p] {
		case 69: goto st102
		case 101: goto st102
	}
	goto st0
st102:
	p++
	if p == pe { goto _test_eof102 }
	fallthrough
case 102:
	switch data[p] {
		case 89: goto st8
		case 121: goto st8
	}
	goto st0
st103:
	p++
	if p == pe { goto _test_eof103 }
	fallthrough
case 103:
	switch data[p] {
		case 66: goto st104
		case 98: goto st104
	}
	goto st0
st104:
	p++
	if p == pe { goto _test_eof104 }
	fallthrough
case 104:
	switch data[p] {
		case 76: goto st105
		case 108: goto st105
	}
	goto st0
st105:
	p++
	if p == pe { goto _test_eof105 }
	fallthrough
case 105:
	switch data[p] {
		case 73: goto st106
		case 105: goto st106
	}
	goto st0
st106:
	p++
	if p == pe { goto _test_eof106 }
	fallthrough
case 106:
	switch data[p] {
		case 67: goto st107
		case 83: goto st108
		case 99: goto st107
		case 115: goto st108
	}
	goto st0
st107:
	p++
	if p == pe { goto _test_eof107 }
	fallthrough
case 107:
	switch data[p] {
		case 69: goto st97
		case 101: goto st97
	}
	goto st0
st108:
	p++
	if p == pe { goto _test_eof108 }
	fallthrough
case 108:
	switch data[p] {
		case 72: goto st8
		case 104: goto st8
	}
	goto st0
st109:
	p++
	if p == pe { goto _test_eof109 }
	fallthrough
case 109:
	if data[p] == 59 { goto st110 }
	goto st0
st110:
	p++
	if p == pe { goto _test_eof110 }
	fallthrough
case 110:
	if data[p] == 10 { goto st111 }
	goto st0
	}
	_test_eof111: cs = 111; goto _test_eof; 
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
	_test_eof38: cs = 38; goto _test_eof; 
	_test_eof39: cs = 39; goto _test_eof; 
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
	_test_eof102: cs = 102; goto _test_eof; 
	_test_eof103: cs = 103; goto _test_eof; 
	_test_eof104: cs = 104; goto _test_eof; 
	_test_eof105: cs = 105; goto _test_eof; 
	_test_eof106: cs = 106; goto _test_eof; 
	_test_eof107: cs = 107; goto _test_eof; 
	_test_eof108: cs = 108; goto _test_eof; 
	_test_eof109: cs = 109; goto _test_eof; 
	_test_eof110: cs = 110; goto _test_eof; 

	_test_eof: {}
	_out: {}
	}

// line 66 "kparse.rl"

            data, err = r.ReadString('\n')
        }

        /*
        if cs < z_first_final {
                // No clue what I'm doing what so ever
                if p == pe {
                        //return nil, os.ErrorString("unexpected eof")
                        println("err unexp eof")
                        return m, nil
                } else {
                        //return nil, os.ErrorString(fmt.Sprintf("error at position %d", p))
                        println("err ", p, "data:", string(data[p]))
                        return nil, nil
                }
        }
        */
        return m, nil
}
