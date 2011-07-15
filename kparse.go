
// line 1 "kparse.rl"
package dns

// Parse private key files

import (
    "os"
    "strings"
)


// line 14 "kparse.go"
var k_start int = 84
var k_first_final int = 84
var k_error int = 0

var k_en_main int = 84


// line 13 "kparse.rl"


func Kparse(data string) (m map[string]string, err os.Error) {
        cs, p, pe := 0, 0, len(data)
        mark := 0
        k := ""
        m = make(map[string]string)

        
// line 32 "kparse.go"
	cs = k_start

// line 35 "kparse.go"
	{
	if p == pe { goto _test_eof }
	switch cs {
	case -666: // i am a hack D:
tr12:
// line 24 "kparse.rl"
	{ m[k] = data[mark:p] }
	goto st84
st84:
	p++
	if p == pe { goto _test_eof84 }
	fallthrough
case 84:
// line 49 "kparse.go"
	switch data[p] {
		case 65: goto tr80
		case 67: goto tr81
		case 69: goto tr82
		case 71: goto tr83
		case 77: goto tr84
		case 80: goto tr85
		case 97: goto tr80
		case 99: goto tr81
		case 101: goto tr82
		case 103: goto tr83
		case 109: goto tr84
		case 112: goto tr85
	}
	goto st0
st0:
cs = 0;
	goto _out;
tr80:
// line 22 "kparse.rl"
	{ mark = p }
	goto st1
st1:
	p++
	if p == pe { goto _test_eof1 }
	fallthrough
case 1:
// line 77 "kparse.go"
	switch data[p] {
		case 67: goto st2
		case 76: goto st12
		case 99: goto st2
		case 108: goto st12
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
// line 23 "kparse.rl"
	{ k = strings.ToLower(data[mark:p]) }
	goto st9
st9:
	p++
	if p == pe { goto _test_eof9 }
	fallthrough
case 9:
// line 161 "kparse.go"
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
	if data[p] < 46 {
		if 40 <= data[p] && data[p] <= 41 { goto tr11 }
	} else if data[p] > 57 {
		if data[p] > 90 {
			if 97 <= data[p] && data[p] <= 122 { goto tr11 }
		} else if data[p] >= 65 {
			goto tr11
		}
	} else {
		goto tr11
	}
	goto st0
tr11:
// line 22 "kparse.rl"
	{ mark = p }
	goto st11
st11:
	p++
	if p == pe { goto _test_eof11 }
	fallthrough
case 11:
// line 196 "kparse.go"
	switch data[p] {
		case 10: goto tr12
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
st12:
	p++
	if p == pe { goto _test_eof12 }
	fallthrough
case 12:
	switch data[p] {
		case 71: goto st13
		case 103: goto st13
	}
	goto st0
st13:
	p++
	if p == pe { goto _test_eof13 }
	fallthrough
case 13:
	switch data[p] {
		case 79: goto st14
		case 111: goto st14
	}
	goto st0
st14:
	p++
	if p == pe { goto _test_eof14 }
	fallthrough
case 14:
	switch data[p] {
		case 82: goto st15
		case 114: goto st15
	}
	goto st0
st15:
	p++
	if p == pe { goto _test_eof15 }
	fallthrough
case 15:
	switch data[p] {
		case 73: goto st16
		case 105: goto st16
	}
	goto st0
st16:
	p++
	if p == pe { goto _test_eof16 }
	fallthrough
case 16:
	switch data[p] {
		case 84: goto st17
		case 116: goto st17
	}
	goto st0
st17:
	p++
	if p == pe { goto _test_eof17 }
	fallthrough
case 17:
	switch data[p] {
		case 72: goto st18
		case 104: goto st18
	}
	goto st0
st18:
	p++
	if p == pe { goto _test_eof18 }
	fallthrough
case 18:
	switch data[p] {
		case 77: goto st8
		case 109: goto st8
	}
	goto st0
tr81:
// line 22 "kparse.rl"
	{ mark = p }
	goto st19
st19:
	p++
	if p == pe { goto _test_eof19 }
	fallthrough
case 19:
// line 295 "kparse.go"
	switch data[p] {
		case 79: goto st20
		case 82: goto st29
		case 111: goto st20
		case 114: goto st29
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
		case 70: goto st22
		case 102: goto st22
	}
	goto st0
st22:
	p++
	if p == pe { goto _test_eof22 }
	fallthrough
case 22:
	switch data[p] {
		case 70: goto st23
		case 102: goto st23
	}
	goto st0
st23:
	p++
	if p == pe { goto _test_eof23 }
	fallthrough
case 23:
	switch data[p] {
		case 73: goto st24
		case 105: goto st24
	}
	goto st0
st24:
	p++
	if p == pe { goto _test_eof24 }
	fallthrough
case 24:
	switch data[p] {
		case 67: goto st25
		case 99: goto st25
	}
	goto st0
st25:
	p++
	if p == pe { goto _test_eof25 }
	fallthrough
case 25:
	switch data[p] {
		case 73: goto st26
		case 105: goto st26
	}
	goto st0
st26:
	p++
	if p == pe { goto _test_eof26 }
	fallthrough
case 26:
	switch data[p] {
		case 69: goto st27
		case 101: goto st27
	}
	goto st0
st27:
	p++
	if p == pe { goto _test_eof27 }
	fallthrough
case 27:
	switch data[p] {
		case 78: goto st28
		case 110: goto st28
	}
	goto st0
st28:
	p++
	if p == pe { goto _test_eof28 }
	fallthrough
case 28:
	switch data[p] {
		case 84: goto st8
		case 116: goto st8
	}
	goto st0
st29:
	p++
	if p == pe { goto _test_eof29 }
	fallthrough
case 29:
	switch data[p] {
		case 69: goto st30
		case 101: goto st30
	}
	goto st0
st30:
	p++
	if p == pe { goto _test_eof30 }
	fallthrough
case 30:
	switch data[p] {
		case 65: goto st31
		case 97: goto st31
	}
	goto st0
st31:
	p++
	if p == pe { goto _test_eof31 }
	fallthrough
case 31:
	switch data[p] {
		case 84: goto st32
		case 116: goto st32
	}
	goto st0
st32:
	p++
	if p == pe { goto _test_eof32 }
	fallthrough
case 32:
	switch data[p] {
		case 69: goto st33
		case 101: goto st33
	}
	goto st0
st33:
	p++
	if p == pe { goto _test_eof33 }
	fallthrough
case 33:
	switch data[p] {
		case 68: goto st8
		case 100: goto st8
	}
	goto st0
tr82:
// line 22 "kparse.rl"
	{ mark = p }
	goto st34
st34:
	p++
	if p == pe { goto _test_eof34 }
	fallthrough
case 34:
// line 452 "kparse.go"
	switch data[p] {
		case 88: goto st35
		case 120: goto st35
	}
	goto st0
st35:
	p++
	if p == pe { goto _test_eof35 }
	fallthrough
case 35:
	switch data[p] {
		case 80: goto st36
		case 112: goto st36
	}
	goto st0
st36:
	p++
	if p == pe { goto _test_eof36 }
	fallthrough
case 36:
	switch data[p] {
		case 79: goto st37
		case 111: goto st37
	}
	goto st0
st37:
	p++
	if p == pe { goto _test_eof37 }
	fallthrough
case 37:
	switch data[p] {
		case 78: goto st38
		case 110: goto st38
	}
	goto st0
st38:
	p++
	if p == pe { goto _test_eof38 }
	fallthrough
case 38:
	switch data[p] {
		case 69: goto st39
		case 101: goto st39
	}
	goto st0
st39:
	p++
	if p == pe { goto _test_eof39 }
	fallthrough
case 39:
	switch data[p] {
		case 78: goto st40
		case 110: goto st40
	}
	goto st0
st40:
	p++
	if p == pe { goto _test_eof40 }
	fallthrough
case 40:
	switch data[p] {
		case 84: goto st41
		case 116: goto st41
	}
	goto st0
st41:
	p++
	if p == pe { goto _test_eof41 }
	fallthrough
case 41:
	if 49 <= data[p] && data[p] <= 50 { goto st8 }
	goto st0
tr83:
// line 22 "kparse.rl"
	{ mark = p }
	goto st42
st42:
	p++
	if p == pe { goto _test_eof42 }
	fallthrough
case 42:
// line 534 "kparse.go"
	switch data[p] {
		case 79: goto st43
		case 111: goto st43
	}
	goto st0
st43:
	p++
	if p == pe { goto _test_eof43 }
	fallthrough
case 43:
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
		case 84: goto st45
		case 116: goto st45
	}
	goto st0
st45:
	p++
	if p == pe { goto _test_eof45 }
	fallthrough
case 45:
	switch data[p] {
		case 65: goto st46
		case 97: goto st46
	}
	goto st0
st46:
	p++
	if p == pe { goto _test_eof46 }
	fallthrough
case 46:
	switch data[p] {
		case 83: goto st47
		case 115: goto st47
	}
	goto st0
st47:
	p++
	if p == pe { goto _test_eof47 }
	fallthrough
case 47:
	switch data[p] {
		case 78: goto st48
		case 110: goto st48
	}
	goto st0
st48:
	p++
	if p == pe { goto _test_eof48 }
	fallthrough
case 48:
	if data[p] == 49 { goto st8 }
	goto st0
tr84:
// line 22 "kparse.rl"
	{ mark = p }
	goto st49
st49:
	p++
	if p == pe { goto _test_eof49 }
	fallthrough
case 49:
// line 606 "kparse.go"
	switch data[p] {
		case 79: goto st50
		case 111: goto st50
	}
	goto st0
st50:
	p++
	if p == pe { goto _test_eof50 }
	fallthrough
case 50:
	switch data[p] {
		case 68: goto st51
		case 100: goto st51
	}
	goto st0
st51:
	p++
	if p == pe { goto _test_eof51 }
	fallthrough
case 51:
	switch data[p] {
		case 85: goto st52
		case 117: goto st52
	}
	goto st0
st52:
	p++
	if p == pe { goto _test_eof52 }
	fallthrough
case 52:
	switch data[p] {
		case 76: goto st53
		case 108: goto st53
	}
	goto st0
st53:
	p++
	if p == pe { goto _test_eof53 }
	fallthrough
case 53:
	switch data[p] {
		case 85: goto st54
		case 117: goto st54
	}
	goto st0
st54:
	p++
	if p == pe { goto _test_eof54 }
	fallthrough
case 54:
	switch data[p] {
		case 83: goto st8
		case 115: goto st8
	}
	goto st0
tr85:
// line 22 "kparse.rl"
	{ mark = p }
	goto st55
st55:
	p++
	if p == pe { goto _test_eof55 }
	fallthrough
case 55:
// line 671 "kparse.go"
	switch data[p] {
		case 82: goto st56
		case 85: goto st78
		case 114: goto st56
		case 117: goto st78
	}
	goto st0
st56:
	p++
	if p == pe { goto _test_eof56 }
	fallthrough
case 56:
	switch data[p] {
		case 73: goto st57
		case 105: goto st57
	}
	goto st0
st57:
	p++
	if p == pe { goto _test_eof57 }
	fallthrough
case 57:
	switch data[p] {
		case 77: goto st58
		case 86: goto st59
		case 109: goto st58
		case 118: goto st59
	}
	goto st0
st58:
	p++
	if p == pe { goto _test_eof58 }
	fallthrough
case 58:
	switch data[p] {
		case 69: goto st41
		case 101: goto st41
	}
	goto st0
st59:
	p++
	if p == pe { goto _test_eof59 }
	fallthrough
case 59:
	switch data[p] {
		case 65: goto st60
		case 97: goto st60
	}
	goto st0
st60:
	p++
	if p == pe { goto _test_eof60 }
	fallthrough
case 60:
	switch data[p] {
		case 84: goto st61
		case 116: goto st61
	}
	goto st0
st61:
	p++
	if p == pe { goto _test_eof61 }
	fallthrough
case 61:
	switch data[p] {
		case 69: goto st62
		case 101: goto st62
	}
	goto st0
st62:
	p++
	if p == pe { goto _test_eof62 }
	fallthrough
case 62:
	switch data[p] {
		case 45: goto st63
		case 69: goto st72
		case 75: goto st76
		case 101: goto st72
		case 107: goto st76
	}
	goto st0
st63:
	p++
	if p == pe { goto _test_eof63 }
	fallthrough
case 63:
	switch data[p] {
		case 75: goto st64
		case 107: goto st64
	}
	goto st0
st64:
	p++
	if p == pe { goto _test_eof64 }
	fallthrough
case 64:
	switch data[p] {
		case 69: goto st65
		case 101: goto st65
	}
	goto st0
st65:
	p++
	if p == pe { goto _test_eof65 }
	fallthrough
case 65:
	switch data[p] {
		case 89: goto st66
		case 121: goto st66
	}
	goto st0
st66:
	p++
	if p == pe { goto _test_eof66 }
	fallthrough
case 66:
	if data[p] == 45 { goto st67 }
	goto st0
st67:
	p++
	if p == pe { goto _test_eof67 }
	fallthrough
case 67:
	switch data[p] {
		case 70: goto st68
		case 102: goto st68
	}
	goto st0
st68:
	p++
	if p == pe { goto _test_eof68 }
	fallthrough
case 68:
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
		case 82: goto st70
		case 114: goto st70
	}
	goto st0
st70:
	p++
	if p == pe { goto _test_eof70 }
	fallthrough
case 70:
	switch data[p] {
		case 77: goto st71
		case 109: goto st71
	}
	goto st0
st71:
	p++
	if p == pe { goto _test_eof71 }
	fallthrough
case 71:
	switch data[p] {
		case 65: goto st28
		case 97: goto st28
	}
	goto st0
st72:
	p++
	if p == pe { goto _test_eof72 }
	fallthrough
case 72:
	switch data[p] {
		case 88: goto st73
		case 120: goto st73
	}
	goto st0
st73:
	p++
	if p == pe { goto _test_eof73 }
	fallthrough
case 73:
	switch data[p] {
		case 80: goto st74
		case 112: goto st74
	}
	goto st0
st74:
	p++
	if p == pe { goto _test_eof74 }
	fallthrough
case 74:
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
		case 78: goto st26
		case 110: goto st26
	}
	goto st0
st76:
	p++
	if p == pe { goto _test_eof76 }
	fallthrough
case 76:
	switch data[p] {
		case 69: goto st77
		case 101: goto st77
	}
	goto st0
st77:
	p++
	if p == pe { goto _test_eof77 }
	fallthrough
case 77:
	switch data[p] {
		case 89: goto st8
		case 121: goto st8
	}
	goto st0
st78:
	p++
	if p == pe { goto _test_eof78 }
	fallthrough
case 78:
	switch data[p] {
		case 66: goto st79
		case 98: goto st79
	}
	goto st0
st79:
	p++
	if p == pe { goto _test_eof79 }
	fallthrough
case 79:
	switch data[p] {
		case 76: goto st80
		case 108: goto st80
	}
	goto st0
st80:
	p++
	if p == pe { goto _test_eof80 }
	fallthrough
case 80:
	switch data[p] {
		case 73: goto st81
		case 105: goto st81
	}
	goto st0
st81:
	p++
	if p == pe { goto _test_eof81 }
	fallthrough
case 81:
	switch data[p] {
		case 67: goto st82
		case 83: goto st83
		case 99: goto st82
		case 115: goto st83
	}
	goto st0
st82:
	p++
	if p == pe { goto _test_eof82 }
	fallthrough
case 82:
	switch data[p] {
		case 69: goto st72
		case 101: goto st72
	}
	goto st0
st83:
	p++
	if p == pe { goto _test_eof83 }
	fallthrough
case 83:
	switch data[p] {
		case 72: goto st8
		case 104: goto st8
	}
	goto st0
	}
	_test_eof84: cs = 84; goto _test_eof; 
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

	_test_eof: {}
	_out: {}
	}

// line 53 "kparse.rl"


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
        return m, nil
}
