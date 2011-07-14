
// line 1 "zparse.rl"
package dns

import (
    "os"
    "fmt"
)


// line 12 "zparse.go"
var z_start int = 0
var z_first_final int = 22
var z_error int = -1

var z_en_main int = 0


// line 11 "zparse.rl"


func zparse(data string) (res int, err os.Error) {
        cs, p, pe, eof := 0, 0, len(data), len(data)

        
// line 27 "zparse.go"
	cs = z_start

// line 30 "zparse.go"
	{
	if p == pe { goto _test_eof }
	switch cs {
	case -666: // i am a hack D:
st0:
	p++
	if p == pe { goto _test_eof0 }
	fallthrough
case 0:
	switch data[p] {
		case 9: goto st1
		case 32: goto st1
	}
	goto st0
tr9:
// line 19 "zparse.rl"
	{ fmt.Printf("%s\n", data[p:pe]) }
	goto st1
st1:
	p++
	if p == pe { goto _test_eof1 }
	fallthrough
case 1:
// line 54 "zparse.go"
	switch data[p] {
		case 9: goto st1
		case 32: goto st1
		case 65: goto tr3
		case 67: goto tr4
		case 68: goto tr5
		case 72: goto tr6
		case 73: goto tr7
		case 78: goto tr8
		case 97: goto tr3
		case 99: goto tr4
		case 100: goto tr5
		case 104: goto tr6
		case 105: goto tr7
		case 110: goto tr8
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr2 }
	goto st0
tr2:
// line 18 "zparse.rl"
	{ fmt.Printf("%s\n", data[p:pe]) }
	goto st2
st2:
	p++
	if p == pe { goto _test_eof2 }
	fallthrough
case 2:
// line 82 "zparse.go"
	switch data[p] {
		case 9: goto tr9
		case 32: goto tr9
	}
	if 48 <= data[p] && data[p] <= 57 { goto st2 }
	goto st0
tr3:
// line 18 "zparse.rl"
	{ fmt.Printf("%s\n", data[p:pe]) }
	goto st3
tr20:
// line 18 "zparse.rl"
	{ fmt.Printf("%s\n", data[p:pe]) }
// line 17 "zparse.rl"
	{ fmt.Printf("%s\n", data[p:pe]) }
	goto st3
st3:
	p++
	if p == pe { goto _test_eof3 }
	fallthrough
case 3:
// line 104 "zparse.go"
	switch data[p] {
		case 9: goto st4
		case 32: goto st4
		case 78: goto st5
		case 110: goto st5
	}
	goto st0
st4:
	p++
	if p == pe { goto _test_eof4 }
	fallthrough
case 4:
	switch data[p] {
		case 9: goto st23
		case 32: goto st23
		case 65: goto tr16
		case 78: goto tr16
		case 97: goto tr16
		case 110: goto tr16
	}
	if data[p] < 72 {
		if data[p] > 57 {
			if 67 <= data[p] && data[p] <= 68 { goto tr16 }
		} else if data[p] >= 48 {
			goto tr15
		}
	} else if data[p] > 73 {
		if data[p] > 100 {
			if 104 <= data[p] && data[p] <= 105 { goto tr16 }
		} else if data[p] >= 99 {
			goto tr16
		}
	} else {
		goto tr16
	}
	goto st22
tr16:
// line 18 "zparse.rl"
	{ fmt.Printf("%s\n", data[p:pe]) }
	goto st22
tr35:
// line 18 "zparse.rl"
	{ fmt.Printf("%s\n", data[p:pe]) }
// line 17 "zparse.rl"
	{ fmt.Printf("%s\n", data[p:pe]) }
	goto st22
tr32:
// line 17 "zparse.rl"
	{ fmt.Printf("%s\n", data[p:pe]) }
	goto st22
st22:
	p++
	if p == pe { goto _test_eof22 }
	fallthrough
case 22:
// line 160 "zparse.go"
	switch data[p] {
		case 9: goto tr33
		case 32: goto tr33
	}
	goto tr32
tr33:
// line 17 "zparse.rl"
	{ fmt.Printf("%s\n", data[p:pe]) }
	goto st23
tr36:
// line 19 "zparse.rl"
	{ fmt.Printf("%s\n", data[p:pe]) }
// line 17 "zparse.rl"
	{ fmt.Printf("%s\n", data[p:pe]) }
	goto st23
st23:
	p++
	if p == pe { goto _test_eof23 }
	fallthrough
case 23:
// line 181 "zparse.go"
	switch data[p] {
		case 9: goto tr33
		case 32: goto tr33
		case 65: goto tr35
		case 78: goto tr35
		case 97: goto tr35
		case 110: goto tr35
	}
	if data[p] < 72 {
		if data[p] > 57 {
			if 67 <= data[p] && data[p] <= 68 { goto tr35 }
		} else if data[p] >= 48 {
			goto tr34
		}
	} else if data[p] > 73 {
		if data[p] > 100 {
			if 104 <= data[p] && data[p] <= 105 { goto tr35 }
		} else if data[p] >= 99 {
			goto tr35
		}
	} else {
		goto tr35
	}
	goto tr32
tr15:
// line 18 "zparse.rl"
	{ fmt.Printf("%s\n", data[p:pe]) }
	goto st24
tr34:
// line 18 "zparse.rl"
	{ fmt.Printf("%s\n", data[p:pe]) }
// line 17 "zparse.rl"
	{ fmt.Printf("%s\n", data[p:pe]) }
	goto st24
tr37:
// line 17 "zparse.rl"
	{ fmt.Printf("%s\n", data[p:pe]) }
	goto st24
st24:
	p++
	if p == pe { goto _test_eof24 }
	fallthrough
case 24:
// line 225 "zparse.go"
	switch data[p] {
		case 9: goto tr36
		case 32: goto tr36
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr37 }
	goto tr32
st5:
	p++
	if p == pe { goto _test_eof5 }
	fallthrough
case 5:
	switch data[p] {
		case 9: goto st1
		case 32: goto st1
		case 89: goto st6
		case 121: goto st6
	}
	goto st0
st6:
	p++
	if p == pe { goto _test_eof6 }
	fallthrough
case 6:
	switch data[p] {
		case 9: goto st7
		case 32: goto st7
	}
	goto st0
st7:
	p++
	if p == pe { goto _test_eof7 }
	fallthrough
case 7:
	switch data[p] {
		case 9: goto st7
		case 32: goto st7
		case 65: goto tr20
		case 67: goto tr4
		case 68: goto tr21
		case 72: goto tr6
		case 73: goto tr7
		case 78: goto tr8
		case 97: goto tr20
		case 99: goto tr4
		case 100: goto tr21
		case 104: goto tr6
		case 105: goto tr7
		case 110: goto tr8
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr19 }
	goto st0
tr19:
// line 18 "zparse.rl"
	{ fmt.Printf("%s\n", data[p:pe]) }
	goto st8
st8:
	p++
	if p == pe { goto _test_eof8 }
	fallthrough
case 8:
// line 286 "zparse.go"
	switch data[p] {
		case 9: goto tr22
		case 32: goto tr22
	}
	if 48 <= data[p] && data[p] <= 57 { goto st8 }
	goto st0
tr22:
// line 19 "zparse.rl"
	{ fmt.Printf("%s\n", data[p:pe]) }
	goto st9
st9:
	p++
	if p == pe { goto _test_eof9 }
	fallthrough
case 9:
// line 302 "zparse.go"
	switch data[p] {
		case 9: goto st9
		case 32: goto st9
		case 65: goto tr20
		case 67: goto tr4
		case 68: goto tr21
		case 72: goto tr6
		case 73: goto tr7
		case 78: goto tr8
		case 97: goto tr20
		case 99: goto tr4
		case 100: goto tr21
		case 104: goto tr6
		case 105: goto tr7
		case 110: goto tr8
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr2 }
	goto st0
tr4:
// line 18 "zparse.rl"
	{ fmt.Printf("%s\n", data[p:pe]) }
	goto st10
st10:
	p++
	if p == pe { goto _test_eof10 }
	fallthrough
case 10:
// line 330 "zparse.go"
	switch data[p] {
		case 9: goto st1
		case 32: goto st1
		case 72: goto st6
		case 83: goto st6
		case 104: goto st6
		case 115: goto st6
	}
	goto st0
tr5:
// line 18 "zparse.rl"
	{ fmt.Printf("%s\n", data[p:pe]) }
	goto st11
tr21:
// line 18 "zparse.rl"
	{ fmt.Printf("%s\n", data[p:pe]) }
// line 17 "zparse.rl"
	{ fmt.Printf("%s\n", data[p:pe]) }
	goto st11
st11:
	p++
	if p == pe { goto _test_eof11 }
	fallthrough
case 11:
// line 355 "zparse.go"
	switch data[p] {
		case 9: goto st1
		case 32: goto st1
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
		case 9: goto st1
		case 32: goto st1
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
		case 9: goto st1
		case 32: goto st1
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
		case 9: goto st1
		case 32: goto st1
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
		case 9: goto st1
		case 32: goto st1
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
		case 9: goto st4
		case 32: goto st4
	}
	goto st0
tr6:
// line 18 "zparse.rl"
	{ fmt.Printf("%s\n", data[p:pe]) }
	goto st17
st17:
	p++
	if p == pe { goto _test_eof17 }
	fallthrough
case 17:
// line 430 "zparse.go"
	switch data[p] {
		case 9: goto st1
		case 32: goto st1
		case 83: goto st6
		case 115: goto st6
	}
	goto st0
tr7:
// line 18 "zparse.rl"
	{ fmt.Printf("%s\n", data[p:pe]) }
	goto st18
st18:
	p++
	if p == pe { goto _test_eof18 }
	fallthrough
case 18:
// line 447 "zparse.go"
	switch data[p] {
		case 9: goto st1
		case 32: goto st1
		case 78: goto st6
		case 110: goto st6
	}
	goto st0
tr8:
// line 18 "zparse.rl"
	{ fmt.Printf("%s\n", data[p:pe]) }
	goto st19
st19:
	p++
	if p == pe { goto _test_eof19 }
	fallthrough
case 19:
// line 464 "zparse.go"
	switch data[p] {
		case 9: goto st1
		case 32: goto st1
		case 79: goto st20
		case 111: goto st20
	}
	goto st0
st20:
	p++
	if p == pe { goto _test_eof20 }
	fallthrough
case 20:
	switch data[p] {
		case 9: goto st1
		case 32: goto st1
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
		case 9: goto st1
		case 32: goto st1
		case 69: goto st6
		case 101: goto st6
	}
	goto st0
	}
	_test_eof0: cs = 0; goto _test_eof; 
	_test_eof1: cs = 1; goto _test_eof; 
	_test_eof2: cs = 2; goto _test_eof; 
	_test_eof3: cs = 3; goto _test_eof; 
	_test_eof4: cs = 4; goto _test_eof; 
	_test_eof22: cs = 22; goto _test_eof; 
	_test_eof23: cs = 23; goto _test_eof; 
	_test_eof24: cs = 24; goto _test_eof; 
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

	_test_eof: {}
	if p == eof {
	switch cs {
	case 22, 23, 24:
// line 17 "zparse.rl"
	{ fmt.Printf("%s\n", data[p:pe]) }
	break
// line 530 "zparse.go"
	}
	}

	}

// line 47 "zparse.rl"


        if cs < z_first_final {
                // No clue what I'm doing what so ever
                if p == pe {
                        return 0, os.ErrorString("unexpected eof")
                } else {
                        return 0, os.ErrorString(fmt.Sprintf("error at position %d", p))
                }
        }
        return 0 ,nil
}
