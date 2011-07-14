
// line 1 "zparse.rl"
package main

import (
    "os"
    "fmt"
)


// line 12 "zparse.go"
var z_start int = 0
var z_first_final int = 10
var z_error int = -1

var z_en_main int = 0


// line 11 "zparse.rl"


func zparse(data string) (res int, err os.Error) {
        cs, p, pe := 0, 0, len(data)

        
// line 27 "zparse.go"
	cs = z_start

// line 30 "zparse.go"
	{
	if p == pe { goto _test_eof }
	switch cs {
	case -666: // i am a hack D:
tr4:
// line 18 "zparse.rl"
	{ fmt.Printf("%s\n", data) }
	goto st0
st0:
	p++
	if p == pe { goto _test_eof0 }
	fallthrough
case 0:
// line 44 "zparse.go"
	switch data[p] {
		case 9: goto st1
		case 32: goto st1
	}
	goto st0
tr6:
// line 19 "zparse.rl"
	{ fmt.Printf("%s\n", data) }
	goto st1
st1:
	p++
	if p == pe { goto _test_eof1 }
	fallthrough
case 1:
// line 59 "zparse.go"
	switch data[p] {
		case 9: goto st1
		case 32: goto st1
		case 65: goto tr3
		case 67: goto tr4
		case 68: goto tr5
		case 78: goto tr4
		case 97: goto tr3
		case 99: goto tr4
		case 100: goto tr5
		case 110: goto tr4
	}
	if data[p] < 72 {
		if 48 <= data[p] && data[p] <= 57 { goto tr2 }
	} else if data[p] > 73 {
		if 104 <= data[p] && data[p] <= 105 { goto tr4 }
	} else {
		goto tr4
	}
	goto st0
tr2:
// line 18 "zparse.rl"
	{ fmt.Printf("%s\n", data) }
	goto st2
st2:
	p++
	if p == pe { goto _test_eof2 }
	fallthrough
case 2:
// line 89 "zparse.go"
	switch data[p] {
		case 9: goto tr6
		case 32: goto tr6
	}
	if 48 <= data[p] && data[p] <= 57 { goto st2 }
	goto st0
tr3:
// line 18 "zparse.rl"
	{ fmt.Printf("%s\n", data) }
	goto st3
st3:
	p++
	if p == pe { goto _test_eof3 }
	fallthrough
case 3:
// line 105 "zparse.go"
	switch data[p] {
		case 9: goto st4
		case 32: goto st4
	}
	goto st0
st4:
	p++
	if p == pe { goto _test_eof4 }
	fallthrough
case 4:
	switch data[p] {
		case 9: goto st11
		case 32: goto st11
		case 65: goto tr12
		case 78: goto tr12
		case 97: goto tr12
		case 110: goto tr12
	}
	if data[p] < 72 {
		if data[p] > 57 {
			if 67 <= data[p] && data[p] <= 68 { goto tr12 }
		} else if data[p] >= 48 {
			goto tr11
		}
	} else if data[p] > 73 {
		if data[p] > 100 {
			if 104 <= data[p] && data[p] <= 105 { goto tr12 }
		} else if data[p] >= 99 {
			goto tr12
		}
	} else {
		goto tr12
	}
	goto st10
tr12:
// line 18 "zparse.rl"
	{ fmt.Printf("%s\n", data) }
	goto st10
tr18:
// line 17 "zparse.rl"
	{ fmt.Printf("%s\n", data) }
	goto st10
tr21:
// line 18 "zparse.rl"
	{ fmt.Printf("%s\n", data) }
// line 17 "zparse.rl"
	{ fmt.Printf("%s\n", data) }
	goto st10
st10:
	p++
	if p == pe { goto _test_eof10 }
	fallthrough
case 10:
// line 159 "zparse.go"
	switch data[p] {
		case 9: goto tr19
		case 32: goto tr19
	}
	goto tr18
tr19:
// line 17 "zparse.rl"
	{ fmt.Printf("%s\n", data) }
	goto st11
tr22:
// line 19 "zparse.rl"
	{ fmt.Printf("%s\n", data) }
// line 17 "zparse.rl"
	{ fmt.Printf("%s\n", data) }
	goto st11
st11:
	p++
	if p == pe { goto _test_eof11 }
	fallthrough
case 11:
// line 180 "zparse.go"
	switch data[p] {
		case 9: goto tr19
		case 32: goto tr19
		case 65: goto tr21
		case 78: goto tr21
		case 97: goto tr21
		case 110: goto tr21
	}
	if data[p] < 72 {
		if data[p] > 57 {
			if 67 <= data[p] && data[p] <= 68 { goto tr21 }
		} else if data[p] >= 48 {
			goto tr20
		}
	} else if data[p] > 73 {
		if data[p] > 100 {
			if 104 <= data[p] && data[p] <= 105 { goto tr21 }
		} else if data[p] >= 99 {
			goto tr21
		}
	} else {
		goto tr21
	}
	goto tr18
tr11:
// line 18 "zparse.rl"
	{ fmt.Printf("%s\n", data) }
	goto st12
tr23:
// line 17 "zparse.rl"
	{ fmt.Printf("%s\n", data) }
	goto st12
tr20:
// line 18 "zparse.rl"
	{ fmt.Printf("%s\n", data) }
// line 17 "zparse.rl"
	{ fmt.Printf("%s\n", data) }
	goto st12
st12:
	p++
	if p == pe { goto _test_eof12 }
	fallthrough
case 12:
// line 224 "zparse.go"
	switch data[p] {
		case 9: goto tr22
		case 32: goto tr22
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr23 }
	goto tr18
tr5:
// line 18 "zparse.rl"
	{ fmt.Printf("%s\n", data) }
	goto st5
st5:
	p++
	if p == pe { goto _test_eof5 }
	fallthrough
case 5:
// line 240 "zparse.go"
	switch data[p] {
		case 9: goto st1
		case 32: goto st1
		case 78: goto st6
		case 110: goto st6
	}
	goto st0
st6:
	p++
	if p == pe { goto _test_eof6 }
	fallthrough
case 6:
	switch data[p] {
		case 9: goto st1
		case 32: goto st1
		case 83: goto st7
		case 115: goto st7
	}
	goto st0
st7:
	p++
	if p == pe { goto _test_eof7 }
	fallthrough
case 7:
	switch data[p] {
		case 9: goto st1
		case 32: goto st1
		case 75: goto st8
		case 107: goto st8
	}
	goto st0
st8:
	p++
	if p == pe { goto _test_eof8 }
	fallthrough
case 8:
	switch data[p] {
		case 9: goto st1
		case 32: goto st1
		case 69: goto st9
		case 101: goto st9
	}
	goto st0
st9:
	p++
	if p == pe { goto _test_eof9 }
	fallthrough
case 9:
	switch data[p] {
		case 9: goto st1
		case 32: goto st1
		case 89: goto st3
		case 121: goto st3
	}
	goto st0
	}
	_test_eof0: cs = 0; goto _test_eof; 
	_test_eof1: cs = 1; goto _test_eof; 
	_test_eof2: cs = 2; goto _test_eof; 
	_test_eof3: cs = 3; goto _test_eof; 
	_test_eof4: cs = 4; goto _test_eof; 
	_test_eof10: cs = 10; goto _test_eof; 
	_test_eof11: cs = 11; goto _test_eof; 
	_test_eof12: cs = 12; goto _test_eof; 
	_test_eof5: cs = 5; goto _test_eof; 
	_test_eof6: cs = 6; goto _test_eof; 
	_test_eof7: cs = 7; goto _test_eof; 
	_test_eof8: cs = 8; goto _test_eof; 
	_test_eof9: cs = 9; goto _test_eof; 

	_test_eof: {}
	if p == eof {
	switch cs {
	case 10, 11, 12:
// line 17 "zparse.rl"
	{ fmt.Printf("%s\n", data) }
	break
// line 318 "zparse.go"
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

func main() {

}
