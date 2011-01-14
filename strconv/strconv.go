package strconv

import (
	"unicode"
        conv "strconv"
        "dns"
)

const (
	m = 60
	h = m * m
	d = 24 * h
	w = 7 * d
)

// Convert a Ttl to a value. Supported value 'm' for minutes, 'h' for hours
// 'w' for week and 'd' for days. Stuff like '1d1d' is legal and return the value of '2d'
func StringToSeconds(ttl string) (sec uint32, ok bool) {
	num := ""
	for _, k := range ttl {
		if unicode.IsDigit(k) {
			num += string(k)
		} else {
			i, _ := conv.Atoi(num)
			switch k {
			case 'm':
				sec += uint32(i) * m
			case 'h':
				sec += uint32(i) * h
			case 'd':
				sec += uint32(i) * d
			case 'w':
				sec += uint32(i) * w
                        default:
                                return
			}
			num = ""
		}
	}
        i, _ := conv.Atoi(num)
        sec += uint32(i)
        return
}

func SecondsToString(val uint32) (str string) {
        mod := val / w
        if mod > 0 {
                str += conv.Itoa(int(mod)) + "w"
        }
        val -= mod * w

        mod = val / d
        if mod > 0 {
                str += conv.Itoa(int(mod)) + "d"
        }
        val -= mod * d

        mod = val / h
        if mod > 0 {
                str += conv.Itoa(int(mod)) + "h"
        }
        val -= mod * h

        mod = val / m
        if mod > 0 {
                str += conv.Itoa(int(mod)) + "m"
        }
        val -= mod * m

        if val > 0 {
                str += conv.Itoa(int(val))
        }
        return
}

// Read a string and convert it to the correct
// Resource Record.
func SetString(s string) dns.RR {

        k := new(dns.RR_DNSKEY)
        return k
}
