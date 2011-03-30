package dns

import (
	"unicode"
	"strconv"
)

const (
	m = 60
	h = m * m
	d = 24 * h
	w = 7 * d
)

// Convert a Ttl to a value. Supported values: 'm' for minutes, 'h' for hours
// 'w' for week and 'd' for days, '1d1d' is legal and returns the value of '2d'.
func stringToSeconds(ttl string) (sec uint32, ok bool) {
	num := ""
	for _, k := range ttl {
		if unicode.IsDigit(k) {
			num += string(k)
		} else {
			i, _ := strconv.Atoi(num)
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
	i, _ := strconv.Atoi(num)
	sec += uint32(i)
	return
}

// Convert a value to a (string) Ttl. Reverse of StringToSeconds()
func secondsToString(val uint32) (str string) {
	mod := val / w
	if mod > 0 {
		str += strconv.Itoa(int(mod)) + "w"
	}
	val -= mod * w

	mod = val / d
	if mod > 0 {
		str += strconv.Itoa(int(mod)) + "d"
	}
	val -= mod * d

	mod = val / h
	if mod > 0 {
		str += strconv.Itoa(int(mod)) + "h"
	}
	val -= mod * h

	mod = val / m
	if mod > 0 {
		str += strconv.Itoa(int(mod)) + "m"
	}
	val -= mod * m

	if val > 0 {
		str += strconv.Itoa(int(val))
	}
	return
}
