package dns

import "encoding/binary"

func HostToNetShort(i uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return b
}
