package dns

import (
  	"github.com/google/go-cmp/cmp"
	"strconv"
	"strings"
	)


/* We need this file until ZONEMD be a standard */
/* Then we MUST refactor to put the code at the right files */

const 
  (
	RESERVED = 0
	TypeZONEMD = uint16(63)
	SchemeSIMPLE = 1
	HashSHA384 = 1
  )

type ZONEMD struct {
  Hdr 		RR_Header
  Serial 	uint32
  Scheme 	uint8
  Hash 		uint8
  Digest 	string `dns:"hex"`
  }

func (rr *ZONEMD) String() string {
  return rr.Hdr.String() + strconv.Itoa(int(rr.Serial)) + 
         " " + strconv.Itoa(int(rr.Scheme)) + 
         " " + strconv.Itoa(int(rr.Hash)) + 
         " " + strings.ToUpper(rr.Digest);
  }
func (rr *ZONEMD) Header() *RR_Header	  { return &rr.Hdr }
func (rr *ZONEMD) len(off int, compression map[string]struct{}) int {
  l := rr.Hdr.len(off, compression)
	l += 4  // Serial
	l++ // Scheme
	l++    // Algorithm
	l += len(rr.Digest) / 2
	return l
}
func (rr *ZONEMD) copy() RR {
	return &ZONEMD {rr.Hdr, rr.Serial, rr.Scheme, rr.Hash, rr.Digest}
}
func (rr *ZONEMD) pack(msg []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	off, err = packUint32(rr.Serial,msg,off)
        if err != nil {
                return off, err
        }
        off, err = packUint8(rr.Scheme, msg, off)
        if err != nil {
                return off, err
        }
        off, err = packUint8(rr.Hash, msg, off)
        if err != nil {
                return off, err
        }
        off, err = packStringHex(rr.Digest, msg, off)
        if err != nil {
                return off, err
        }
        return off, nil
}
func (rr *ZONEMD) unpack(msg []byte, off int) (off1 int, err error) {
        rdStart := off
        _ = rdStart

        rr.Serial, off, err = unpackUint32(msg, off)
        if err != nil {
                return off, err
        }
        if off == len(msg) {
                return off, nil
        }
        rr.Scheme, off, err = unpackUint8(msg, off)
        if err != nil {
                return off, err
        }
        if off == len(msg) {
                return off, nil
        }
        rr.Hash, off, err = unpackUint8(msg, off)
        if err != nil {
                return off, err
        }
        if off == len(msg) {
                return off, nil
        }
        rr.Digest, off, err = unpackStringHex(msg, off, rdStart+int(rr.Hdr.Rdlength))
        if err != nil {
                return off, err
        }
  return off, nil
}
func (rr *ZONEMD) parse(c *zlexer, o string) *ParseError {
  return rr.parseZONEMD(c, o, "ZONEMD")
}
func (rr *ZONEMD) isDuplicate(r2 RR) bool {
  return cmp.Equal(rr,r2)
}

func (rr *ZONEMD) parseZONEMD(c *zlexer, o, typ string) *ParseError {
        l, _ := c.Next()
        i, e := strconv.ParseUint(l.token, 10, 32)
        if e != nil || l.err {
                return &ParseError{"", "bad " + typ + " Serial", l}
        }
        rr.Serial = uint32(i)

        c.Next() // zBlank
        l, _ = c.Next()
        i, e1 := strconv.ParseUint(l.token, 10, 8)
        if e1 != nil || l.err {
                return &ParseError{"", "bad " + typ + " Scheme", l}
        }
        rr.Scheme = uint8(i)

        c.Next() // zBlank
        l, _ = c.Next()
        if i, err := strconv.ParseUint(l.token, 10, 8); err != nil {
                tokenUpper := strings.ToUpper(l.token)
                i, ok := StringToAlgorithm[tokenUpper]
                if !ok || l.err {
                        return &ParseError{"", "bad " + typ + " Hash Algorithm", l}
                }
                rr.Hash = i
        } else {
                rr.Hash = uint8(i)
        }
        s, e2 := endingToString(c, "bad "+typ+" Digest")
        if e2 != nil {
                return e2
        }
        rr.Digest = s
        return nil
}

