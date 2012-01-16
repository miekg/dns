package dns

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"io"
	"math/big"
	"strings"
	"text/scanner"
)

// ReadPrivateKey reads a private key from the io.Reader q.
func ReadPrivateKey(q io.Reader) (PrivateKey, error) {
	m, e := parseKey(q)
	if m == nil {
		return nil, e
	}
	if _, ok := m["private-key-format"]; !ok {
		return nil, ErrPrivKey
	}
	if m["private-key-format"] != "v1.2" && m["private-key-format"] != "v1.3" {
		return nil, ErrPrivKey
	}
	switch m["algorithm"] {
	case "1 (RSAMD5)", "5 (RSASHA1)", "8 (RSASHA256)", "10 (RSASHA512)":
		fallthrough
	case "7 (RSASHA1NSEC3SHA1)":
		return readPrivateKeyRSA(m)
	case "13 (ECDSAP256SHA256)", "14 (ECDSAP384SHA384)":
		return readPrivateKeyECDSA(m)
	}
	return nil, ErrPrivKey
}

// Read a private key (file) string and create a public key. Return the private key.
func readPrivateKeyRSA(m map[string]string) (PrivateKey, error) {
	p := new(rsa.PrivateKey)
	p.Primes = []*big.Int{nil, nil}
	for k, v := range m {
		switch k {
		case "modulus", "publicexponent", "privateexponent", "prime1", "prime2":
			v1, err := packBase64([]byte(v))
			if err != nil {
				return nil, err
			}
			switch k {
			case "modulus":
				p.PublicKey.N = big.NewInt(0)
				p.PublicKey.N.SetBytes(v1)
			case "publicexponent":
				i := big.NewInt(0)
				i.SetBytes(v1)
				p.PublicKey.E = int(i.Int64()) // int64 should be large enough
			case "privateexponent":
				p.D = big.NewInt(0)
				p.D.SetBytes(v1)
			case "prime1":
				p.Primes[0] = big.NewInt(0)
				p.Primes[0].SetBytes(v1)
			case "prime2":
				p.Primes[1] = big.NewInt(0)
				p.Primes[1].SetBytes(v1)
			}
		case "exponent1", "exponent2", "coefficient":
			// not used in Go (yet)
		case "created", "publish", "activate":
			// not used in Go (yet)
		}
	}
	return p, nil
}

func readPrivateKeyECDSA(m map[string]string) (PrivateKey, error) {
	p := new(ecdsa.PrivateKey)
	p.D = big.NewInt(0)
	// Need to check if we have everything
	for k, v := range m {
		switch k {
		case "privatekey:":
			v1, err := packBase64([]byte(v))
			if err != nil {
				return nil, err
			}
			p.D.SetBytes(v1)
		case "created:", "publish:", "activate:":
			/* not used in Go (yet) */
		}
	}
	return p, nil
}

// parseKey reads a private key from r. It returns a map[string]string,
// with the key-value pairs, or an error when the file is not correct.
func parseKey(r io.Reader) (map[string]string, error) {
	var s scanner.Scanner
	m := make(map[string]string)
	c := make(chan lex)
	k := ""
	s.Init(r)
	s.Mode = 0
	s.Whitespace = 0
	// Start the lexer
	go klexer(s, c)
	for l := range c {
		// It should alternate
		switch l.value {
		case _KEY:
			k = l.token
		case _VALUE:
			if k == "" {
				return nil, &ParseError{"No key seen", l}
			}
			//println("Setting", strings.ToLower(k), "to", l.token, "b")
			m[strings.ToLower(k)] = l.token
			k = ""
		}
	}
	return m, nil
}

// klexer scans the sourcefile and returns tokens on the channel c.
func klexer(s scanner.Scanner, c chan lex) {
	var l lex
	str := "" // Hold the current read text
	commt := false
	key := true
	tok := s.Scan()
	defer close(c)
	for tok != scanner.EOF {
		l.column = s.Position.Column
		l.line = s.Position.Line
		switch x := s.TokenText(); x {
		case ":":
			if commt {
				break
			}
			l.token = str
			if key {
				l.value = _KEY
				c <- l
				// Next token is a space, eat it
				s.Scan()
				key = false
				str = ""
			} else {
				l.value = _VALUE
			}
		case ";":
			commt = true
		case "\n":
			if commt {
				// Reset a comment
				commt = false
			}
			l.value = _VALUE
			l.token = str
			c <- l
			str = ""
			commt = false
			key = true
		default:
			if commt {
				break
			}
			str += x
		}
		tok = s.Scan()
	}
	if len(str) > 0 {
		// Send remainder
		l.token = str
		l.value = _VALUE
		c <- l
	}
}
