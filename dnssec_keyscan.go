package dns

import (
	"bufio"
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"io"
	"math/big"
	"strconv"
	"strings"

	"golang.org/x/crypto/ed25519"
)

// NewPrivateKey returns a PrivateKey by parsing the string s.
// s should be in the same form of the BIND private key files.
func (k *DNSKEY) NewPrivateKey(s string) (crypto.PrivateKey, error) {
	if s == "" || s[len(s)-1] != '\n' { // We need a closing newline
		return k.ReadPrivateKey(strings.NewReader(s+"\n"), "")
	}
	return k.ReadPrivateKey(strings.NewReader(s), "")
}

// ReadPrivateKey reads a private key from the io.Reader q. The string file is
// only used in error reporting.
// The public key must be known, because some cryptographic algorithms embed
// the public inside the privatekey.
func (k *DNSKEY) ReadPrivateKey(q io.Reader, file string) (crypto.PrivateKey, error) {
	m, err := parseKey(q, file)
	if m == nil {
		return nil, err
	}
	if _, ok := m["private-key-format"]; !ok {
		return nil, ErrPrivKey
	}
	if m["private-key-format"] != "v1.2" && m["private-key-format"] != "v1.3" {
		return nil, ErrPrivKey
	}
	// TODO(mg): check if the pubkey matches the private key
	algo, err := strconv.ParseUint(strings.SplitN(m["algorithm"], " ", 2)[0], 10, 8)
	if err != nil {
		return nil, ErrPrivKey
	}
	switch uint8(algo) {
	case DSA:
		priv, err := readPrivateKeyDSA(m)
		if err != nil {
			return nil, err
		}
		pub := k.publicKeyDSA()
		if pub == nil {
			return nil, ErrKey
		}
		priv.PublicKey = *pub
		return priv, nil
	case RSAMD5:
		fallthrough
	case RSASHA1:
		fallthrough
	case RSASHA1NSEC3SHA1:
		fallthrough
	case RSASHA256:
		fallthrough
	case RSASHA512:
		priv, err := readPrivateKeyRSA(m)
		if err != nil {
			return nil, err
		}
		pub := k.publicKeyRSA()
		if pub == nil {
			return nil, ErrKey
		}
		priv.PublicKey = *pub
		return priv, nil
	case ECCGOST:
		return nil, ErrPrivKey
	case ECDSAP256SHA256:
		fallthrough
	case ECDSAP384SHA384:
		priv, err := readPrivateKeyECDSA(m)
		if err != nil {
			return nil, err
		}
		pub := k.publicKeyECDSA()
		if pub == nil {
			return nil, ErrKey
		}
		priv.PublicKey = *pub
		return priv, nil
	case ED25519:
		return readPrivateKeyED25519(m)
	default:
		return nil, ErrPrivKey
	}
}

// Read a private key (file) string and create a public key. Return the private key.
func readPrivateKeyRSA(m map[string]string) (*rsa.PrivateKey, error) {
	p := new(rsa.PrivateKey)
	p.Primes = []*big.Int{nil, nil}
	for k, v := range m {
		switch k {
		case "modulus", "publicexponent", "privateexponent", "prime1", "prime2":
			v1, err := fromBase64([]byte(v))
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

func readPrivateKeyDSA(m map[string]string) (*dsa.PrivateKey, error) {
	p := new(dsa.PrivateKey)
	p.X = big.NewInt(0)
	for k, v := range m {
		switch k {
		case "private_value(x)":
			v1, err := fromBase64([]byte(v))
			if err != nil {
				return nil, err
			}
			p.X.SetBytes(v1)
		case "created", "publish", "activate":
			/* not used in Go (yet) */
		}
	}
	return p, nil
}

func readPrivateKeyECDSA(m map[string]string) (*ecdsa.PrivateKey, error) {
	p := new(ecdsa.PrivateKey)
	p.D = big.NewInt(0)
	// TODO: validate that the required flags are present
	for k, v := range m {
		switch k {
		case "privatekey":
			v1, err := fromBase64([]byte(v))
			if err != nil {
				return nil, err
			}
			p.D.SetBytes(v1)
		case "created", "publish", "activate":
			/* not used in Go (yet) */
		}
	}
	return p, nil
}

func readPrivateKeyED25519(m map[string]string) (ed25519.PrivateKey, error) {
	var p ed25519.PrivateKey
	// TODO: validate that the required flags are present
	for k, v := range m {
		switch k {
		case "privatekey":
			p1, err := fromBase64([]byte(v))
			if err != nil {
				return nil, err
			}
			if len(p1) != ed25519.SeedSize {
				return nil, ErrPrivKey
			}
			p = ed25519.NewKeyFromSeed(p1)
		case "created", "publish", "activate":
			/* not used in Go (yet) */
		}
	}
	return p, nil
}

// parseKey reads a private key from r. It returns a map[string]string,
// with the key-value pairs, or an error when the file is not correct.
func parseKey(r io.Reader, file string) (map[string]string, error) {
	m := make(map[string]string)
	k := ""

	c := newKLexer(r)

	for l, ok := c.Next(); ok; l, ok = c.Next() {
		// It should alternate
		switch l.value {
		case zKey:
			k = l.token
		case zValue:
			if k == "" {
				return nil, &ParseError{file, "no private key seen", l}
			}
			//println("Setting", strings.ToLower(k), "to", l.token, "b")
			m[strings.ToLower(k)] = l.token
			k = ""
		}
	}

	return m, nil
}

type klexer struct {
	src *bufio.Reader

	line   int
	column int

	key bool

	eol bool // end-of-line
	eof bool // end-of-file
}

func newKLexer(r io.Reader) *klexer {
	return &klexer{
		src: bufio.NewReader(r),

		line: 1,

		key: true,
	}
}

// tokenText returns the next byte from the input
func (kl *klexer) tokenText() (byte, error) {
	c, err := kl.src.ReadByte()
	if err != nil {
		return 0, err
	}

	// delay the newline handling until the next token is delivered,
	// fixes off-by-one errors when reporting a parse error.
	if kl.eol {
		kl.line++
		kl.column = 0
		kl.eol = false
	}

	if c == '\n' {
		kl.eol = true
	} else {
		kl.column++
	}

	return c, nil
}

// klexer scans the sourcefile and returns tokens on the channel c.
func (kl *klexer) Next() (lex, bool) {
	if kl.eof {
		return lex{value: zEOF}, false
	}

	var (
		l lex

		str strings.Builder

		commt bool
	)

	x, err := kl.tokenText()
	for err == nil {
		l.line, l.column = kl.line, kl.column

		switch x {
		case ':':
			if commt {
				break
			}

			l.token = str.String()

			if kl.key {
				l.value = zKey
				kl.key = false

				// Next token is a space, eat it
				kl.tokenText()

				return l, true
			}

			l.value = zValue
		case ';':
			commt = true
		case '\n':
			if commt {
				// Reset a comment
				commt = false
			}

			kl.key = true

			l.value = zValue
			l.token = str.String()
			return l, true
		default:
			if commt {
				break
			}

			str.WriteByte(x)
		}

		x, err = kl.tokenText()
	}

	kl.eof = true

	if str.Len() > 0 {
		// Send remainder
		l.token = str.String()
		l.value = zValue
		return l, true
	}

	return lex{value: zEOF}, false
}
