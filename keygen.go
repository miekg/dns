package dns

import (
	"os"
        "io"
	"big"
	"fmt"
        "bufio"
	"strconv"
	"crypto/rsa"
        "crypto/ecdsa"
        "crypto/elliptic"
	"crypto/rand"
)

// Empty interface that is used as a wrapper around all possible
// private key implementations from the crypto package.
type PrivateKey interface{}

// Generate a key of the given bit size.
// The public part is put inside the DNSKEY record. 
// The Algorithm in the key must be set as this will define
// what kind of DNSKEY will be generated.
func (r *RR_DNSKEY) Generate(bits int) (PrivateKey, os.Error) {
	switch r.Algorithm {
	case AlgRSAMD5, AlgRSASHA1, AlgRSASHA256:
		if bits < 512 || bits > 4096 {
			return nil, ErrKeySize
		}
	case AlgRSASHA512:
		if bits < 1024 || bits > 4096 {
			return nil, ErrKeySize
		}
	}

	switch r.Algorithm {
	case AlgRSAMD5, AlgRSASHA1, AlgRSASHA256, AlgRSASHA512:
		priv, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, err
		}
                r.setPublicKeyRSA(priv.PublicKey.E, priv.PublicKey.N)
		return priv, nil
        case AlgECDSAP256SHA256, AlgECDSAP384SHA384:
                var c *elliptic.Curve
                switch r.Algorithm {
                case AlgECDSAP256SHA256:
                        c = elliptic.P256()
                case AlgECDSAP384SHA384:
                        c = elliptic.P384()
                }
                priv, err := ecdsa.GenerateKey(c, rand.Reader)
                if err != nil {
                        return nil, err
                }
                r.setPublicKeyCurve(priv.PublicKey.X, priv.PublicKey.Y)
                return priv, nil
	default:
		return nil, ErrAlg
	}
	return nil, nil // Dummy return
}

// Convert a PrivateKey to a string. This
// string has the same format as the private-key-file of BIND9 (Private-key-format: v1.3). 
// It needs some info from the key (hashing, keytag), so its a method of the RR_DNSKEY.
func (r *RR_DNSKEY) PrivateKeyString(p PrivateKey) (s string) {
	switch t := p.(type) {
	case *rsa.PrivateKey:
		algorithm := strconv.Itoa(int(r.Algorithm)) + " (" + alg_str[r.Algorithm] + ")"
		modulus := unpackBase64(t.PublicKey.N.Bytes())
		e := big.NewInt(int64(t.PublicKey.E))
		publicExponent := unpackBase64(e.Bytes())
		privateExponent := unpackBase64(t.D.Bytes())
		prime1 := unpackBase64(t.Primes[0].Bytes())
		prime2 := unpackBase64(t.Primes[1].Bytes())
		// Calculate Exponent1/2 and Coefficient as per: http://en.wikipedia.org/wiki/RSA#Using_the_Chinese_remainder_algorithm
		// and from: http://code.google.com/p/go/issues/detail?id=987
		one := big.NewInt(1)
		minusone := big.NewInt(-1)
		p_1 := big.NewInt(0).Sub(t.Primes[0], one)
		q_1 := big.NewInt(0).Sub(t.Primes[1], one)
		exp1 := big.NewInt(0).Mod(t.D, p_1)
		exp2 := big.NewInt(0).Mod(t.D, q_1)
		coeff := big.NewInt(0).Exp(t.Primes[1], minusone, t.Primes[0])

		exponent1 := unpackBase64(exp1.Bytes())
		exponent2 := unpackBase64(exp2.Bytes())
		coefficient := unpackBase64(coeff.Bytes())

		s = "Private-key-format: v1.3\n" +
			"Algorithm: " + algorithm + "\n" +
			"Modules: " + modulus + "\n" +
			"PublicExponent: " + publicExponent + "\n" +
			"PrivateExponent: " + privateExponent + "\n" +
			"Prime1: " + prime1 + "\n" +
			"Prime2: " + prime2 + "\n" +
			"Exponent1: " + exponent1 + "\n" +
			"Exponent2: " + exponent2 + "\n" +
			"Coefficient: " + coefficient + "\n"
	}
	return
}

// Read a private key (file) string and create a public key. Return the private key.
func (k *RR_DNSKEY) ReadPrivateKey(q io.Reader) (PrivateKey, os.Error) {
	p := new(rsa.PrivateKey)
	p.Primes = []*big.Int{nil,nil}
	var left, right string
        r := bufio.NewReader(q)
	line, _, err := r.ReadLine()
	for err == nil {
		n, _ := fmt.Sscanf(string(line), "%s %s+\n", &left, &right)
		if n > 0 {
			switch left {
			case "Private-key-format:":
				if right != "v1.3" {
					return nil, ErrPrivKey
				}
			case "Algorithm:":
				a, _ := strconv.Atoi(right)
				if a == 0 {
					return nil, ErrAlg
				}
				k.Algorithm = uint8(a)
			case "Modulus:", "PublicExponent:", "PrivateExponent:", "Prime1:", "Prime2:":
				v, err := packBase64([]byte(right))
				if err != nil {
					return nil, err
				}
				if left == "Modulus:" {
					p.PublicKey.N = big.NewInt(0)
					p.PublicKey.N.SetBytes(v)
				}
				if left == "PublicExponent:" {
					i := big.NewInt(0)
					i.SetBytes(v)
					// Int64 should be large enough
					p.PublicKey.E = int(i.Int64())
				}
				if left == "PrivateExponent:" {
					p.D = big.NewInt(0)
					p.D.SetBytes(v)
				}
				if left == "Prime1:" {
					p.Primes[0] = big.NewInt(0)
					p.Primes[0].SetBytes(v)
				}
				if left == "Prime2:" {
					p.Primes[1] = big.NewInt(0)
					p.Primes[1].SetBytes(v)
				}
			case "Exponent1:", "Exponent2:", "Coefficient:":
				/* not used in Go (yet) */
			case "Created:", "Publish:", "Activate:":
				/* not used in Go (yet) */
			default:
				return nil, ErrKey
			}
		}
		line, _, err = r.ReadLine()
	}
	if ! k.setPublicKeyRSA(p.PublicKey.E, p.PublicKey.N) {
                return nil, ErrKey
        }
	return p, nil
}
