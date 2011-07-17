package dns

import (
	"os"
        "io"
	"big"
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
// For ECDSA the algorithms implies a keysize, in that case
// bits should be zero.
func (r *RR_DNSKEY) Generate(bits int) (PrivateKey, os.Error) {
	switch r.Algorithm {
	case RSAMD5, RSASHA1, RSASHA256:
		if bits < 512 || bits > 4096 {
			return nil, ErrKeySize
		}
	case RSASHA512:
		if bits < 1024 || bits > 4096 {
			return nil, ErrKeySize
		}
        case ECDSAP256SHA256:
                if bits != 256 {
                        return nil, ErrKeySize
                }
        case ECDSAP384SHA384:
                if bits != 384 {
                        return nil, ErrKeySize
                }
	}

	switch r.Algorithm {
	case RSAMD5, RSASHA1, RSASHA256, RSASHA512:
		priv, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, err
		}
                r.setPublicKeyRSA(priv.PublicKey.E, priv.PublicKey.N)
		return priv, nil
        case ECDSAP256SHA256, ECDSAP384SHA384:
                var c *elliptic.Curve
                switch r.Algorithm {
                case ECDSAP256SHA256:
                        c = elliptic.P256()
                case ECDSAP384SHA384:
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
        case *ecdsa.PrivateKey:
                //
	}
	return
}

func (k *RR_DNSKEY) Read(q io.Reader) os.Error {
        r, e := Zparse(q)
        if e != nil || r == nil {
                return e
        }
        if _, ok := r.(*RR_DNSKEY); !ok {
                panic("did not read a DNSKEY")
        }
        k1 := r.(*RR_DNSKEY)
        k.Hdr = k1.Hdr
        k.Flags = k1.Flags
        k.Protocol = k1.Protocol
        k.Algorithm = k1.Algorithm
        k.PublicKey = k1.PublicKey
        return nil
}

func (k *RR_DNSKEY) ReadPrivateKey(q io.Reader) (PrivateKey, os.Error) {
        kv, _ := Kparse(q)
        if _, ok := kv["private-key-format"]; !ok {
                return nil, ErrPrivKey
        }
        if kv["private-key-format"] != "v1.2" && kv["private-key-format"] != "v1.3" {
                return nil, ErrPrivKey
        }
        switch kv["algorithm"] {
        case "RSAMD5", "RSASHA1", "RSASHA256", "RSASHA512":
                return k.readPrivateKeyRSA(kv)
        case "ECDSAP256SHA256", "ECDSAP384SHA384":
                return k.readPrivateKeyECDSA(kv)
        }
	return nil, ErrPrivKey
}

// Read a private key (file) string and create a public key. Return the private key.
func (k *RR_DNSKEY) readPrivateKeyRSA(kv map[string]string) (PrivateKey, os.Error) {
	p := new(rsa.PrivateKey)
	p.Primes = []*big.Int{nil,nil}
        for k, v := range kv {
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

func (k *RR_DNSKEY) readPrivateKeyECDSA(kv map[string]string) (PrivateKey, os.Error) {
	p := new(ecdsa.PrivateKey)
	p.D = big.NewInt(0)
        // Need to check if we have everything
        for k, v := range kv {
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
