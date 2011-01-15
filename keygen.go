package dns

import (
	"os"
	"crypto/rsa"
	"crypto/rand"
)

// Empty interface that is used a wrapper around all possible
// private key implementation from the crypto package.
type PrivateKey interface{}

// io.Reader
// PrivateKeyToString
// PrivateKeyFromString
// PrivateKeyToDNSKEY

// Generate a key of the given bit size.
// The public part is directly put inside the DNSKEY record. 
// The Algorithm in the key must be set as this will define
// what kind of DNSKEY will be generated.
func (r *RR_DNSKEY) Generate(bits int) (PrivateKey, os.Error) {
	switch r.Algorithm {
	case AlgRSAMD5, AlgRSASHA1, AlgRSASHA256:
		if bits < 512 || bits > 4096 {
			return nil, &Error{Error: "Size not in range [512..4096]"}
		}
	case AlgRSASHA512:
		if bits < 1024 || bits > 4096 {
			return nil, &Error{Error: "Size not in range [1024..4096]"}
		}
	default:
		return nil, &Error{Error: "Algorithm not recognized"}
        }

        switch r.Algorithm {
        case AlgRSAMD5, AlgRSASHA1, AlgRSASHA256, AlgRSASHA512:
		priv, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, err
		}
		keybuf := make([]byte, 2)

		if priv.PublicKey.E < 256 {
                        keybuf[0] = 1
			keybuf[1] = uint8(priv.PublicKey.E)
		} else {
			keybuf[0] = 0
                        //keybuf[1] = part of length
                        //keybuf[2] = rest of length
			// keybuf[1]+[2] have the length
			// keybuf[3:..3+lenght] have exponent
			// not implemented
			return nil, &Error{Error: "Exponent too large"}
		}
		keybuf = append(keybuf, priv.PublicKey.N.Bytes()...)
		r.PubKey = unpackBase64(keybuf)
		return priv, nil
	}
	return nil, nil // Dummy return
}
