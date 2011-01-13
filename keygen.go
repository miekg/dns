package dns

import (
        "os"
        "crypto/rsa"
        "crypto/rand"
        "encoding/base64"
)

// io.Reader
// PrivateKeyToString
// PrivateKeyFromString
// PrivateKeyToDNSKEY

// Generate a RSA key of the given bit size.
// The public part is directly put inside the DNSKEY record. 
// The Algorithm in the key must be set
func (r *RR_DNSKEY) GenerateRSA(bits int) (*rsa.PrivateKey, os.Error) {
        switch r.Algorithm {
        case AlgRSAMD5: fallthrough
        case AlgRSASHA1: fallthrough
        case AlgRSASHA256:
                if bits < 512 || bits > 4096 {
                        return nil, &Error{Error: "Size not in range [512..4096]"}
                }
        case AlgRSASHA512:
                if bits < 1024 || bits > 4096 {
                        return nil, &Error{Error: "Size not in range [1024..4096]"}
                }
        default:
                return nil, &Error{Error: "Algorithm does not match RSA*"}
        }
        priv, err := rsa.GenerateKey(rand.Reader, bits)
        if err != nil {
                return nil, err
        }
        keybuf := make([]byte, 1)

        if priv.PublicKey.E < 256 {
                keybuf[0] = uint8(priv.PublicKey.E)
        } else {
                keybuf[0] = 0
                // keybuf[1]+[2] have the length
                // keybuf[3:..3+lenght] have exponent
                // not implemented
                return nil, &Error{Error: "Exponent too large"}
        }
        keybuf = append(keybuf, priv.PublicKey.N.Bytes()...)

        b64 := make([]byte, base64.StdEncoding.EncodedLen(len(keybuf)))
        base64.StdEncoding.Encode(b64, keybuf)
        r.PubKey = string(b64)
        return priv, nil
}
