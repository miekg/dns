package dns

import (
        "os"
        "crypto/rsa"
        "crypto/rand"
        "encoding/base64"
)


// Generate a RSA key of the given bit size.
// The public parts are directly put inside the
// DNSKEY record. The private key is returned.
func (r *RR_DNSKEY) GenerateRSA(bits int) (*rsa.PrivateKey, os.Error) {
/*
   -b <key size in bits>:
         RSAMD5:        [512..4096]
         RSASHA1:       [512..4096]
         NSEC3RSASHA1:  [512..4096]
         RSASHA256:     [512..4096]
         RSASHA512:     [1024..4096]
*/
        priv, err := rsa.GenerateKey(rand.Reader, bits)
        if err != nil {
                return nil, err
        }
        //func GenerateKey(rand io.Reader, bits int) (priv *PrivateKey, err os.Error)
        // Fill r.PubKey    string "base64"
        //priv.PublicKey.N (*big.Int) modulus
        //priv.PublicKey.E (int)      public exponent
        keybuf := make([]byte, 1)

        if priv.PublicKey.E < 256 {
                keybuf[0] = uint8(priv.PublicKey.E)
        } else {
                keybuf[0] = 0
                // keybuf[1]+[2] have the length
                // keybuf[3:..3+lenght] have exponent
                // not implemented
                return nil, &Error{Error: "Exponent to large"}
        }
        keybuf = append(keybuf, priv.PublicKey.N.Bytes()...)

        b64 := make([]byte, base64.StdEncoding.EncodedLen(len(keybuf)))
        base64.StdEncoding.Encode(b64, keybuf)
        r.PubKey = string(b64)
        return priv, nil
}
