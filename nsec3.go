package dns

import (
        "crypto/sha1"
)

// NSEC3 related functions

// Hash a string/label according to RFC5155
func Nsec3Hash(label string, hash int, i iterations, salt string) {
        nsec3 := ""
        switch hash {
        case HashSHA1:
           s := sha1.New()
                // i times
                // add salt, binary???
           io.WriteString(s, string(label))
           ds.Digest = hex.EncodeToString(
        }

        return nsec3
}
