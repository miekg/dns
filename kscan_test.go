// Copyright 2014 CloudFlare. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"crypto/rsa"
	"reflect"
	"testing"
)

type algorithm struct {
	name uint8
	bits int
}

func TestNewPrivateKeyECDSA(t *testing.T) {
	algorithms := []algorithm{
		algorithm{ECDSAP256SHA256, 256},
		algorithm{ECDSAP384SHA384, 384},
		algorithm{RSASHA1, 1024},
		algorithm{RSASHA256, 2048},
		// algorithm{DSA, 1024},  // TODO: STILL BROKEN!
	}

	for _, algo := range algorithms {
		key := new(DNSKEY)
		key.Hdr.Rrtype = TypeDNSKEY
		key.Hdr.Name = "miek.nl."
		key.Hdr.Class = ClassINET
		key.Hdr.Ttl = 14400
		key.Flags = 256
		key.Protocol = 3
		key.Algorithm = algo.name
		privkey, err := key.Generate(algo.bits)
		if err != nil {
			t.Fatal(err.Error())
		}

		newPrivKey, err := key.NewPrivateKey(key.PrivateKeyString(privkey))
		if err != nil {
			t.Fatal(err.Error())
		}

		switch newPrivKey := newPrivKey.(type) {
		case *rsa.PrivateKey:
			newPrivKey.Precompute()
		}

		if !reflect.DeepEqual(privkey, newPrivKey) {
			t.Errorf("[%v] Private keys differ:\n%#v\n%#v\n", AlgorithmToString[algo.name], privkey, newPrivKey)
		}
	}
}
