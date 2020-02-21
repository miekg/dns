package dns

import (
	"encoding/base64"
	"encoding/binary"
	"testing"
	"time"
)

func newSecret(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func newTsig(algo string) *Msg {
	m := new(Msg)
	m.SetQuestion("example.org.", TypeA)
	m.SetTsig("example.", algo, 300, time.Now().Unix())
	return m
}

func TestTsig(t *testing.T) {
	secret := newSecret("pRZgBrBvI4NAHZYhxmhs/Q==")

	m := newTsig(HmacMD5)
	buf, _, err := TsigGenerate(m, secret, "", false)
	if err != nil {
		t.Fatal(err)
	}
	err = TsigVerify(buf, secret, "", false)
	if err != nil {
		t.Fatal(err)
	}

	// TSIG accounts for ID substitution. This means if the message ID is
	// changed by a forwarder, we should still be able to verify the TSIG.
	m = newTsig(HmacMD5)
	buf, _, err = TsigGenerate(m, secret, "", false)
	if err != nil {
		t.Fatal(err)
	}

	binary.BigEndian.PutUint16(buf[0:2], 42)
	err = TsigVerify(buf, secret, "", false)
	if err != nil {
		t.Fatal(err)
	}
}

func TestTsigCase(t *testing.T) {
	secret := newSecret("pRZgBrBvI4NAHZYhxmhs/Q==")

	m := newTsig("HmAc-mD5.sig-ALg.rEg.int.") // HmacMD5
	buf, _, err := TsigGenerate(m, secret, "", false)
	if err != nil {
		t.Fatal(err)
	}
	err = TsigVerify(buf, secret, "", false)
	if err != nil {
		t.Fatal(err)
	}
}
