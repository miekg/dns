package dns

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

func newTsig(algo string) *Msg {
	m := new(Msg)
	m.SetQuestion("example.org.", TypeA)
	m.SetTsig("example.", algo, 300, time.Now().Unix())
	return m
}

func TestTsig(t *testing.T) {
	m := newTsig(HmacMD5)
	buf, _, err := TsigGenerate(m, "pRZgBrBvI4NAHZYhxmhs/Q==", "", false)
	if err != nil {
		t.Fatal(err)
	}
	err = TsigVerify(buf, "pRZgBrBvI4NAHZYhxmhs/Q==", "", false)
	if err != nil {
		t.Fatal(err)
	}

	// TSIG accounts for ID substitution. This means if the message ID is
	// changed by a forwarder, we should still be able to verify the TSIG.
	m = newTsig(HmacMD5)
	buf, _, err = TsigGenerate(m, "pRZgBrBvI4NAHZYhxmhs/Q==", "", false)
	if err != nil {
		t.Fatal(err)
	}

	binary.BigEndian.PutUint16(buf[0:2], 42)
	err = TsigVerify(buf, "pRZgBrBvI4NAHZYhxmhs/Q==", "", false)
	if err != nil {
		t.Fatal(err)
	}
}

func TestTsigCase(t *testing.T) {
	m := newTsig("HmAc-mD5.sig-ALg.rEg.int.") // HmacMD5
	buf, _, err := TsigGenerate(m, "pRZgBrBvI4NAHZYhxmhs/Q==", "", false)
	if err != nil {
		t.Fatal(err)
	}
	err = TsigVerify(buf, "pRZgBrBvI4NAHZYhxmhs/Q==", "", false)
	if err != nil {
		t.Fatal(err)
	}
}

const (
	// A template wire-format DNS message (in hex form) containing a TSIG RR.
	// Its time signed field will be filled by tests.
	wireMsg = "c60028000001000000010001076578616d706c6503636f6d00000600010161c00c0001000100000e100004c0000201077465" +
		"73746b65790000fa00ff00000000003d0b686d61632d73686132353600" +
		"%012x" + // placeholder for the "time signed" field
		"012c00208cf23e0081d915478a182edcea7ff48ad102948e6c7ef8e887536957d1fa5616c60000000000"
	// A secret (in base64 format) with which the TSIG in wireMsg will be validated
	testSecret        = "NoTCJU+DMqFWywaPyxSijrDEA/eC3nK0xi3AMEZuPVk="
	// the 'time signed' field value that would make the TSIG RR valid with testSecret
	timeSigned uint64 = 1594855491
)

func TestTsigErrors(t *testing.T) {
	// Helper shortcut to build wire-format test message.
	// TsigVerify can modify the slice, so we need to create a new one for each test case below.
	buildMsgData := func(tm uint64) []byte {
		msgData, err := hex.DecodeString(fmt.Sprintf(wireMsg, tm))
		if err != nil {
			t.Fatal(err)
		}
		return msgData
	}

	checkError := func(expected, actual error) {
		if actual == nil {
			t.Fatal("expected an error, but got nil")
		}
		if actual != expected {
			t.Fatalf("expected an error '%v' but got '%v'", expected, actual)
		}
	}

	// the signature is valid but 'time signed' is too far from the "current time".
	checkError(ErrTime, tsigVerify(buildMsgData(timeSigned), testSecret, "", false, timeSigned+301))
	checkError(ErrTime, tsigVerify(buildMsgData(timeSigned), testSecret, "", false, timeSigned-301))

	// the signature is invalid and 'time signed' is too far.
	// the signature should be checked first, so we should see ErrSig.
	checkError(ErrSig, tsigVerify(buildMsgData(timeSigned+301), testSecret, "", false, timeSigned))

	// tweak the algorithm name in the wire data, resulting in the "unknown algorithm" error.
	msgData := buildMsgData(timeSigned)
	copy(msgData[67:], "bogus")
	checkError(ErrKeyAlg, tsigVerify(msgData, testSecret, "", false, timeSigned))

	// call TsigVerify with a message that doesn't contain a TSIG
	msgData, _, err := stripTsig(buildMsgData(timeSigned))
	if err != nil {
		t.Fatal(err)
	}
	checkError(ErrNoSig, tsigVerify(msgData, testSecret, "", false, timeSigned))
}
