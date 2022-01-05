package dns

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"testing"
	"time"
)

const (
	tsigName  = "axfr."
	tsigFudge = 300
)

var (
	tsigSecret  = map[string]string{tsigName: "so6ZGir4GPAqINNh9U5c3A=="}
	xfrSoa      = testRR(`miek.nl.	0	IN	SOA	linode.atoom.net. miek.miek.nl. 2009032802 21600 7200 604800 3600`)
	xfrA        = testRR(`x.miek.nl.	1792	IN	A	10.0.0.1`)
	xfrMX       = testRR(`miek.nl.	1800	IN	MX	1	x.miek.nl.`)
	xfrTestData = []RR{xfrSoa, xfrA, xfrMX, xfrSoa}
)

func InvalidXfrServer(w ResponseWriter, req *Msg) {
	ch := make(chan *Envelope)
	tr := new(Transfer)

	go tr.Out(w, req, ch)
	ch <- &Envelope{RR: []RR{}}
	close(ch)
	w.Hijack()
}

func SingleEnvelopeXfrServer(w ResponseWriter, req *Msg) {
	ch := make(chan *Envelope)
	tr := new(Transfer)

	go tr.Out(w, req, ch)
	ch <- &Envelope{RR: xfrTestData}
	close(ch)
	w.Hijack()
}

func MultipleEnvelopeXfrServer(w ResponseWriter, req *Msg) {
	ch := make(chan *Envelope)
	tr := new(Transfer)

	go tr.Out(w, req, ch)

	for _, rr := range xfrTestData {
		ch <- &Envelope{RR: []RR{rr}}
	}
	close(ch)
	w.Hijack()
}

func TestInvalidXfr(t *testing.T) {
	HandleFunc("miek.nl.", InvalidXfrServer)
	defer HandleRemove("miek.nl.")

	s, addrstr, _, err := RunLocalTCPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %s", err)
	}
	defer s.Shutdown()

	tr := new(Transfer)
	m := new(Msg)
	m.SetAxfr("miek.nl.")

	c, err := tr.In(m, addrstr)
	if err != nil {
		t.Fatal("failed to zone transfer in", err)
	}

	for msg := range c {
		if msg.Error == nil {
			t.Fatal("failed to catch 'no SOA' error")
		}
	}
}

func TestSingleEnvelopeXfr(t *testing.T) {
	HandleFunc("miek.nl.", SingleEnvelopeXfrServer)
	defer HandleRemove("miek.nl.")

	s, addrstr, _, err := RunLocalTCPServer(":0", func(srv *Server) {
		srv.TsigSecret = tsigSecret
	})
	if err != nil {
		t.Fatalf("unable to run test server: %s", err)
	}
	defer s.Shutdown()

	axfrTestingSuite(t, addrstr)
}

func TestMultiEnvelopeXfr(t *testing.T) {
	HandleFunc("miek.nl.", MultipleEnvelopeXfrServer)
	defer HandleRemove("miek.nl.")

	s, addrstr, _, err := RunLocalTCPServer(":0", func(srv *Server) {
		srv.TsigSecret = tsigSecret
	})
	if err != nil {
		t.Fatalf("unable to run test server: %s", err)
	}
	defer s.Shutdown()

	axfrTestingSuite(t, addrstr)
}

func axfrTestingSuite(t *testing.T, addrstr string) {
	tr := new(Transfer)
	m := new(Msg)
	m.SetAxfr("miek.nl.")

	c, err := tr.In(m, addrstr)
	if err != nil {
		t.Fatal("failed to zone transfer in", err)
	}

	var records []RR
	for msg := range c {
		if msg.Error != nil {
			t.Fatal(msg.Error)
		}
		records = append(records, msg.RR...)
	}

	if len(records) != len(xfrTestData) {
		t.Fatalf("bad axfr: expected %v, got %v", records, xfrTestData)
	}

	for i, rr := range records {
		if !IsDuplicate(rr, xfrTestData[i]) {
			t.Fatalf("bad axfr: expected %v, got %v", records, xfrTestData)
		}
	}
}

func axfrTestingSuiteWithCustomTsig(t *testing.T, addrstr string, provider TsigProvider, tsigSecret map[string]string) {
	tr := new(Transfer)
	m := new(Msg)
	var err error
	tr.Conn, err = Dial("tcp", addrstr)
	if err != nil {
		t.Fatal("failed to dial", err)
	}
	tr.Conn.TsigProvider = provider
	tr.TsigSecret = tsigSecret
	m.SetAxfr("miek.nl.")
	m.SetTsig(tsigName, HmacSHA256, tsigFudge, time.Now().Unix())

	c, err := tr.In(m, addrstr)
	if err != nil {
		t.Fatal("failed to zone transfer in", err)
	}

	var records []RR
	for msg := range c {
		if msg.Error != nil {
			t.Fatal(msg.Error)
		}
		records = append(records, msg.RR...)
	}

	if len(records) != len(xfrTestData) {
		t.Fatalf("bad axfr: expected %v, got %v", records, xfrTestData)
	}

	for i, rr := range records {
		if !IsDuplicate(rr, xfrTestData[i]) {
			t.Fatalf("bad axfr: expected %v, got %v", records, xfrTestData)
		}
	}
}

func TestCustomTsigProvider(t *testing.T) {
	HandleFunc("miek.nl.", SingleEnvelopeXfrServer)
	defer HandleRemove("miek.nl.")

	s, addrstr, _, err := RunLocalTCPServer(":0", func(srv *Server) {
		srv.TsigSecret = tsigSecret
	})
	if err != nil {
		t.Fatalf("unable to run test server: %s", err)
	}
	defer s.Shutdown()

	axfrTestingSuiteWithCustomTsig(t, addrstr, tsigMockHMACProvider(tsigSecret["axfr."]), tsigSecret)
}

type tsigMockHMACProvider string

func (key tsigMockHMACProvider) Generate(msg []byte, t *TSIG) ([]byte, error) {
	// If we barf here, the caller is to blame
	rawsecret, err := fromBase64([]byte(key))
	if err != nil {
		return nil, err
	}
	var h hash.Hash
	switch CanonicalName(t.Algorithm) {
	case HmacSHA1:
		h = hmac.New(sha1.New, rawsecret)
	case HmacSHA224:
		h = hmac.New(sha256.New224, rawsecret)
		// Deprecated
	case HmacMD5:
		h = hmac.New(md5.New, rawsecret)
	case HmacSHA256:
		h = hmac.New(sha256.New, rawsecret)
	case HmacSHA384:
		h = hmac.New(sha512.New384, rawsecret)
	case HmacSHA512:
		h = hmac.New(sha512.New, rawsecret)
	default:
		return nil, ErrKeyAlg
	}
	h.Write(msg)
	return h.Sum(nil), nil
}

func (key tsigMockHMACProvider) Verify(msg []byte, t *TSIG) error {
	b, err := key.Generate(msg, t)
	if err != nil {
		return err
	}
	mac, err := hex.DecodeString(t.MAC)
	if err != nil {
		return err
	}
	if !hmac.Equal(b, mac) {
		return ErrSig
	}
	return nil
}
