package dns

import (
	"fmt"
	"testing"
	"time"
)

var (
	tsigSecret  = map[string]string{"axfr.": "so6ZGir4GPAqINNh9U5c3A=="}
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

	axfrTestingSuite(t, addrstr, nil, nil)
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

	axfrTestingSuite(t, addrstr, nil, nil)
}

func TestMultiEnvelopeXfrDuplicateTsigNames(t *testing.T) {
	HandleFunc("miek.nl.", MultipleEnvelopeXfrServer)
	defer HandleRemove("miek.nl.")

	s, addrstr, _, err := RunLocalTCPServer(":0", func(srv *Server) {
		srv.TsigKeyNameBuilder = func(t *TSIG, m *Msg) string {
			return fmt.Sprintf("%s%s", t.Hdr.Name, m.Question[0].Name)
		}
		srv.TsigSecret = map[string]string{"axfr.miek.nl.": "so6ZGir4GPAqINNh9U5c3A==", "axfr.example.com.": "bo6ZGir4GPAqINNh9U5c3A=="}
	})
	if err != nil {
		t.Fatalf("unable to run test server: %s", err)
	}
	defer s.Shutdown()

	// The client shouldn't have to alter the tsig name
	clientTsigSecret := map[string]string{"axfr.": "so6ZGir4GPAqINNh9U5c3A=="}
	tsig := &TSIG{Hdr: RR_Header{Name: "axfr."}, Algorithm: "hmac-sha256.", Fudge: 300}

	axfrTestingSuite(t, addrstr, clientTsigSecret, tsig)
}

func axfrTestingSuite(t *testing.T, addrstr string, tsigSecret map[string]string, tsig *TSIG) {
	tr := new(Transfer)
	if tsigSecret != nil {
		tr.TsigSecret = tsigSecret
	}
	m := new(Msg)
	m.SetAxfr("miek.nl.")
	if tsig != nil {
		m.SetTsig(tsig.Hdr.Name, tsig.Algorithm, tsig.Fudge, time.Now().Unix())
	}

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
