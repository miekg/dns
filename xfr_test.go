package dns

import (
	"fmt"
	"testing"
)

var (
	tsigSecret = map[string]string{"axfr.": "so6ZGir4GPAqINNh9U5c3A=="}
	xfrSoa     = `miek.nl.	0	IN	SOA	linode.atoom.net. miek.miek.nl. 2009032802 21600 7200 604800 3600`
	xfrA       = `x.miek.nl.	1792	IN	A	10.0.0.1`
	xfrMX      = `miek.nl.	1800	IN	MX	1	x.miek.nl.`
	testData   = axfrZoneData()
)

func axfrZoneData() []RR {
	soa, _ := NewRR(xfrSoa)
	a, _ := NewRR(xfrA)
	mx, _ := NewRR(xfrMX)

	return []RR{soa, a, mx, soa}
}

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
	ch <- &Envelope{RR: axfrZoneData()}
	close(ch)
	w.Hijack()
}

func MultipleEnvelopeXfrServer(w ResponseWriter, req *Msg) {
	ch := make(chan *Envelope)
	tr := new(Transfer)

	go tr.Out(w, req, ch)
	records := axfrZoneData()

	for _, rr := range records {
		ch <- &Envelope{RR: []RR{rr}}
	}
	close(ch)
	w.Hijack()
}

func TestInvalidXfr(t *testing.T) {
	HandleFunc("miek.nl.", InvalidXfrServer)
	defer HandleRemove("miek.nl.")

	s, addrstr, err := RunLocalTCPServer(":0")
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

	s, addrstr, err := RunLocalTCPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %s", err)
	}
	s.TsigSecret = tsigSecret
	defer s.Shutdown()

	testCases := []struct {
		name string
		tsig map[string]string
	}{
		{"empty", nil},
		{"valid", tsigSecret},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Testing %v TSIG", tc.name), axfrTestingSuite(addrstr))
	}
}

func TestMultiEnvelopeXfr(t *testing.T) {
	HandleFunc("miek.nl.", MultipleEnvelopeXfrServer)
	defer HandleRemove("miek.nl.")

	s, addrstr, err := RunLocalTCPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %s", err)
	}
	defer s.Shutdown()

	testCases := []struct {
		name string
		tsig map[string]string
	}{
		{"empty", nil},
		{"valid", tsigSecret},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Testing %v TSIG", tc.name), axfrTestingSuite(addrstr))
	}
}

func axfrTestingSuite(addrstr string) func(*testing.T) {
	return func(t *testing.T) {
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
			for _, rr := range msg.RR {
				records = append(records, rr)
			}
		}

		if len(records) != len(testData) {
			t.Fatalf("bad axfr: expected %v, got %v", records, testData)
		}

		for i := range records {
			if records[i].String() != testData[i].String() {
				t.Fatalf("bad axfr: expected %v, got %v", records, testData)
			}
		}
	}
}
