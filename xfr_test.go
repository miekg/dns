package dns

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func getXfrRRs(req *Msg) []RR {
	RRs := make([]RR, 4)
	RRs[0] = &SOA{Hdr: RR_Header{Name: "example.com.", Rrtype: TypeSOA, Class: ClassINET, Ttl: 12345},
		Ns:      "ns1.example.com.",
		Mbox:    "mbox#example.com.",
		Serial:  12345,
		Refresh: 28800,
		Retry:   7200,
		Expire:  604800,
		Minttl:  3600}
	RRs[1] = &TXT{Hdr: RR_Header{Name: req.Question[0].Name, Rrtype: TypeTXT, Class: ClassINET, Ttl: 0}, Txt: []string{"Weipeng"}}
	RRs[2] = &TXT{Hdr: RR_Header{Name: req.Question[0].Name, Rrtype: TypeTXT, Class: ClassINET, Ttl: 0}, Txt: []string{"Sun"}}
	RRs[3] = &SOA{Hdr: RR_Header{Name: "example.com.", Rrtype: TypeSOA, Class: ClassINET, Ttl: 12345},
		Ns:      "ns1.example.com.",
		Mbox:    "mbox#example.com.",
		Serial:  12345,
		Refresh: 28800,
		Retry:   7200,
		Expire:  604800,
		Minttl:  3600}
	return RRs
}

func xfrServer(w ResponseWriter, req *Msg) {

	t := new(Transfer)
	env := make(chan *Envelope)
	go t.Out(w, req, env)
	RRs := getXfrRRs(req)

	envMsg1 := new(Envelope)
	envMsg1.RR = RRs[:2]
	env <- envMsg1

	envMsg2 := new(Envelope)
	envMsg2.RR = RRs[2:]
	env <- envMsg2

	close(env)

}

func testXfr(t *testing.T, flag bool) {
	var tsigMap map[string]string
	tsigMap = make(map[string]string)
	tsigMap["example.com."] = "pRZgBrBvI4NAHZYhxmhs/Q=="

	// Start the tcp server
	HandleFunc("example.com.", xfrServer)
	defer HandleRemove("example.com.")

	waitLock := sync.Mutex{}
	server := &Server{Addr: ":0", Net: "tcp", ReadTimeout: time.Hour, WriteTimeout: time.Hour, NotifyStartedFunc: waitLock.Unlock, TsigSecret: tsigMap}
	waitLock.Lock()

	go func() {
		server.ListenAndServe()
	}()
	waitLock.Lock()

	// Xfr query
	m := new(Msg)
	m.SetQuestion("example.com.", TypeAXFR)

	// Set tsig RR or not
	if flag {
		m.SetTsig("example.com.", HmacMD5, 300, time.Now().Unix())

	}

	addr := server.Listener.Addr().String()
	transfer := new(Transfer)
	transfer.TsigSecret = tsigMap

	env, err := transfer.In(m, addr)
	if err != nil {
		t.Fatal("failed to transfer example.com", err)
	}

	var result []RR
	for msg := range env {
		if msg.Error != nil {
			t.Fatal(msg.Error)
		}
		result = append(result, msg.RR...)

	}

	// Compare input and output, check point
	RRs := getXfrRRs(m)
	if len(result) != len(RRs) {
		t.Fatal("The len of results is not correct")
	}

	for i := 0; i < len(result); i++ {
		if 0 != strings.Compare(result[i].String(), RRs[i].String()) {
			t.Fatal("Input-output is not the same")
		}

	}

	server.Shutdown()
}

func TestXfrWithNoTsig(t *testing.T) {
	testXfr(t, false)
}

func TestXfrWithTsig(t *testing.T) {
	testXfr(t, true)
}
