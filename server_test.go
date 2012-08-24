package dns

import (
	"testing"
	"time"
)

func HelloServer(w ResponseWriter, req *Msg) {
	m := new(Msg)
	m.SetReply(req)

	m.Extra = make([]RR, 1)
	m.Extra[0] = &RR_TXT{Hdr: RR_Header{Name: m.Question[0].Name, Rrtype: TypeTXT, Class: ClassINET, Ttl: 0}, Txt: []string{"Hello world"}}
	w.Write(m)
}

func AnotherHelloServer(w ResponseWriter, req *Msg) {
	m := new(Msg)
	m.SetReply(req)

	m.Extra = make([]RR, 1)
	m.Extra[0] = &RR_TXT{Hdr: RR_Header{Name: m.Question[0].Name, Rrtype: TypeTXT, Class: ClassINET, Ttl: 0}, Txt: []string{"Hello example"}}
	w.Write(m)
}

func TestServing(t *testing.T) {
	HandleFunc("miek.nl.", HelloServer)
	HandleFunc("example.com.", AnotherHelloServer)
	go func() {
		err := ListenAndServe(":8053", "udp", nil)
		if err != nil {
			t.Log("ListenAndServe: ", err.Error())
			t.Fail()
		}
	}()
	time.Sleep(4e8)
	c := new(Client)
	m := new(Msg)

	m.SetQuestion("miek.nl.", TypeTXT)
	r, _ := c.Exchange(m, "127.0.0.1:8053")
	txt := r.Extra[0].(*RR_TXT).Txt[0]
	if txt != "Hello world" {
		t.Log("Unexpected result for miek.nl", txt, "!= Hello world")
		t.Fail()
	}
	m.SetQuestion("example.com.", TypeTXT)
	r, _ = c.Exchange(m, "127.0.0.1:8053")
	txt = r.Extra[0].(*RR_TXT).Txt[0]
	if txt != "Hello example" {
		t.Log("Unexpected result for example.com", txt, "!= Hello example")
		t.Fail()
	}
}

func BenchmarkServing(b *testing.B) {
	b.StopTimer()
	// Again start a server
	HandleFunc("miek.nl.", HelloServer)
	go func() {
		ListenAndServe("127.0.0.1:8053", "udp", nil)
	}()

	c := new(Client)
	m := new(Msg)
	m.SetQuestion("miek.nl", TypeSOA)

	b.StartTimer()
	for i := 0; i < b.N; i++ {
		c.Exchange(m, "127.0.0.1:8053")
	}
}
