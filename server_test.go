package dns

import (
	"testing"
	"time"
)

func HelloServer(w ResponseWriter, req *Msg) {
	m := new(Msg)
	m.SetReply(req)

	m.Extra = make([]RR, 1)
	m.Extra[0] = &RR_TXT{Hdr: RR_Header{Name: m.Question[0].Name, Rrtype: TypeTXT, Class: ClassINET, Ttl: 0}, Txt: "Hello world"}
	buf, _ := m.Pack()
	w.Write(buf)
}

func TestServing(t *testing.T) {
	HandleFunc("miek.nl.", HelloServer)
	go func() {
		err := ListenAndServe(":8053", "udp", nil)
		if err != nil {
			t.Log("ListenAndServe: ", err.String())
			t.Fail()
		}
	}()
	time.Sleep(1e9)
}

func BenchmarkServing(b *testing.B) {
        b.StopTimer()
        // Again start a server
	HandleFunc("miek.nl.", HelloServer)
	go func() {
	        ListenAndServe("127.0.0.1:8053", "udp", nil)
	}()

        c := NewClient()
        m := new(Msg)
        m.SetQuestion("miek.nl", TypeSOA)

        b.StartTimer()
        for i := 0; i < b.N; i++ {
                c.Exchange(m, "127.0.0.1:8053")
                print(i, " ")
        }
}
