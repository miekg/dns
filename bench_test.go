package dns

import (
	"fmt"
	"net"
	"sync"
	"testing"
)

func BenchmarkServer(b *testing.B) {
	HandleFunc(".", erraticHandler)
	defer HandleRemove(".")
	for _, workers := range []int{-1, 50, 100, 200, 1000} {
		benchmark(workers, b)
	}
}

func benchmark(workers int, b *testing.B) {
	s, addr, err := runLocalUDPServer(workers)
	if err != nil {
		b.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	m := new(Msg)
	m.SetQuestion("domain.local.", TypeA)

	conn, err := net.Dial("udp", addr)
	if err != nil {
		b.Fatalf("client Dial() failed: %v", err)
	}
	defer conn.Close()

	test := fmt.Sprintf("%d_workers", workers)
	b.Run(test, func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err = exchange(conn, m)
			if err != nil {
				b.Fatalf("exchange() failed: %v", err)
			}
		}
	})
}

var (
	rrA, _    = NewRR(". IN 0 A 192.0.2.53")
	rrAAAA, _ = NewRR(". IN 0 AAAA 2001:DB8::53")
)

func erraticHandler(w ResponseWriter, r *Msg) {
	r.Response = true

	switch r.Question[0].Qtype {
	case TypeA:
		rr := *(rrA.(*A))
		rr.Header().Name = r.Question[0].Name
		r.Answer = []RR{&rr}
		r.Rcode = RcodeSuccess
	case TypeAAAA:
		rr := *(rrAAAA.(*AAAA))
		rr.Header().Name = r.Question[0].Name
		r.Answer = []RR{&rr}
		r.Rcode = RcodeSuccess
	default:
		r.Rcode = RcodeServerFailure
	}

	w.WriteMsg(r)
}

func runLocalUDPServer(workers int) (*Server, string, error) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, "", err
	}

	var wg sync.WaitGroup
	wg.Add(1)
	server := &Server{
		PacketConn:        pc,
		NotifyStartedFunc: wg.Done,
		Workers:           workers,
	}

	go func() {
		server.ActivateAndServe()
		pc.Close()
	}()

	wg.Wait()
	return server, pc.LocalAddr().String(), nil
}

func exchange(conn net.Conn, m *Msg) (r *Msg, err error) {
	c := Conn{Conn: conn}
	if err = c.WriteMsg(m); err != nil {
		return nil, err
	}
	r, err = c.ReadMsg()
	if err == nil && r.Id != m.Id {
		err = ErrId
	}
	return r, err
}
