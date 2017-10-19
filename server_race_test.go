package dns

import (
	"net"
	"testing"
)

func TestServerStartStopRace(t *testing.T) {
	a, aaddr := newServer(HandlerFunc(func(w ResponseWriter, r *Msg) {
		w.WriteMsg(r)
	}))
	defer a.close()

	b, baddr := newServer(HandlerFunc(func(w ResponseWriter, r *Msg) {
		w.WriteMsg(r)
	}))
	defer b.close()

	m := new(Msg)
	m.SetQuestion("example.org.", TypeAAAA)
	c := new(Client)
	c.Net = "tcp"
	for i := 0; i < 10; i++ {
		c.Exchange(m, aaddr)
		c.Exchange(m, baddr)
	}
}

type server struct {
	s1 *Server
	s2 *Server
}

func newServer(f HandlerFunc) (*server, string) {
	HandleFunc(".", f)

	ch1 := make(chan bool)
	ch2 := make(chan bool)

	p, _ := net.ListenPacket("udp", ":0")
	l, _ := net.Listen("tcp", p.LocalAddr().String())

	s1 := &Server{PacketConn: p}
	s2 := &Server{Listener: l}
	s1.NotifyStartedFunc = func() { close(ch1) }
	s2.NotifyStartedFunc = func() { close(ch2) }
	go s1.ActivateAndServe()
	go s2.ActivateAndServe()

	<-ch1
	<-ch2

	return &server{s1: s1, s2: s2}, p.LocalAddr().String()
}

func (s *server) close() {
	s.s1.Shutdown()
	s.s2.Shutdown()
}
