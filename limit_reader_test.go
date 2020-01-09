package dns

import (
	"net"
	"sync"
	"testing"
	"time"
)

func TestLimitReader(t *testing.T) {
	pc, err := net.ListenPacket("udp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{PacketConn: pc, ReadTimeout: time.Second * 2, WriteTimeout: time.Second * 2}
	server.DecorateReader = func(r Reader) Reader {
		return &LimitReader{Reader: r, MaxGoroutines: 0}
	}
	HandleFunc("example.org.", HelloServer)
	defer server.Shutdown()

	waitLock := sync.Mutex{}
	waitLock.Lock()
	server.NotifyStartedFunc = waitLock.Unlock

	fin := make(chan error, 1)
	go func() {
		fin <- server.ActivateAndServe()
		pc.Close()
	}()

	waitLock.Lock()

	c := new(Client)
	m := new(Msg).SetQuestion("example.org.", TypeTXT)

	r, _, _ := c.Exchange(m, pc.LocalAddr().String())
	if r.Rcode != RcodeRefused {
		t.Errorf("expected rcode %d, got %d", RcodeRefused, r.Rcode)
	}
}
