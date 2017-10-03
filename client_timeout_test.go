//+build go1.7

package dns

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestTimeout(t *testing.T) {
	// Set up a dummy UDP server that won't respond
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("unable to resolve local udp address: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer conn.Close()
	addrstr := conn.LocalAddr().String()

	// Message to send
	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeTXT)

	// Use a channel + timeout to ensure we don't get stuck if the
	// Client Timeout is not working properly
	done := make(chan struct{}, 2)

	timeout := time.Millisecond
	allowable := timeout + (10 * time.Millisecond)
	abortAfter := timeout + (100 * time.Millisecond)

	start := time.Now()

	go func() {
		c := &Client{Timeout: timeout}
		_, _, err := c.Exchange(m, addrstr)
		if err == nil {
			t.Error("no timeout using Client.Exchange")
		}
		done <- struct{}{}
	}()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		c := &Client{}
		_, _, err := c.ExchangeContext(ctx, m, addrstr)
		if err == nil {
			t.Error("no timeout using Client.ExchangeContext")
		}
		done <- struct{}{}
	}()

	// Wait for both the Exchange and ExchangeContext tests to be done.
	for i := 0; i < 2; i++ {
		select {
		case <-done:
		case <-time.After(abortAfter):
		}
	}

	length := time.Since(start)

	if length > allowable {
		t.Errorf("exchange took longer (%v) than specified Timeout (%v)", length, timeout)
	}
}
