package dns

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"time"
)

// ExchangeContext performs a synchronous UDP query, like Exchange. It
// additionally obeys deadlines from the passed Context.
func ExchangeContext(ctx context.Context, m *Msg, a string) (r *Msg, err error) {
	println("dns: ExchangeContext: this function is deprecated")
	client := Client{Net: "udp"}
	r, _, err = client.ExchangeContext(ctx, m, a)
	// ignorint rtt to leave the original ExchangeContext API unchanged, but
	// this function will go away
	return r, err
}

// ExchangeConn performs a synchronous query. It sends the message m via the connection
// c and waits for a reply. The connection c is not closed by ExchangeConn.
// This function is going away, but can easily be mimicked:
//
//	co := &dns.Conn{Conn: c} // c is your net.Conn
//	co.WriteMsg(m)
//	in, _  := co.ReadMsg()
//	co.Close()
//
func ExchangeConn(c net.Conn, m *Msg) (r *Msg, err error) {
	println("dns: ExchangeConn: this function is deprecated")
	co := new(Conn)
	co.Conn = c
	if err = co.WriteMsg(m); err != nil {
		return nil, err
	}
	r, err = co.ReadMsg()
	if err == nil && r.Id != m.Id {
		err = ErrId
	}
	return r, err
}

// DialTimeout acts like Dial but takes a timeout.
func DialTimeout(network, address string, timeout time.Duration) (conn *Conn, err error) {
	println("dns: DialTimeout: this function is deprecated")

	client := Client{Net: "udp"}
	conn, err = client.DialWithDialer(&net.Dialer{Timeout: timeout}, address)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// DialWithTLS connects to the address on the named network with TLS.
func DialWithTLS(network, address string, tlsConfig *tls.Config) (conn *Conn, err error) {
	println("dns: DialWithTLS: this function is deprecated")
	if !strings.HasSuffix(network, "-tls") {
		network += "-tls"
	}
	client := Client{Net: network, TLSConfig: tlsConfig}
	conn, err = client.DialWithDialer(nil, address)

	if err != nil {
		return nil, err
	}
	return conn, nil
}

// DialTimeoutWithTLS acts like DialWithTLS but takes a timeout.
func DialTimeoutWithTLS(network, address string, tlsConfig *tls.Config, timeout time.Duration) (conn *Conn, err error) {
	println("dns: DialTimeoutWithTLS: this function is deprecated")
	if !strings.HasSuffix(network, "-tls") {
		network += "-tls"
	}
	client := Client{Net: network, TLSConfig: tlsConfig}
	conn, err = client.DialWithDialer(&net.Dialer{Timeout: timeout}, address)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// ExchangeContext acts like Exchange, but honors the deadline on the provided
// context, if present. If there is both a context deadline and a configured
// timeout on the client, the earliest of the two takes effect.
func (c *Client) ExchangeContext(ctx context.Context, m *Msg, a string) (r *Msg, rtt time.Duration, err error) {
	println("dns: Client.ExchangeContext: this function is deprecated")
	var timeout time.Duration
	if deadline, ok := ctx.Deadline(); !ok {
		timeout = 0
	} else {
		timeout = deadline.Sub(time.Now())
	}
	dialer := net.Dialer{Timeout: timeout}
	// not passing the context to the underlying calls, as the API does not support
	// context. For timeouts you should use a net.Dialer and call ExchangeWithDialer.
	return c.ExchangeWithDialer(&dialer, m, a)
}
