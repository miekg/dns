// +build go1.6,!go1.7

package dns

import (
	"net"
	"time"

	"golang.org/x/net/context"
)

// ExchangeContext performs a synchronous UDP query, like Exchange. It
// additionally obeys deadlines from the passed Context.
func ExchangeContext(ctx context.Context, m *Msg, a string) (r *Msg, err error) {
	client := Client{Net: "udp"}
	r, _, err = client.ExchangeContext(ctx, m, a)
	// ignorint rtt to leave the original ExchangeContext API unchanged, but
	// this function will go away
	return r, err
}

// ExchangeContext acts like Exchange, but honors the deadline on the provided
// context, if present. If there is both a context deadline and a configured
// timeout on the client, the earliest of the two takes effect.
func (c *Client) ExchangeContext(ctx context.Context, m *Msg, a string) (r *Msg, rtt time.Duration, err error) {
	var timeout time.Duration
	if deadline, ok := ctx.Deadline(); !ok {
		timeout = 0
	} else {
		timeout = deadline.Sub(time.Now())
	}
	// not passing the context to the underlying calls, as the API does not support
	// context. For timeouts you should set up Client.Dialer and call Client.Exchange.
	c.Dialer = &net.Dialer{Timeout: timeout}
	return c.Exchange(m, a)
}
