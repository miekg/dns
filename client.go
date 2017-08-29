package dns

// A client implementation.

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

const dnsTimeout time.Duration = 2 * time.Second
const tcpIdleTimeout time.Duration = 8 * time.Second

// A Conn represents a connection to a DNS server.
type Conn struct {
	net.Conn                         // a net.Conn holding the connection
	UDPSize        uint16            // minimum receive buffer for UDP messages
	TsigSecret     map[string]string // secret(s) for Tsig map[<zonename>]<base64 secret>, zonename must be fully qualified
	rtt            time.Duration
	t              time.Time
	tsigRequestMAC string
}

// A Client defines parameters for a DNS client.
type Client struct {
	Net            string            // if "tcp" or "tcp-tls" (DNS over TLS) a TCP query will be initiated, otherwise an UDP one (default is "" for UDP)
	UDPSize        uint16            // minimum receive buffer for UDP messages
	TLSConfig      *tls.Config       // TLS connection configuration
	Timeout        time.Duration     // a cumulative timeout for dial, write and read, defaults to 0 (disabled) - overrides DialTimeout, ReadTimeout, WriteTimeout when non-zero. Can be overridden with net.Dialer.Timeout (see Client.ExchangeWithDialer and Client.DialWithDialer) or context.Context.Deadline (see the deprecated ExchangeContext)
	DialTimeout    time.Duration     // net.DialTimeout, defaults to 2 seconds, or net.Dialer.Timeout if expiring earlier - overridden by Timeout when that value is non-zero
	ReadTimeout    time.Duration     // net.Conn.SetReadTimeout value for connections, defaults to 2 seconds - overridden by Timeout when that value is non-zero
	WriteTimeout   time.Duration     // net.Conn.SetWriteTimeout value for connections, defaults to 2 seconds - overridden by Timeout when that value is non-zero
	TsigSecret     map[string]string // secret(s) for Tsig map[<zonename>]<base64 secret>, zonename must be fully qualified
	SingleInflight bool              // if true suppress multiple outstanding queries for the same Qname, Qtype and Qclass
	group          singleflight
}

// msgHash is a helper function to get a unique key given the triple
// (qname, qtype, qclass) of a DNS query. This is not a cryptographic hash. This
// is going to be used to generate keys for a map of in-flight queries.
func msgHash(m *Msg) string {
	// According to RFC4343 two queries with different ASCII case are different,
	// so we are not enforcing it here
	qname := []byte(m.Question[0].Name)
	qtype := m.Question[0].Qtype
	qclass := m.Question[0].Qclass
	hash := sha256.New()
	hash.Write([]byte(fmt.Sprintf("%s/%04X/%04X", qname, qtype, qclass)))
	return fmt.Sprintf("%x", hash.Sum(nil))
}

// Exchange performs a synchronous UDP query. It sends the message m to the address
// contained in a and waits for a reply. Exchange does not retry a failed query, nor
// will it fall back to TCP in case of truncation.
// See client.Exchange for more information on setting larger buffer sizes.
func Exchange(m *Msg, a string) (r *Msg, err error) {
	client := Client{Net: "udp"}
	r, _, err = client.Exchange(m, a)
	return r, err
}

// Exchange performs a synchronous query. It sends the message m to the address
// contained in a and waits for a reply. Basic use pattern with a *dns.Client:
//
//	c := new(dns.Client)
//	in, rtt, err := c.Exchange(message, "127.0.0.1:53")
//
// Exchange does not retry a failed query, nor will it fall back to TCP in
// case of truncation.
// It is up to the caller to create a message that allows for larger responses to be
// returned. Specifically this means adding an EDNS0 OPT RR that will advertise a larger
// buffer, see SetEdns0. Messages without an OPT RR will fallback to the historic limit
// of 512 bytes.
func (c *Client) Exchange(m *Msg, a string) (r *Msg, rtt time.Duration, err error) {
	return c.ExchangeWithDialer(nil, m, a)
}

func (c *Client) dialTimeout() time.Duration {
	if c.Timeout != 0 {
		return c.Timeout
	}
	if c.DialTimeout != 0 {
		return c.DialTimeout
	}
	return dnsTimeout
}

func (c *Client) readTimeout() time.Duration {
	if c.ReadTimeout != 0 {
		return c.ReadTimeout
	}
	return dnsTimeout
}

func (c *Client) writeTimeout() time.Duration {
	if c.WriteTimeout != 0 {
		return c.WriteTimeout
	}
	return dnsTimeout
}

func (c *Client) DialWithDialer(dialer *net.Dialer, address string) (conn *Conn, err error) {
	// create a new dialer with the appropriate timeout
	var realDialer net.Dialer
	if dialer == nil {
		realDialer = net.Dialer{}
	} else {
		realDialer = net.Dialer(*dialer)
	}
	realDialer.Timeout = c.getTimeoutForRequest(dialer, c.writeTimeout())

	network := "udp"
	use_tls := false

	switch c.Net {
	case "tcp-tls":
		network = "tcp"
		use_tls = true
	case "tcp4-tls":
		network = "tcp4"
		use_tls = true
	case "tcp6-tls":
		network = "tcp6"
		use_tls = true
	default:
		if c.Net != "" {
			network = c.Net
		}
	}

	conn = new(Conn)
	if use_tls {
		conn.Conn, err = tls.DialWithDialer(&realDialer, network, address, c.TLSConfig)
	} else {
		conn.Conn, err = realDialer.Dial(network, address)
	}
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (c *Client) ExchangeWithDialer(dialer *net.Dialer, m *Msg, address string) (r *Msg, rtt time.Duration, err error) {
	if !c.SingleInflight {
		return c.exchange(dialer, m, address)
	}

	r, rtt, err, shared := c.group.Do(msgHash(m), func() (*Msg, time.Duration, error) {
		return c.exchange(dialer, m, address)
	})
	if r != nil && shared {
		r = r.Copy()
	}
	return r, rtt, err
}

func (c *Client) exchange(dialer *net.Dialer, m *Msg, a string) (r *Msg, rtt time.Duration, err error) {
	var co *Conn

	co, err = c.DialWithDialer(dialer, a)

	if err != nil {
		return nil, 0, err
	}
	defer co.Close()

	opt := m.IsEdns0()
	// If EDNS0 is used use that for size.
	if opt != nil && opt.UDPSize() >= MinMsgSize {
		co.UDPSize = opt.UDPSize()
	}
	// Otherwise use the client's configured UDP size.
	if opt == nil && c.UDPSize >= MinMsgSize {
		co.UDPSize = c.UDPSize
	}

	co.TsigSecret = c.TsigSecret
	// write with the appropriate write timeout
	co.SetWriteDeadline(time.Now().Add(c.getTimeoutForRequest(dialer, c.writeTimeout())))
	if err = co.WriteMsg(m); err != nil {
		return nil, 0, err
	}

	co.SetReadDeadline(time.Now().Add(c.getTimeoutForRequest(dialer, c.readTimeout())))
	r, err = co.ReadMsg()
	if err == nil && r.Id != m.Id {
		err = ErrId
	}
	return r, co.rtt, err
}

// ReadMsg reads a message from the connection co.
// If the received message contains a TSIG record the transaction
// signature is verified.
func (co *Conn) ReadMsg() (*Msg, error) {
	p, err := co.ReadMsgHeader(nil)
	if err != nil {
		return nil, err
	}

	m := new(Msg)
	if err := m.Unpack(p); err != nil {
		// If ErrTruncated was returned, we still want to allow the user to use
		// the message, but naively they can just check err if they don't want
		// to use a truncated message
		if err == ErrTruncated {
			return m, err
		}
		return nil, err
	}
	if t := m.IsTsig(); t != nil {
		if _, ok := co.TsigSecret[t.Hdr.Name]; !ok {
			return m, ErrSecret
		}
		// Need to work on the original message p, as that was used to calculate the tsig.
		err = TsigVerify(p, co.TsigSecret[t.Hdr.Name], co.tsigRequestMAC, false)
	}
	return m, err
}

// ReadMsgHeader reads a DNS message, parses and populates hdr (when hdr is not nil).
// Returns message as a byte slice to be parsed with Msg.Unpack later on.
// Note that error handling on the message body is not possible as only the header is parsed.
func (co *Conn) ReadMsgHeader(hdr *Header) ([]byte, error) {
	var (
		p   []byte
		n   int
		err error
	)

	switch t := co.Conn.(type) {
	case *net.TCPConn, *tls.Conn:
		r := t.(io.Reader)

		// First two bytes specify the length of the entire message.
		l, err := tcpMsgLen(r)
		if err != nil {
			return nil, err
		}
		p = make([]byte, l)
		n, err = tcpRead(r, p)
		co.rtt = time.Since(co.t)
	default:
		if co.UDPSize > MinMsgSize {
			p = make([]byte, co.UDPSize)
		} else {
			p = make([]byte, MinMsgSize)
		}
		n, err = co.Read(p)
		co.rtt = time.Since(co.t)
	}

	if err != nil {
		return nil, err
	} else if n < headerSize {
		return nil, ErrShortRead
	}

	p = p[:n]
	if hdr != nil {
		dh, _, err := unpackMsgHdr(p, 0)
		if err != nil {
			return nil, err
		}
		*hdr = dh
	}
	return p, err
}

// tcpMsgLen is a helper func to read first two bytes of stream as uint16 packet length.
func tcpMsgLen(t io.Reader) (int, error) {
	p := []byte{0, 0}
	n, err := t.Read(p)
	if err != nil {
		return 0, err
	}

	// As seen with my local router/switch, returns 1 byte on the above read,
	// resulting a a ShortRead. Just write it out (instead of loop) and read the
	// other byte.
	if n == 1 {
		n1, err := t.Read(p[1:])
		if err != nil {
			return 0, err
		}
		n += n1
	}

	if n != 2 {
		return 0, ErrShortRead
	}
	l := binary.BigEndian.Uint16(p)
	if l == 0 {
		return 0, ErrShortRead
	}
	return int(l), nil
}

// tcpRead calls TCPConn.Read enough times to fill allocated buffer.
func tcpRead(t io.Reader, p []byte) (int, error) {
	n, err := t.Read(p)
	if err != nil {
		return n, err
	}
	for n < len(p) {
		j, err := t.Read(p[n:])
		if err != nil {
			return n, err
		}
		n += j
	}
	return n, err
}

// Read implements the net.Conn read method.
func (co *Conn) Read(p []byte) (n int, err error) {
	if co.Conn == nil {
		return 0, ErrConnEmpty
	}
	if len(p) < 2 {
		return 0, io.ErrShortBuffer
	}
	switch t := co.Conn.(type) {
	case *net.TCPConn, *tls.Conn:
		r := t.(io.Reader)

		l, err := tcpMsgLen(r)
		if err != nil {
			return 0, err
		}
		if l > len(p) {
			return int(l), io.ErrShortBuffer
		}
		return tcpRead(r, p[:l])
	}
	// UDP connection
	n, err = co.Conn.Read(p)
	if err != nil {
		return n, err
	}
	return n, err
}

// WriteMsg sends a message through the connection co.
// If the message m contains a TSIG record the transaction
// signature is calculated.
func (co *Conn) WriteMsg(m *Msg) (err error) {
	var out []byte
	if t := m.IsTsig(); t != nil {
		mac := ""
		if _, ok := co.TsigSecret[t.Hdr.Name]; !ok {
			return ErrSecret
		}
		out, mac, err = TsigGenerate(m, co.TsigSecret[t.Hdr.Name], co.tsigRequestMAC, false)
		// Set for the next read, although only used in zone transfers
		co.tsigRequestMAC = mac
	} else {
		out, err = m.Pack()
	}
	if err != nil {
		return err
	}
	co.t = time.Now()
	if _, err = co.Write(out); err != nil {
		return err
	}
	return nil
}

// Write implements the net.Conn Write method.
func (co *Conn) Write(p []byte) (n int, err error) {
	switch t := co.Conn.(type) {
	case *net.TCPConn, *tls.Conn:
		w := t.(io.Writer)

		lp := len(p)
		if lp < 2 {
			return 0, io.ErrShortBuffer
		}
		if lp > MaxMsgSize {
			return 0, &Error{err: "message too large"}
		}
		l := make([]byte, 2, lp+2)
		binary.BigEndian.PutUint16(l, uint16(lp))
		p = append(l, p...)
		n, err := io.Copy(w, bytes.NewReader(p))
		return int(n), err
	}
	n, err = co.Conn.Write(p)
	return n, err
}

// Return the appropriate timeout for a specific request
func (c *Client) getTimeoutForRequest(dialer *net.Dialer, timeout time.Duration) time.Duration {
	var requestTimeout time.Duration
	if c.Timeout != 0 {
		requestTimeout = c.Timeout
	} else {
		requestTimeout = timeout
	}
	// net.Dialer.Timeout has priority if smaller than the timeouts computed so
	// far
	if dialer != nil && dialer.Timeout != 0 {
		if dialer.Timeout < requestTimeout {
			requestTimeout = dialer.Timeout
		}
	}
	return requestTimeout
}

// Dial connects to the address on the named network.
func Dial(network, address string) (conn *Conn, err error) {
	conn = new(Conn)
	conn.Conn, err = net.Dial(network, address)
	if err != nil {
		return nil, err
	}
	return conn, nil
}
