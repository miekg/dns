package dns

import (
	"bytes"
	"context"
	"errors"
	"io/ioutil"
	"net"
	"net/http"
	"time"
)

const dohMimeType = "application/dns-udpwireformat"

var errDOHReadBeforeWrite = errors.New("dns: ReadMsg called before WriteMsg")

type dohConn struct {
	client  *Client
	address string
	resp    chan *http.Response
}

func (c *Client) dohDial(address string) (conn *Conn, err error) {
	return &Conn{
		Conn: dohStubConn{},
		doh: &dohConn{
			client:  c,
			address: address,
			resp:    make(chan *http.Response, 1),
		},
	}, nil
}

func (co *dohConn) Write(b []byte) (err error) {
	req, err := http.NewRequest(http.MethodPost, co.address, bytes.NewReader(b))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", dohMimeType)
	req.Header.Set("Accept", dohMimeType)

	d := co.client.dialTimeout() + co.client.writeTimeout() + co.client.readTimeout()

	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()

	req = req.WithContext(ctx)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	co.resp <- resp
	return nil
}

func (co *dohConn) ReadMsgHeader(hdr *Header) ([]byte, error) {
	select {
	case resp := <-co.resp:
		defer resp.Body.Close()

		p, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		if hdr != nil {
			dh, _, err := unpackMsgHdr(p, 0)
			if err != nil {
				return nil, err
			}

			*hdr = dh
		}

		return p, nil
	default:
		return nil, errDOHReadBeforeWrite
	}
}

type dohStubConn struct{}

func (dohStubConn) Read([]byte) (n int, err error) {
	panic("dns: Read not supported for DNS-over-HTTP connections")
}

func (dohStubConn) Write([]byte) (n int, err error) {
	panic("dns: Write not supported for DNS-over-HTTP connections")
}

func (dohStubConn) Close() error { return nil }

func (dohStubConn) LocalAddr() net.Addr  { return dohStubAddr{} }
func (dohStubConn) RemoteAddr() net.Addr { return dohStubAddr{} }

func (dohStubConn) SetDeadline(time.Time) error      { return nil }
func (dohStubConn) SetReadDeadline(time.Time) error  { return nil }
func (dohStubConn) SetWriteDeadline(time.Time) error { return nil }

type dohStubAddr struct{}

func (dohStubAddr) Network() string { return "https" }
func (dohStubAddr) String() string  { return "dns-over-http" }
