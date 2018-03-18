package dns

import (
	"bytes"
	"io"
	"io/ioutil"
	"net/http"
)

const mime = "application/dns-udpwireformat"

// MsgToRequest wraps m in a http POST request according to the DNS over HTTPS Spec.
func MsgToRequest(m *Msg, url string) (*http.Request, error) {
	out, err := m.Pack()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", url, bytes.NewReader(out))
	req.Header.Set("Content-Type", mime)
	req.Header.Set("Accept", mime)

	return req, nil
}

// ResponseToMsg extracts a dns.Msg from the response body. The resp.Body is closed
// after this operation.
func ResponseToMsg(resp *http.Response) (*Msg, error) {
	defer resp.Body.Close()
	return msgFromReader(resp.Body)
}

// RequestToMsg extra the dns message from the request body.
func RequestToMsg(req *http.Request) (*Msg, error) {
	defer req.Body.Close()
	return msgFromReader(req.Body)
}

func msgFromReader(r io.Reader) (*Msg, error) {
	buf, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, nil

	}
	m := new(Msg)
	err = m.Unpack(buf)
	return m, err
}
