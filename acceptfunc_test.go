package dns

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestAcceptNotify(t *testing.T) {
	HandleFunc("example.org.", handleNotify)
	s, addrstr, _, err := RunLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	m := new(Msg)
	m.SetNotify("example.org.")
	// Set a SOA hint in the answer section, this is allowed according to RFC 1996.
	soa, _ := NewRR("example.org. IN SOA sns.dns.icann.org. noc.dns.icann.org. 2018112827 7200 3600 1209600 3600")
	m.Answer = []RR{soa}

	c := new(Client)
	resp, _, err := c.Exchange(m, addrstr)
	if err != nil {
		t.Errorf("failed to exchange: %v", err)
	}
	if resp.Rcode != RcodeSuccess {
		t.Errorf("expected %s, got %s", RcodeToString[RcodeSuccess], RcodeToString[resp.Rcode])
	}
}

func handleNotify(w ResponseWriter, req *Msg) {
	m := new(Msg)
	m.SetReply(req)
	w.WriteMsg(m)
}

func TestInvalidMsg(t *testing.T) {
	HandleFunc("example.org.", func(ResponseWriter, *Msg) {
		t.Fatal("the handler must not be called in any of these tests")
	})
	s, addrstr, _, err := RunLocalTCPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	s.MsgAcceptFunc = func(dh Header) MsgAcceptAction {
		switch dh.Id {
		case 0x0001:
			return MsgAccept
		case 0x0002:
			return MsgReject
		case 0x0003:
			return MsgIgnore
		case 0x0004:
			return MsgRejectNotImplemented
		default:
			t.Errorf("unexpected ID %x", dh.Id)
			return -1
		}
	}

	invalidErrors := make(chan error)
	s.MsgInvalidFunc = func(m []byte, err error) {
		invalidErrors <- err
	}

	c, err := net.Dial("tcp", addrstr)
	if err != nil {
		t.Fatalf("cannot connect to test server: %v", err)
	}

	write := func(m []byte) {
		var length [2]byte
		binary.BigEndian.PutUint16(length[:], uint16(len(m)))
		_, err := c.Write(length[:])
		if err != nil {
			t.Fatalf("length write failed: %v", err)
		}
		_, err = c.Write(m)
		if err != nil {
			t.Fatalf("content write failed: %v", err)
		}
	}

	/* Message is too short, so there is no header to accept or reject. */

	tooShortMessage := make([]byte, 11)
	tooShortMessage[1] = 0x3 // ID = 3, would be ignored if it were parsable.

	write(tooShortMessage)
	// Expect an error to be reported.
	<-invalidErrors

	/* Message is accepted but is actually invalid. */

	badMessage := make([]byte, 13)
	badMessage[1] = 0x1 // ID = 1, Accept.
	badMessage[5] = 1   // QDCOUNT = 1
	badMessage[12] = 99 // Bad question section.  Invalid!

	write(badMessage)
	// Expect an error to be reported.
	<-invalidErrors

	/* Message is rejected before it can be determined to be invalid. */

	close(invalidErrors) // A call to InvalidMsgFunc would panic due to the closed chan.

	badMessage[1] = 0x2 // ID = 2, Reject
	write(badMessage)

	badMessage[1] = 0x3 // ID = 3, Ignore
	write(badMessage)

	badMessage[1] = 0x4 // ID = 4, RejectNotImplemented
	write(badMessage)
}
