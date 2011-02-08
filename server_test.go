package dns

import (
	"testing"
	"net"
	"time"
)

type server int

func createpkg(id uint16, tcp bool, remove net.Addr) []byte {
	m := new(Msg)
	m.MsgHdr.Id = id
	m.MsgHdr.Authoritative = true
	m.MsgHdr.AuthenticatedData = false
	m.MsgHdr.RecursionAvailable = true
	m.MsgHdr.Response = true
	m.MsgHdr.Opcode = OpcodeQuery
	m.MsgHdr.Rcode = RcodeSuccess
	m.Question = make([]Question, 1)
	m.Question[0] = Question{"miek.nl.", TypeTXT, ClassINET}
	m.Answer = make([]RR, 1)
	t := new(RR_TXT)
	t.Hdr = RR_Header{Name: "miek.nl.", Rrtype: TypeTXT, Class: ClassINET, Ttl: 3600}
	if tcp {
		t.Txt = "Dit is iets anders TCP"
	} else {
		t.Txt = "Dit is iets anders UDP"
	}
	m.Answer[0] = t
	out, _ := m.Pack()
	return out
}

func (h *server) ReplyUDP(c *net.UDPConn, a net.Addr, in []byte) {
	inmsg := new(Msg)
	inmsg.Unpack(in)
	if inmsg.MsgHdr.Response == true {
		// Uh... answering to an response??
		// dont think so
		return
	}
	out := createpkg(inmsg.MsgHdr.Id, false, a)
	SendUDP(out, c, a)
}

func (h *server) ReplyTCP(c *net.TCPConn, in []byte) {
	inmsg := new(Msg)
	inmsg.Unpack(in)
	if inmsg.MsgHdr.Response == true {
		return
	}
	out := createpkg(inmsg.MsgHdr.Id, true, c.RemoteAddr())
	SendTCP(out, c)
}

func TestResponder(t *testing.T) {
        var h *server
        go ListenAndServeTCP("127.0.0.1:8053", h)
        go ListenAndServeUDP("127.0.0.1:8053", h)
        time.Sleep(20 * 1e9)
}

/*
type servtsig Server

func createpkgtsig(id uint16, tcp bool, remove net.Addr) []byte {
	m := new(Msg)
	m.MsgHdr.Id = id
	m.MsgHdr.Authoritative = true
	m.MsgHdr.AuthenticatedData = false
	m.MsgHdr.RecursionAvailable = true
	m.MsgHdr.Response = true
	m.MsgHdr.Opcode = OpcodeQuery
	m.MsgHdr.Rcode = RcodeSuccess
	m.Question = make([]Question, 1)
	m.Question[0] = Question{"miek.nl.", TypeTXT, ClassINET}
	m.Answer = make([]RR, 1)
	t := new(RR_TXT)
	t.Hdr = RR_Header{Name: "miek.nl.", Rrtype: TypeTXT, Class: ClassINET, Ttl: 3600}
	if tcp {
		t.Txt = "Dit is iets anders TCP"
	} else {
		t.Txt = "Dit is iets anders UDP"
	}
	m.Answer[0] = t
	out, _ := m.Pack()
	return out
}

func (s *servtsig) ResponderUDP(c *net.UDPConn, a net.Addr, in []byte) {
	inmsg := new(Msg)
	inmsg.Unpack(in)
        fmt.Printf("%v\n", inmsg)
	if inmsg.MsgHdr.Response == true {
		// Uh... answering to an response??
		// dont think so
		return
	}
        rr := inmsg.Extra[len(inmsg.Extra)-1]
        switch t := rr.(type) {
        case *RR_TSIG:
                v := t.Verify(inmsg, "awwLOtRfpGE+rRKF2+DEiw==")
                println(v)
        }


	out := createpkgtsig(inmsg.MsgHdr.Id, false, a)
	SendUDP(out, c, a)
	// Meta.QLen/RLen/QueryStart/QueryEnd can be filled in at
	// this point for logging purposses or anything else
}

func (s *servtsig) ResponderTCP(c *net.TCPConn, in []byte) {
	inmsg := new(Msg)
	inmsg.Unpack(in)
	if inmsg.MsgHdr.Response == true {
		// Uh... answering to an response??
		// dont think so
		return
	}
	out := createpkgtsig(inmsg.MsgHdr.Id, true, c.RemoteAddr())
	SendTCP(out, c)
}

func TestResponderTsig(t *testing.T) {
	su := new(Server)
	su.Address = "127.0.0.1"
	su.Port = "8053"
	var us *servtsig
	uch := make(chan os.Error)
	go su.NewResponder(us, uch)

	st := new(Server)
	st.Address = "127.0.0.1"
	st.Port = "8053"
	st.Tcp = true
	var ts *servtsig
	tch := make(chan os.Error)
	go st.NewResponder(ts, tch)
	time.Sleep(1 * 1e9)
	uch <- nil
	tch <- nil
}
*/
