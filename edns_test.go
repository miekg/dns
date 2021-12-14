package dns

import (
	"bytes"
	"net"
	"testing"
)

func TestOPTTtl(t *testing.T) {
	e := &OPT{}
	e.Hdr.Name = "."
	e.Hdr.Rrtype = TypeOPT

	// verify the default setting of DO=0
	if e.Do() {
		t.Errorf("DO bit should be zero")
	}

	// There are 6 possible invocations of SetDo():
	//
	// 1. Starting with DO=0, using SetDo()
	// 2. Starting with DO=0, using SetDo(true)
	// 3. Starting with DO=0, using SetDo(false)
	// 4. Starting with DO=1, using SetDo()
	// 5. Starting with DO=1, using SetDo(true)
	// 6. Starting with DO=1, using SetDo(false)

	// verify that invoking SetDo() sets DO=1 (TEST #1)
	e.SetDo()
	if !e.Do() {
		t.Errorf("DO bit should be non-zero")
	}
	// verify that using SetDo(true) works when DO=1 (TEST #5)
	e.SetDo(true)
	if !e.Do() {
		t.Errorf("DO bit should still be non-zero")
	}
	// verify that we can use SetDo(false) to set DO=0 (TEST #6)
	e.SetDo(false)
	if e.Do() {
		t.Errorf("DO bit should be zero")
	}
	// verify that if we call SetDo(false) when DO=0 that it is unchanged (TEST #3)
	e.SetDo(false)
	if e.Do() {
		t.Errorf("DO bit should still be zero")
	}
	// verify that using SetDo(true) works for DO=0 (TEST #2)
	e.SetDo(true)
	if !e.Do() {
		t.Errorf("DO bit should be non-zero")
	}
	// verify that using SetDo() works for DO=1 (TEST #4)
	e.SetDo()
	if !e.Do() {
		t.Errorf("DO bit should be non-zero")
	}

	if e.Version() != 0 {
		t.Errorf("version should be non-zero")
	}

	e.SetVersion(42)
	if e.Version() != 42 {
		t.Errorf("set 42, expected %d, got %d", 42, e.Version())
	}

	e.SetExtendedRcode(42)
	// ExtendedRcode has the last 4 bits set to 0.
	if e.ExtendedRcode() != 42&0xFFFFFFF0 {
		t.Errorf("set 42, expected %d, got %d", 42&0xFFFFFFF0, e.ExtendedRcode())
	}

	// This will reset the 8 upper bits of the extended rcode
	e.SetExtendedRcode(RcodeNotAuth)
	if e.ExtendedRcode() != 0 {
		t.Errorf("Setting a non-extended rcode is expected to set extended rcode to 0, got: %d", e.ExtendedRcode())
	}
}

func TestEDNS0_SUBNETUnpack(t *testing.T) {
	for _, ip := range []net.IP{
		net.IPv4(0xde, 0xad, 0xbe, 0xef),
		net.ParseIP("192.0.2.1"),
		net.ParseIP("2001:db8::68"),
	} {
		var s1 EDNS0_SUBNET
		s1.Address = ip

		if ip.To4() == nil {
			s1.Family = 2
			s1.SourceNetmask = net.IPv6len * 8
		} else {
			s1.Family = 1
			s1.SourceNetmask = net.IPv4len * 8
		}

		b, err := s1.pack()
		if err != nil {
			t.Fatalf("failed to pack: %v", err)
		}

		var s2 EDNS0_SUBNET
		if err := s2.unpack(b); err != nil {
			t.Fatalf("failed to unpack: %v", err)
		}

		if !ip.Equal(s2.Address) {
			t.Errorf("address different after unpacking; expected %s, got %s", ip, s2.Address)
		}
	}
}

func TestEDNS0_UL(t *testing.T) {
	cases := []struct {
		l  uint32
		kl uint32
	}{
		{0x01234567, 0},
		{0x76543210, 0xFEDCBA98},
	}
	for _, c := range cases {
		expect := EDNS0_UL{EDNS0UL, c.l, c.kl}
		b, err := expect.pack()
		if err != nil {
			t.Fatalf("failed to pack: %v", err)
		}
		actual := EDNS0_UL{EDNS0UL, ^uint32(0), ^uint32(0)}
		if err := actual.unpack(b); err != nil {
			t.Fatalf("failed to unpack: %v", err)
		}
		if expect != actual {
			t.Errorf("unpacked option is different; expected %v, got %v", expect, actual)
		}
	}
}

func TestZ(t *testing.T) {
	e := &OPT{}
	e.Hdr.Name = "."
	e.Hdr.Rrtype = TypeOPT
	e.SetVersion(8)
	e.SetDo()
	if e.Z() != 0 {
		t.Errorf("expected Z of 0, got %d", e.Z())
	}
	e.SetZ(5)
	if e.Z() != 5 {
		t.Errorf("expected Z of 5, got %d", e.Z())
	}
	e.SetZ(0xFFFF)
	if e.Z() != 0x7FFF {
		t.Errorf("expected Z of 0x7FFFF, got %d", e.Z())
	}
	if e.Version() != 8 {
		t.Errorf("expected version to still be 8, got %d", e.Version())
	}
	if !e.Do() {
		t.Error("expected DO to be set")
	}
}

func TestEDNS0_ESU(t *testing.T) {
	p := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x29, 0x04,
		0xC4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00,
		0x04, 0x00, 0x24, 0x73, 0x69, 0x70, 0x3A, 0x2B,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
		0x39, 0x40, 0x74, 0x65, 0x73, 0x74, 0x2E, 0x63,
		0x6F, 0x6D, 0x3B, 0x75, 0x73, 0x65, 0x72, 0x3D,
		0x63, 0x67, 0x72, 0x61, 0x74, 0x65, 0x73,
	}

	m := new(Msg)
	if err := m.Unpack(p); err != nil {
		t.Fatalf("failed to unpack: %v", err)
	}
	opt := m.IsEdns0()
	if opt == nil {
		t.Fatalf("expected edns0 option")
	}
	if len(opt.Option) != 1 {
		t.Fatalf("expected only one option: %v", opt.Option)
	}
	edns0 := opt.Option[0]
	esu, ok := edns0.(*EDNS0_ESU)
	if !ok {
		t.Fatalf("expected option of type EDNS0_ESU, got %t", edns0)
	}
	expect := "sip:+123456789@test.com;user=cgrates"
	if esu.Uri != expect {
		t.Errorf("unpacked option is different; expected %v, got %v", expect, esu.Uri)
	}
}

func TestEDNS0_TCP_KEEPALIVE_unpack(t *testing.T) {
	cases := []struct {
		name        string
		b           []byte
		expected    uint16
		expectedErr bool
	}{
		{
			name:     "empty",
			b:        []byte{},
			expected: 0,
		},
		{
			name:     "timeout 1",
			b:        []byte{0, 1},
			expected: 1,
		},
		{
			name:        "invalid",
			b:           []byte{0, 1, 3},
			expectedErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := &EDNS0_TCP_KEEPALIVE{}
			err := e.unpack(tc.b)
			if err != nil && !tc.expectedErr {
				t.Error("failed to unpack, expected no error")
			}
			if err == nil && tc.expectedErr {
				t.Error("unpacked, but expected an error")
			}
			if e.Timeout != tc.expected {
				t.Errorf("invalid timeout, actual: %d, expected: %d", e.Timeout, tc.expected)
			}
		})
	}
}

func TestEDNS0_TCP_KEEPALIVE_pack(t *testing.T) {
	cases := []struct {
		name     string
		edns     *EDNS0_TCP_KEEPALIVE
		expected []byte
	}{
		{
			name: "empty",
			edns: &EDNS0_TCP_KEEPALIVE{
				Code:    EDNS0TCPKEEPALIVE,
				Timeout: 0,
			},
			expected: nil,
		},
		{
			name: "timeout 1",
			edns: &EDNS0_TCP_KEEPALIVE{
				Code:    EDNS0TCPKEEPALIVE,
				Timeout: 1,
			},
			expected: []byte{0, 1},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := tc.edns.pack()
			if err != nil {
				t.Error("expected no error")
			}

			if tc.expected == nil && b != nil {
				t.Errorf("invalid result, expected nil")
			}

			res := bytes.Compare(b, tc.expected)
			if res != 0 {
				t.Errorf("invalid result, expected: %v, actual: %v", tc.expected, b)
			}
		})
	}
}
