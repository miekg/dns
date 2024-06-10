package dns

import (
	"bytes"
	"net"
	"testing"
)

// TestPacketDataNsec tests generated using fuzz.go and with a message pack
// containing the following bytes: 0000\x00\x00000000\x00\x002000000\x0060000\x00\x130000000000000000000"
// That bytes sequence created the overflow error and further permutations of that sequence were able to trigger
// the other code paths.
func TestPackDataNsec(t *testing.T) {
	type args struct {
		bitmap []uint16
		msg    []byte
		off    int
	}
	tests := []struct {
		name       string
		args       args
		wantOff    int
		wantBytes  []byte
		wantErr    bool
		wantErrMsg string
	}{
		{
			name: "overflow",
			args: args{
				bitmap: []uint16{
					8962, 8963, 8970, 8971, 8978, 8979,
					8986, 8987, 8994, 8995, 9002, 9003,
					9010, 9011, 9018, 9019, 9026, 9027,
					9034, 9035, 9042, 9043, 9050, 9051,
					9058, 9059, 9066,
				},
				msg: []byte{
					48, 48, 48, 48, 0, 0, 0,
					1, 0, 0, 0, 0, 0, 0, 50,
					48, 48, 48, 48, 48, 48,
					0, 54, 48, 48, 48, 48,
					0, 19, 48, 48,
				},
				off: 48,
			},
			wantErr:    true,
			wantErrMsg: "dns: overflow packing nsec",
			wantOff:    48,
		},
		{
			name: "disordered nsec bits",
			args: args{
				bitmap: []uint16{
					8962,
					1,
				},
				msg: []byte{
					48, 48, 48, 48, 0, 0, 0, 1, 0, 0, 0, 0,
					0, 0, 50, 48, 48, 48, 48, 48, 48, 0, 54, 48,
					48, 48, 48, 0, 19, 48, 48, 48, 48, 48, 48, 0,
					0, 0, 1, 0, 0, 0, 0, 0, 0, 50, 48, 48,
					48, 48, 48, 48, 0, 54, 48, 48, 48, 48, 0, 19,
					48, 48, 48, 48, 48, 48, 0, 0, 0, 1, 0, 0,
					0, 0, 0, 0, 50, 48, 48, 48, 48, 48, 48, 0,
					54, 48, 48, 48, 48, 0, 19, 48, 48, 48, 48, 48,
					48, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 50,
					48, 48, 48, 48, 48, 48, 0, 54, 48, 48, 48, 48,
					0, 19, 48, 48, 48, 48, 48, 48, 0, 0, 0, 1,
					0, 0, 0, 0, 0, 0, 50, 48, 48, 48, 48, 48,
					48, 0, 54, 48, 48, 48, 48, 0, 19, 48, 48,
				},
				off: 0,
			},
			wantErr:    true,
			wantErrMsg: "dns: nsec bits out of order",
			wantOff:    155,
		},
		{
			name: "simple message with only one window",
			args: args{
				bitmap: []uint16{
					1,
				},
				msg: []byte{
					48, 48, 48, 48, 0, 0,
					0, 1, 0, 0, 0, 0,
					0, 0, 50, 48, 48, 48,
					48, 48, 48, 0, 54, 48,
					48, 48, 48, 0, 19, 48, 48,
				},
				off: 0,
			},
			wantErr:   false,
			wantOff:   3,
			wantBytes: []byte{0, 1, 64},
		},
		{
			name: "multiple types",
			args: args{
				bitmap: []uint16{
					TypeNS, TypeSOA, TypeRRSIG, TypeDNSKEY, TypeNSEC3PARAM,
				},
				msg: []byte{
					48, 48, 48, 48, 0, 0,
					0, 1, 0, 0, 0, 0,
					0, 0, 50, 48, 48, 48,
					48, 48, 48, 0, 54, 48,
					48, 48, 48, 0, 19, 48, 48,
				},
				off: 0,
			},
			wantErr:   false,
			wantOff:   9,
			wantBytes: []byte{0, 7, 34, 0, 0, 0, 0, 2, 144},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotOff, err := packDataNsec(tt.args.bitmap, tt.args.msg, tt.args.off)
			if (err != nil) != tt.wantErr {
				t.Errorf("packDataNsec() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.wantErrMsg != err.Error() {
				t.Errorf("packDataNsec() error msg = %v, wantErrMsg %v", err.Error(), tt.wantErrMsg)
				return
			}
			if gotOff != tt.wantOff {
				t.Errorf("packDataNsec() = %v, want off %v", gotOff, tt.wantOff)
			}
			if err == nil && tt.args.off < len(tt.args.msg) && gotOff < len(tt.args.msg) {
				if want, got := tt.wantBytes, tt.args.msg[tt.args.off:gotOff]; !bytes.Equal(got, want) {
					t.Errorf("packDataNsec() = %v, want bytes %v", got, want)
				}
			}
		})
	}
}

func TestPackDataNsecDirtyBuffer(t *testing.T) {
	zeroBuf := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0}
	dirtyBuf := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}
	off1, _ := packDataNsec([]uint16{TypeNS, TypeSOA, TypeRRSIG}, zeroBuf, 0)
	off2, _ := packDataNsec([]uint16{TypeNS, TypeSOA, TypeRRSIG}, dirtyBuf, 0)
	if off1 != off2 {
		t.Errorf("off1 %v != off2 %v", off1, off2)
	}
	if !bytes.Equal(zeroBuf[:off1], dirtyBuf[:off2]) {
		t.Errorf("dirty buffer differs from zero buffer: %v, %v", zeroBuf[:off1], dirtyBuf[:off2])
	}
}

func BenchmarkPackDataNsec(b *testing.B) {
	benches := []struct {
		name  string
		types []uint16
	}{
		{"empty", nil},
		{"typical", []uint16{TypeNS, TypeSOA, TypeRRSIG, TypeDNSKEY, TypeNSEC3PARAM}},
		{"multiple_windows", []uint16{1, 300, 350, 10000, 20000}},
	}
	for _, bb := range benches {
		b.Run(bb.name, func(b *testing.B) {
			buf := make([]byte, 100)
			for n := 0; n < b.N; n++ {
				packDataNsec(bb.types, buf, 0)
			}
		})
	}
}
func TestUnpackString(t *testing.T) {
	msg := []byte("\x00abcdef\x0f\\\"ghi\x04mmm\x7f")
	msg[0] = byte(len(msg) - 1)

	got, _, err := unpackString(msg, 0)
	if err != nil {
		t.Fatal(err)
	}

	if want := `abcdef\015\\\"ghi\004mmm\127`; want != got {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func BenchmarkUnpackString(b *testing.B) {
	b.Run("Escaped", func(b *testing.B) {
		msg := []byte("\x00abcdef\x0f\\\"ghi\x04mmm")
		msg[0] = byte(len(msg) - 1)

		for n := 0; n < b.N; n++ {
			got, _, err := unpackString(msg, 0)
			if err != nil {
				b.Fatal(err)
			}

			if want := `abcdef\015\\\"ghi\004mmm`; want != got {
				b.Errorf("expected %q, got %q", want, got)
			}
		}
	})
	b.Run("Unescaped", func(b *testing.B) {
		msg := []byte("\x00large.example.com")
		msg[0] = byte(len(msg) - 1)

		for n := 0; n < b.N; n++ {
			got, _, err := unpackString(msg, 0)
			if err != nil {
				b.Fatal(err)
			}

			if want := "large.example.com"; want != got {
				b.Errorf("expected %q, got %q", want, got)
			}
		}
	})
}

func TestPackDataAplPrefix(t *testing.T) {
	tests := []struct {
		name     string
		negation bool
		ip       net.IP
		mask     net.IPMask
		expect   []byte
	}{
		{
			"1:192.0.2.0/24",
			false,
			net.ParseIP("192.0.2.0").To4(),
			net.CIDRMask(24, 32),
			[]byte{0x00, 0x01, 0x18, 0x03, 192, 0, 2},
		},
		{
			"2:2001:db8:cafe::0/48",
			false,
			net.ParseIP("2001:db8:cafe::"),
			net.CIDRMask(48, 128),
			[]byte{0x00, 0x02, 0x30, 0x06, 0x20, 0x01, 0x0d, 0xb8, 0xca, 0xfe},
		},
		{
			"with trailing zero bytes 2:2001:db8:cafe::0/64",
			false,
			net.ParseIP("2001:db8:cafe::"),
			net.CIDRMask(64, 128),
			[]byte{0x00, 0x02, 0x40, 0x06, 0x20, 0x01, 0x0d, 0xb8, 0xca, 0xfe},
		},
		{
			"no non-zero bytes 2::/16",
			false,
			net.ParseIP("::"),
			net.CIDRMask(16, 128),
			[]byte{0x00, 0x02, 0x10, 0x00},
		},
		{
			"!2:2001:db8::/32",
			true,
			net.ParseIP("2001:db8::"),
			net.CIDRMask(32, 128),
			[]byte{0x00, 0x02, 0x20, 0x84, 0x20, 0x01, 0x0d, 0xb8},
		},
		{
			"normalize 1:198.51.103.255/22",
			false,
			net.ParseIP("198.51.103.255").To4(),
			net.CIDRMask(22, 32),
			[]byte{0x00, 0x01, 0x16, 0x03, 198, 51, 100}, // 1:198.51.100.0/22
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ap := &APLPrefix{
				Negation: tt.negation,
				Network:  net.IPNet{IP: tt.ip, Mask: tt.mask},
			}
			out := make([]byte, 16)
			off, err := packDataAplPrefix(ap, out, 0)
			if err != nil {
				t.Fatalf("expected no error, got %q", err)
			}
			if !bytes.Equal(tt.expect, out[:off]) {
				t.Fatalf("expected output %02x, got %02x", tt.expect, out[:off])
			}
			// Make sure the packed bytes would be accepted by its own unpack
			_, _, err = unpackDataAplPrefix(out, 0)
			if err != nil {
				t.Fatalf("expected no error, got %q", err)
			}
		})
	}
}

func TestPackDataAplPrefix_Failures(t *testing.T) {
	tests := []struct {
		name string
		ip   net.IP
		mask net.IPMask
	}{
		{
			"family mismatch",
			net.ParseIP("2001:db8::"),
			net.CIDRMask(24, 32),
		},
		{
			"unrecognized family",
			[]byte{0x42},
			[]byte{0xff},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ap := &APLPrefix{Network: net.IPNet{IP: tt.ip, Mask: tt.mask}}
			msg := make([]byte, 16)
			off, err := packDataAplPrefix(ap, msg, 0)
			if err == nil {
				t.Fatal("expected error, got none")
			}
			if off != len(msg) {
				t.Fatalf("expected %d, got %d", len(msg), off)
			}
		})
	}
}

func TestPackDataAplPrefix_BufferBounds(t *testing.T) {
	ap := &APLPrefix{
		Negation: false,
		Network: net.IPNet{
			IP:   net.ParseIP("2001:db8::"),
			Mask: net.CIDRMask(32, 128),
		},
	}
	wire := []byte{0x00, 0x02, 0x20, 0x04, 0x20, 0x01, 0x0d, 0xb8}

	t.Run("small", func(t *testing.T) {
		msg := make([]byte, len(wire))
		_, err := packDataAplPrefix(ap, msg, 1) // offset
		if err == nil {
			t.Fatal("expected error, got none")
		}
	})

	t.Run("exact fit", func(t *testing.T) {
		msg := make([]byte, len(wire))
		off, err := packDataAplPrefix(ap, msg, 0)
		if err != nil {
			t.Fatalf("expected no error, got %q", err)
		}
		if !bytes.Equal(wire, msg[:off]) {
			t.Fatalf("expected %02x, got %02x", wire, msg[:off])
		}
	})
}

func TestPackDataApl(t *testing.T) {
	in := []APLPrefix{
		{
			Negation: true,
			Network: net.IPNet{
				IP:   net.ParseIP("198.51.0.0").To4(),
				Mask: net.CIDRMask(16, 32),
			},
		},
		{
			Negation: false,
			Network: net.IPNet{
				IP:   net.ParseIP("2001:db8:beef::"),
				Mask: net.CIDRMask(48, 128),
			},
		},
	}
	expect := []byte{
		// 1:192.51.0.0/16
		0x00, 0x01, 0x10, 0x82, 0xc6, 0x33,
		// 2:2001:db8:beef::0/48
		0x00, 0x02, 0x30, 0x06, 0x20, 0x01, 0x0d, 0xb8, 0xbe, 0xef,
	}

	msg := make([]byte, 32)
	off, err := packDataApl(in, msg, 0)
	if err != nil {
		t.Fatalf("expected no error, got %q", err)
	}
	if !bytes.Equal(expect, msg[:off]) {
		t.Fatalf("expected %02x, got %02x", expect, msg[:off])
	}
}

func TestUnpackDataAplPrefix(t *testing.T) {
	tests := []struct {
		name     string
		wire     []byte
		negation bool
		ip       net.IP
		mask     net.IPMask
	}{
		{
			"1:192.0.2.0/24",
			[]byte{0x00, 0x01, 0x18, 0x03, 192, 0, 2},
			false,
			net.ParseIP("192.0.2.0").To4(),
			net.CIDRMask(24, 32),
		},
		{
			"2:2001:db8::/32",
			[]byte{0x00, 0x02, 0x20, 0x04, 0x20, 0x01, 0x0d, 0xb8},
			false,
			net.ParseIP("2001:db8::"),
			net.CIDRMask(32, 128),
		},
		{
			"!2:2001:db8:8000::/33",
			[]byte{0x00, 0x02, 0x21, 0x85, 0x20, 0x01, 0x0d, 0xb8, 0x80},
			true,
			net.ParseIP("2001:db8:8000::"),
			net.CIDRMask(33, 128),
		},
		{
			"1:0.0.0.0/0",
			[]byte{0x00, 0x01, 0x00, 0x00},
			false,
			net.ParseIP("0.0.0.0").To4(),
			net.CIDRMask(0, 32),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, off, err := unpackDataAplPrefix(tt.wire, 0)
			if err != nil {
				t.Fatalf("expected no error, got %q", err)
			}
			if off != len(tt.wire) {
				t.Fatalf("expected offset %d, got %d", len(tt.wire), off)
			}
			if got.Negation != tt.negation {
				t.Errorf("expected negation %v, got %v", tt.negation, got.Negation)
			}
			if !tt.ip.Equal(got.Network.IP) {
				t.Errorf("expected IP %02x, got %02x", tt.ip, got.Network.IP)
			}
			if !bytes.Equal(got.Network.Mask, tt.mask) {
				t.Errorf("expected mask %02x, got %02x", tt.mask, got.Network.Mask)
			}
		})
	}
}

func TestUnpackDataAplPrefix_Errors(t *testing.T) {
	tests := []struct {
		name string
		wire []byte
		want string
	}{
		{
			"incomplete header",
			[]byte{0x00, 0x01, 0x18},
			"dns: overflow unpacking APL prefix",
		},
		{
			"unrecognized family",
			[]byte{0x00, 0x03, 0x00, 0x00},
			"dns: unrecognized APL address family",
		},
		{
			"prefix too large for family IPv4",
			[]byte{0x00, 0x01, 0x21, 0x04, 192, 0, 2, 0},
			"dns: APL prefix too long",
		},
		{
			"prefix too large for family IPv6",
			[]byte{0x00, 0x02, 0x81, 0x85, 0x20, 0x01, 0x0d, 0xb8, 0x80},
			"dns: APL prefix too long",
		},
		{
			"afdlen too long for address family IPv4",
			[]byte{0x00, 0x01, 22, 0x05, 192, 0, 2, 0, 0},
			"dns: APL length too long",
		},
		{
			"overflow unpacking APL address",
			[]byte{0x00, 0x01, 0x10, 0x02, 192},
			"dns: overflow unpacking APL address",
		},
		{
			"address included trailing zeros",
			[]byte{0x00, 0x01, 0x10, 0x04, 192, 0, 2, 0},
			"dns: extra APL address bits",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := unpackDataAplPrefix(tt.wire, 0)
			if err == nil {
				t.Fatal("expected error, got none")
			}

			if err.Error() != tt.want {
				t.Errorf("expected %s, got %s", tt.want, err.Error())
			}
		})
	}
}

func TestUnpackDataApl(t *testing.T) {
	wire := []byte{
		// 2:2001:db8:cafe:4200:0/56
		0x00, 0x02, 0x38, 0x07, 0x20, 0x01, 0x0d, 0xb8, 0xca, 0xfe, 0x42,
		// 1:192.0.2.0/24
		0x00, 0x01, 0x18, 0x03, 192, 0, 2,
		// !1:192.0.2.128/25
		0x00, 0x01, 0x19, 0x84, 192, 0, 2, 128,
		// 1:10.0.0.0/24
		0x00, 0x01, 0x18, 0x01, 0x0a,
		// !1:10.0.0.1/32
		0x00, 0x01, 0x20, 0x84, 0x0a, 0, 0, 1,
		// !1:0.0.0.0/0
		0x00, 0x01, 0x00, 0x80,
		// 2::0/0
		0x00, 0x02, 0x00, 0x00,
	}
	expect := []APLPrefix{
		{
			Negation: false,
			Network: net.IPNet{
				IP:   net.ParseIP("2001:db8:cafe:4200::"),
				Mask: net.CIDRMask(56, 128),
			},
		},
		{
			Negation: false,
			Network: net.IPNet{
				IP:   net.ParseIP("192.0.2.0").To4(),
				Mask: net.CIDRMask(24, 32),
			},
		},
		{
			Negation: true,
			Network: net.IPNet{
				IP:   net.ParseIP("192.0.2.128").To4(),
				Mask: net.CIDRMask(25, 32),
			},
		},
		{
			Negation: false,
			Network: net.IPNet{
				IP:   net.ParseIP("10.0.0.0").To4(),
				Mask: net.CIDRMask(24, 32),
			},
		},
		{
			Negation: true,
			Network: net.IPNet{
				IP:   net.ParseIP("10.0.0.1").To4(),
				Mask: net.CIDRMask(32, 32),
			},
		},
		{
			Negation: true,
			Network: net.IPNet{
				IP:   net.ParseIP("0.0.0.0").To4(),
				Mask: net.CIDRMask(0, 32),
			},
		},
		{
			Negation: false,
			Network: net.IPNet{
				IP:   net.ParseIP("::").To16(),
				Mask: net.CIDRMask(0, 128),
			},
		},
	}

	got, off, err := unpackDataApl(wire, 0)
	if err != nil {
		t.Fatalf("expected no error, got %q", err)
	}
	if off != len(wire) {
		t.Fatalf("expected offset %d, got %d", len(wire), off)
	}
	if len(got) != len(expect) {
		t.Fatalf("expected %d prefixes, got %d", len(expect), len(got))
	}
	for i, exp := range expect {
		if got[i].Negation != exp.Negation {
			t.Errorf("[%d] expected negation %v, got %v", i, exp.Negation, got[i].Negation)
		}
		if !exp.Network.IP.Equal(got[i].Network.IP) {
			t.Errorf("[%d] expected IP %02x, got %02x", i, exp.Network.IP, got[i].Network.IP)
		}
		if !bytes.Equal(got[i].Network.Mask, exp.Network.Mask) {
			t.Errorf("[%d] expected mask %02x, got %02x", i, exp.Network.Mask, got[i].Network.Mask)
		}
	}
}
