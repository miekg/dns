package dns

import (
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
)

const fallbackType = 65280

func TestMsgJSONRoundTrip(t *testing.T) {
	fixtures := messageFixtures(t)

	expectedTypes := map[uint16]string{
		TypeA:        "A",
		TypeAAAA:     "AAAA",
		TypeCNAME:    "CNAME",
		TypeNS:       "NS",
		TypePTR:      "PTR",
		TypeTXT:      "TXT",
		TypeMX:       "MX",
		TypeSRV:      "SRV",
		TypeSOA:      "SOA",
		TypeCAA:      "CAA",
		TypeNAPTR:    "NAPTR",
		TypeDS:       "DS",
		TypeDNSKEY:   "DNSKEY",
		TypeRRSIG:    "RRSIG",
		TypeTLSA:     "TLSA",
		fallbackType: "TYPE65280",
	}

	seenTypes := make(map[uint16]bool)

	for name, want := range fixtures {
		want := want
		t.Run(name, func(t *testing.T) {
			t.Helper()

			data, err := json.Marshal((*Msg)(want))
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}

			var got Msg
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("Unmarshal failed: %v\nJSON: %s", err, data)
			}

			wantCopy := want.Copy()
			gotMsg := Msg(got)

			if wantCopy.String() != gotMsg.String() {
				t.Fatalf("round-trip mismatch\nwant: %s\njson: %s\ngot: %s", wantCopy, data, gotMsg.String())
			}
		})

		for _, rr := range want.Answer {
			seenTypes[rr.Header().Rrtype] = true
		}
		for _, rr := range want.Ns {
			seenTypes[rr.Header().Rrtype] = true
		}
		for _, rr := range want.Extra {
			seenTypes[rr.Header().Rrtype] = true
		}
	}

	for typ, label := range expectedTypes {
		if !seenTypes[typ] {
			t.Fatalf("test fixtures missing record for type %s", label)
		}
	}
}

func TestMsgMarshalNil(t *testing.T) {

	var m *Msg
	got, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("Marshal nil failed: %v", err)
	}
	if string(got) != "null" {
		t.Fatalf("unexpected JSON for nil Msg: %s", got)
	}
}

func TestMsgUnmarshalNull(t *testing.T) {

	var msg Msg
	if err := json.Unmarshal([]byte("null"), &msg); err != nil {
		t.Fatalf("Unmarshal null failed: %v", err)
	}
	dnsMsg := Msg(msg)
	if dnsMsg.Id != 0 || len(dnsMsg.Question) != 0 || len(dnsMsg.Answer) != 0 || len(dnsMsg.Ns) != 0 || len(dnsMsg.Extra) != 0 {
		t.Fatalf("expected zero-value message after null unmarshal, got %+v", dnsMsg)
	}
}

func messageFixtures(t *testing.T) map[string]*Msg {
	t.Helper()

	const ttl = 600

	header := func(name string, rrtype uint16) RR_Header {
		return RR_Header{Name: name, Rrtype: rrtype, Class: ClassINET, Ttl: ttl}
	}

	fallbackRR := mustRR(t, "raw.example. 3600 IN TYPE65280 \\# 4 01020304")
	fallbackRR.Header().Name = "raw.example."
	fallbackRR.Header().Class = ClassINET
	fallbackRR.Header().Rrtype = fallbackType
	fallbackRR.Header().Ttl = 3600

	full := &Msg{
		MsgHdr: MsgHdr{
			Id:                 4242,
			Response:           true,
			Opcode:             OpcodeUpdate,
			Authoritative:      true,
			Truncated:          true,
			RecursionDesired:   true,
			RecursionAvailable: true,
			Zero:               true,
			AuthenticatedData:  true,
			CheckingDisabled:   true,
			Rcode:              RcodeNameError,
		},
		Question: []Question{
			{Name: "a.example.", Qtype: TypeA, Qclass: ClassINET},
			{Name: "aaaa.example.", Qtype: TypeAAAA, Qclass: ClassCHAOS},
		},
		Answer: []RR{
			&A{Hdr: header("a.example.", TypeA), A: net.IPv4(192, 0, 2, 1)},
			&AAAA{Hdr: header("aaaa.example.", TypeAAAA), AAAA: net.ParseIP("2001:db8::1")},
			&CNAME{Hdr: header("alias.example.", TypeCNAME), Target: "target.example."},
			&NS{Hdr: header("example.", TypeNS), Ns: "ns1.example."},
			&PTR{Hdr: header("1.2.0.192.in-addr.arpa.", TypePTR), Ptr: "ptr.example."},
		},
		Ns: []RR{
			&TXT{Hdr: header("txt.example.", TypeTXT), Txt: []string{"chunk1", "chunk2"}},
			&MX{Hdr: header("example.", TypeMX), Preference: 10, Mx: "mail.example."},
			&SRV{Hdr: header("_service._tcp.example.", TypeSRV), Priority: 0, Weight: 5, Port: 443, Target: "srv.example."},
			&SOA{
				Hdr:     header("example.", TypeSOA),
				Ns:      "ns1.example.",
				Mbox:    "hostmaster.example.",
				Serial:  2023120101,
				Refresh: 7200,
				Retry:   900,
				Expire:  1209600,
				Minttl:  3600,
			},
		},
		Extra: []RR{
			&CAA{Hdr: header("example.", TypeCAA), Flag: 0, Tag: "issue", Value: "letsencrypt.org"},
			&NAPTR{
				Hdr:         header("example.", TypeNAPTR),
				Order:       100,
				Preference:  50,
				Flags:       "s",
				Service:     "SIP+D2U",
				Regexp:      "!^.*$!sip:info@example.com!",
				Replacement: "_sip._udp.example.",
			},
			&DS{
				Hdr:        header("example.", TypeDS),
				KeyTag:     12345,
				Algorithm:  8,
				DigestType: 2,
				Digest:     "BEEFCAFE0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123",
			},
			&DNSKEY{
				Hdr:       header("example.", TypeDNSKEY),
				Flags:     257,
				Protocol:  3,
				Algorithm: 8,
				PublicKey: "AwEAAcR2examplePublicKey==",
			},
			&RRSIG{
				Hdr:         header("example.", TypeRRSIG),
				TypeCovered: TypeA,
				Algorithm:   8,
				Labels:      2,
				OrigTtl:     600,
				Expiration:  1735689600,
				Inception:   1733097600,
				KeyTag:      12345,
				SignerName:  "example.",
				Signature:   "exampleSignatureBase64==",
			},
			&TLSA{
				Hdr:          header("_443._tcp.example.", TypeTLSA),
				Usage:        3,
				Selector:     1,
				MatchingType: 1,
				Certificate:  "abcdef1234567890",
			},
			fallbackRR,
		},
	}

	minimal := new(Msg)
	minimal.SetQuestion("minimal.example.", TypeTXT)

	return map[string]*Msg{
		"full":    full,
		"minimal": minimal,
	}
}

func mustRR(t *testing.T, s string) RR {
	t.Helper()
	rr, err := NewRR(s)
	if err != nil {
		t.Fatalf("failed to parse RR %q: %v", s, err)
	}
	return rr
}

func TestStringToType(t *testing.T) {

	tests := []struct {
		name    string
		input   string
		want    uint16
		wantErr bool
	}{
		{name: "known mnemonic", input: "A", want: TypeA},
		{name: "case insensitive", input: "a", want: TypeA},
		{name: "numeric string", input: "15", want: TypeMX},
		{name: "unknown", input: "definitely-unknown", wantErr: true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {

			got, err := stringToType(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("stringToType(%q) = %d, want %d", tc.input, got, tc.want)
			}
		})
	}
}

func TestClassToString(t *testing.T) {

	tests := []struct {
		name string
		in   uint16
		want string
	}{
		{name: "known class", in: ClassINET, want: "IN"},
		{name: "unknown class", in: 9999, want: "9999"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {

			if got := classToString(tc.in); got != tc.want {
				t.Fatalf("classToString(%d) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestTypeToString(t *testing.T) {

	tests := []struct {
		name string
		in   uint16
		want string
	}{
		{name: "known type", in: TypeAAAA, want: "AAAA"},
		{name: "unknown type", in: 9999, want: "9999"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {

			if got := typeToString(tc.in); got != tc.want {
				t.Fatalf("typeToString(%d) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestStringToClass(t *testing.T) {

	tests := []struct {
		name    string
		input   string
		want    uint16
		wantErr bool
	}{
		{name: "known mnemonic", input: "IN", want: ClassINET},
		{name: "case insensitive", input: "in", want: ClassINET},
		{name: "numeric string", input: "254", want: 254},
		{name: "unknown", input: "definitely-unknown", wantErr: true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {

			got, err := stringToClass(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("stringToClass(%q) = %d, want %d", tc.input, got, tc.want)
			}
		})
	}
}

func TestGetUintHelpers(t *testing.T) {

	m := map[string]any{
		"u8":    float64(42),
		"u16":   int(65535),
		"u32n":  json.Number("123456"),
		"u32s":  "789",
		"int64": int64(65535),
	}

	if got := getUint8(m, "u8"); got != 42 {
		t.Fatalf("getUint8 = %d, want 42", got)
	}
	if got := getUint16(m, "u16"); got != 65535 {
		t.Fatalf("getUint16 = %d, want 65535", got)
	}
	if got := getUint32(m, "u32n"); got != 123456 {
		t.Fatalf("getUint32(json.Number) = %d, want 123456", got)
	}
	if got := getUint32(m, "u32s"); got != 789 {
		t.Fatalf("getUint32(string) = %d, want 789", got)
	}
	if got := getUint16(m, "missing"); got != 0 {
		t.Fatalf("getUint16 missing key = %d, want 0", got)
	}
	if got := getUint32(m, "int64"); got != 65535 {
		t.Fatalf("getUint32 = %d, want 65535", got)
	}
}

func TestGetStringSlice(t *testing.T) {

	m := map[string]any{"txt": []any{"chunk1", "chunk2"}}
	got, err := getStringSlice(m, "txt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"chunk1", "chunk2"}
	if len(got) != len(want) {
		t.Fatalf("len mismatch: got %d want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("getStringSlice mismatch at %d: got %q want %q", i, got[i], want[i])
		}
	}

	_, err = getStringSlice(map[string]any{"txt": "not-a-slice"}, "txt")
	if err == nil {
		t.Fatal("expected error for non-slice input")
	}

	_, err = getStringSlice(map[string]any{"txt": []any{"ok", 123}}, "txt")
	if err == nil {
		t.Fatal("expected error for mixed slice")
	}
}

func TestRRFromJSONFallback(t *testing.T) {

	rr, err := rrFromJSON(RRJSON{
		Name:  "fallback.example.",
		Type:  "99",
		Class: "IN",
		TTL:   123,
		Data: map[string]any{
			"raw": "fallback.example. 0 IN TYPE99 \\# 0",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rr == nil {
		t.Fatalf("expected rr, got nil")
	}
	hdr := rr.Header()
	if hdr.Name != "fallback.example." {
		t.Fatalf("unexpected name: %q", hdr.Name)
	}
	if hdr.Ttl != 123 {
		t.Fatalf("ttl not restored from JSON header: got %d", hdr.Ttl)
	}
	if hdr.Class != ClassINET {
		t.Fatalf("unexpected class: %d", hdr.Class)
	}
	if hdr.Rrtype != 99 {
		t.Fatalf("unexpected type: %d", hdr.Rrtype)
	}
}

func TestRRsFromJSONAggregatesErrors(t *testing.T) {

	valid := RRJSON{
		Name:  "valid.example.",
		Type:  "A",
		Class: "IN",
		TTL:   60,
		Data:  map[string]any{"a": "192.0.2.1"},
	}
	invalid := RRJSON{
		Name:  "invalid.example.",
		Type:  "A",
		Class: "IN",
		TTL:   60,
		Data:  map[string]any{"a": "not-an-ip"},
	}

	got, err := rrsFromJSON([]RRJSON{valid, invalid})
	if err == nil {
		t.Fatal("expected aggregated error")
	}
	if !strings.Contains(err.Error(), "ParseAddr") {
		t.Fatalf("unexpected error contents: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected one successful RR, got %d", len(got))
	}
	if got[0].Header().Name != "valid.example." {
		t.Fatalf("unexpected RR in output: %v", got[0])
	}
}

func TestWrapError(t *testing.T) {

	if got := wrapError(ErrInvalidJSON, nil); got != nil {
		t.Fatalf("wrapError should return nil when err nil: got %v", got)
	}

	base := errors.New("boom")
	err := wrapError(ErrInvalidJSON, base)
	if !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("expected errors.Is to match sentinel: %v", err)
	}
	if got := err.Error(); got != "dnsjson: invalid JSON: boom" {
		t.Errorf("%q != %q", got, "dnsjson: invalid JSON: boom")
	}
	if errors.Unwrap(err) != base {
		t.Fatalf("expected unwrap to yield original error, got %v", errors.Unwrap(err))
	}
}

func TestUnknownTypeErrorIs(t *testing.T) {

	_, err := stringToType("definitely-unknown")
	if err == nil {
		t.Fatal("expected error for unknown type")
	}
	if !errors.Is(err, ErrUnknownType) {
		t.Fatalf("expected errors.Is to match ErrUnknownType: %v", err)
	}
	if errors.Is(err, ErrUnknownClass) {
		t.Fatalf("unexpected match against ErrUnknownClass: %v", err)
	}

	var ute *unknownTypeError
	if !errors.As(err, &ute) {
		t.Fatalf("expected unknownTypeError, got %T", err)
	}
	if ute.Error() != "unknown type \"definitely-unknown\"" {
		t.Fatalf("unexpected error string: %q", ute.Error())
	}
}

func TestUnknownClassErrorIs(t *testing.T) {
	_, err := stringToClass("definitely-unknown")
	if err == nil {
		t.Fatal("expected error for unknown class")
	}
	if !errors.Is(err, ErrUnknownClass) {
		t.Fatalf("expected errors.Is to match ErrUnknownClass: %v", err)
	}
	if errors.Is(err, ErrUnknownType) {
		t.Fatalf("unexpected match against ErrUnknownType: %v", err)
	}

	var uce *unknownClassError
	if !errors.As(err, &uce) {
		t.Fatalf("expected unknownClassError, got %T", err)
	}
	if uce.Error() != "unknown class \"definitely-unknown\"" {
		t.Fatalf("unexpected error string: %q", uce.Error())
	}
}

func TestStringSliceErrorIs(t *testing.T) {
	_, err := getStringSlice(map[string]any{"txt": "not-a-slice"}, "txt")
	if err == nil {
		t.Fatal("expected error for invalid string slice")
	}
	if !errors.Is(err, ErrInvalidStringSlice) {
		t.Fatalf("expected errors.Is to match ErrInvalidStringSlice: %v", err)
	}

	var sse *stringSliceError
	if !errors.As(err, &sse) {
		t.Fatalf("expected stringSliceError, got %T", err)
	}
	if sse.Error() != "txt must be array of strings" {
		t.Fatalf("unexpected error string: %q", sse.Error())
	}
}
