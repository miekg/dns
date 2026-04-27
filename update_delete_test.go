package dns

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"testing"
	"time"
)

// These tests exist to answer a specific question: does miekg/dns correctly
// build and parse a DNS UPDATE message containing an RFC 2136 §2.5.2
// "delete RRset" record (CLASS ANY, TTL 0, empty RDATA), and the §2.5.4
// "delete RR from RRset" record (CLASS NONE, TTL 0, RDATA present)?
//
// The question arose because tdns-mp saw UPDATE messages that were reported
// as "4 octets too long" at the receiver. If these tests pass, the bug is
// not in the library.

// TestRemoveRRsetWireFormat covers RFC 2136 §2.5.2.
func TestRemoveRRsetWireFormat(t *testing.T) {
	m := new(Msg)
	m.SetUpdate("example.com.")
	m.Id = 1

	rr := testRR("www.example.com. 3600 IN A 127.0.0.1")
	m.RemoveRRset([]RR{rr})

	wire, err := m.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}

	m2 := new(Msg)
	if err := m2.Unpack(wire); err != nil {
		t.Fatalf("Unpack: %v\nwire (%d): %s",
			err, len(wire), hex.EncodeToString(wire))
	}

	if len(m2.Ns) != 1 {
		t.Fatalf("Ns has %d RRs, want 1", len(m2.Ns))
	}
	h := m2.Ns[0].Header()
	if h.Class != ClassANY {
		t.Errorf("Class = %d, want ClassANY (%d)", h.Class, ClassANY)
	}
	if h.Ttl != 0 {
		t.Errorf("TTL = %d, want 0", h.Ttl)
	}
	if h.Rrtype != TypeA {
		t.Errorf("Rrtype = %d, want TypeA (%d)", h.Rrtype, TypeA)
	}
	if h.Rdlength != 0 {
		t.Errorf("Rdlength = %d, want 0 (§2.5.2 requires empty RDATA)",
			h.Rdlength)
	}

	wire2, err := m2.Pack()
	if err != nil {
		t.Fatalf("repack: %v", err)
	}
	if !bytes.Equal(wire, wire2) {
		t.Errorf("repacked wire differs (pack/unpack not stable).\n  first  (%d): %s\n  second (%d): %s",
			len(wire), hex.EncodeToString(wire),
			len(wire2), hex.EncodeToString(wire2))
	}

	// Explicit size budget so a 4-octet drift would show up clearly.
	// Header(12) + Zone("example.com."=13 + qtype+qclass=4) +
	// Update("www.example.com."=17 uncompressed + type+class+ttl+rdlength=10 + rdata(0))
	// = 12 + 17 + 27 = 56. The library does not compress owner names in the
	// Update section; see Msg.Pack.
	const want = 56
	if len(wire) != want {
		t.Errorf("packed length = %d, want %d (unexpected %+d bytes)",
			len(wire), want, len(wire)-want)
	}
}

// TestRemoveWireFormat covers RFC 2136 §2.5.4.
func TestRemoveWireFormat(t *testing.T) {
	m := new(Msg)
	m.SetUpdate("example.com.")
	m.Id = 1

	rr := testRR("www.example.com. 3600 IN A 127.0.0.1")
	m.Remove([]RR{rr})

	wire, err := m.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}

	m2 := new(Msg)
	if err := m2.Unpack(wire); err != nil {
		t.Fatalf("Unpack: %v\nwire (%d): %s",
			err, len(wire), hex.EncodeToString(wire))
	}

	if len(m2.Ns) != 1 {
		t.Fatalf("Ns has %d RRs, want 1", len(m2.Ns))
	}
	h := m2.Ns[0].Header()
	if h.Class != ClassNONE {
		t.Errorf("Class = %d, want ClassNONE (%d)", h.Class, ClassNONE)
	}
	if h.Ttl != 0 {
		t.Errorf("TTL = %d, want 0", h.Ttl)
	}
	if h.Rrtype != TypeA {
		t.Errorf("Rrtype = %d, want TypeA (%d)", h.Rrtype, TypeA)
	}
	if h.Rdlength != 4 {
		t.Errorf("Rdlength = %d, want 4 (A record rdata)", h.Rdlength)
	}
	a, ok := m2.Ns[0].(*A)
	if !ok {
		t.Fatalf("Ns[0] is %T, want *A", m2.Ns[0])
	}
	if a.A.String() != "127.0.0.1" {
		t.Errorf("A = %s, want 127.0.0.1", a.A)
	}

	wire2, err := m2.Pack()
	if err != nil {
		t.Fatalf("repack: %v", err)
	}
	if !bytes.Equal(wire, wire2) {
		t.Errorf("repacked wire differs (pack/unpack not stable).\n  first  (%d): %s\n  second (%d): %s",
			len(wire), hex.EncodeToString(wire),
			len(wire2), hex.EncodeToString(wire2))
	}

	// Same layout as §2.5.2, plus 4 bytes of A rdata: 56 + 4 = 60.
	const want = 60
	if len(wire) != want {
		t.Errorf("packed length = %d, want %d (unexpected %+d bytes)",
			len(wire), want, len(wire)-want)
	}
}

// TestRemoveRRsetSIG0RoundTrip signs a §2.5.2 "delete RRset" UPDATE with
// SIG(0), packs to wire, unpacks, and verifies both the in-memory SIG and
// the SIG re-parsed from Additional.
func TestRemoveRRsetSIG0RoundTrip(t *testing.T) {
	testDeleteSIG0(t, "RemoveRRset",
		func(m *Msg, rr RR) { m.RemoveRRset([]RR{rr}) })
}

// TestRemoveRRsetDSSIG0RoundTrip is the §2.5.2 case that originally exposed
// the bug fixed in UnpackRRWithHeader: when the placeholder type has
// fixed-size scalar rdata fields (e.g. DS: KeyTag+Algorithm+DigestType =
// 4 bytes), the pre-fix unpacker built a typed *DS with zero values and a
// later re-pack emitted 4 phantom bytes, breaking SIG(0) verification.
// With the fix, unpack returns *ANY for any CLASS=ANY+Rdlength=0 record
// regardless of typed-rdata layout, restoring round-trip symmetry.
//
// TypeA is bug-immune because packDataA already short-circuits len(IP)==0
// (see msg_helpers.go); this DS test catches the general case.
func TestRemoveRRsetDSSIG0RoundTrip(t *testing.T) {
	keyrr := &KEY{DNSKEY: DNSKEY{
		Hdr: RR_Header{
			Name:   "updater.example.",
			Rrtype: TypeKEY,
			Class:  ClassINET,
			Ttl:    3600,
		},
		Algorithm: ED25519,
	}}
	priv, err := keyrr.Generate(256)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	m := new(Msg)
	m.SetUpdate("example.")
	// DS placeholder, the type that broke before the fix.
	dsPlaceholder := &DS{Hdr: RR_Header{
		Name:   "child.example.",
		Rrtype: TypeDS,
		Class:  ClassINET,
		Ttl:    3600,
	}}
	m.RemoveRRset([]RR{dsPlaceholder})

	now := uint32(time.Now().Unix())
	sigrr := &SIG{RRSIG: RRSIG{
		Hdr:        RR_Header{Name: ".", Rrtype: TypeSIG, Class: ClassANY},
		Algorithm:  ED25519,
		Expiration: now + 300,
		Inception:  now - 300,
		KeyTag:     keyrr.KeyTag(),
		SignerName: keyrr.Hdr.Name,
	}}
	mb, err := sigrr.Sign(priv.(crypto.Signer), m)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	m2 := new(Msg)
	if err := m2.Unpack(mb); err != nil {
		t.Fatalf("Unpack of signed wire (%d bytes): %v\nwire: %s",
			len(mb), err, hex.EncodeToString(mb))
	}
	if len(m2.Ns) != 1 {
		t.Fatalf("unpacked Ns has %d RRs, want 1", len(m2.Ns))
	}
	// After the fix, a CLASS=ANY+Rdlength=0+TYPE=DS record must come back
	// as *ANY (not *DS), preserving round-trip symmetry. Without the fix
	// this is *DS and the SIG verification below fails.
	if _, ok := m2.Ns[0].(*ANY); !ok {
		t.Errorf("Ns[0] is %T, want *ANY (delete-RRset placeholder)", m2.Ns[0])
	}
	h := m2.Ns[0].Header()
	if h.Rrtype != TypeDS {
		t.Errorf("Rrtype = %d, want TypeDS (%d)", h.Rrtype, TypeDS)
	}
	if h.Class != ClassANY {
		t.Errorf("Class = %d, want ClassANY (%d)", h.Class, ClassANY)
	}
	if h.Rdlength != 0 {
		t.Errorf("Rdlength = %d, want 0", h.Rdlength)
	}

	if len(m2.Extra) != 1 {
		t.Fatalf("Extra has %d RRs, want 1 (SIG)", len(m2.Extra))
	}
	sigrrwire, ok := m2.Extra[0].(*SIG)
	if !ok {
		t.Fatalf("Extra[0] is %T, want *SIG", m2.Extra[0])
	}
	for _, s := range []*SIG{sigrr, sigrrwire} {
		src := "sigrr"
		if s == sigrrwire {
			src = "sigrrwire"
		}
		if err := s.Verify(keyrr, mb); err != nil {
			t.Errorf("Verify(%s): %v", src, err)
		}
	}
}

// TestRemoveSIG0RoundTrip is the §2.5.4 variant.
func TestRemoveSIG0RoundTrip(t *testing.T) {
	testDeleteSIG0(t, "Remove",
		func(m *Msg, rr RR) { m.Remove([]RR{rr}) })
}

func testDeleteSIG0(t *testing.T, label string, apply func(*Msg, RR)) {
	t.Helper()

	keyrr := &KEY{DNSKEY: DNSKEY{
		Hdr: RR_Header{
			Name:   "updater.example.",
			Rrtype: TypeKEY,
			Class:  ClassINET,
			Ttl:    3600,
		},
		Algorithm: ED25519,
	}}
	priv, err := keyrr.Generate(256)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	m := new(Msg)
	m.SetUpdate("example.")
	rr := testRR("www.example. 3600 IN A 127.0.0.1")
	apply(m, rr)

	now := uint32(time.Now().Unix())
	sigrr := &SIG{RRSIG: RRSIG{
		Hdr:        RR_Header{Name: ".", Rrtype: TypeSIG, Class: ClassANY},
		Algorithm:  ED25519,
		Expiration: now + 300,
		Inception:  now - 300,
		KeyTag:     keyrr.KeyTag(),
		SignerName: keyrr.Hdr.Name,
	}}
	mb, err := sigrr.Sign(priv.(crypto.Signer), m)
	if err != nil {
		t.Fatalf("%s Sign: %v", label, err)
	}

	m2 := new(Msg)
	if err := m2.Unpack(mb); err != nil {
		t.Fatalf("%s Unpack of signed wire (%d bytes): %v\nwire: %s",
			label, len(mb), err, hex.EncodeToString(mb))
	}
	if len(m2.Ns) != 1 {
		t.Errorf("%s unpacked Ns has %d RRs, want 1", label, len(m2.Ns))
	}
	if len(m2.Extra) != 1 {
		t.Fatalf("%s Extra has %d RRs, want 1 (SIG)", label, len(m2.Extra))
	}
	sigrrwire, ok := m2.Extra[0].(*SIG)
	if !ok {
		t.Fatalf("%s Extra[0] is %T, want *SIG", label, m2.Extra[0])
	}

	for _, s := range []*SIG{sigrr, sigrrwire} {
		src := "sigrr"
		if s == sigrrwire {
			src = "sigrrwire"
		}
		if err := s.Verify(keyrr, mb); err != nil {
			t.Errorf("%s Verify(%s): %v", label, src, err)
		}
	}
}
