package dns

import "testing"

func TestDuplicateA(t *testing.T) {
	a1, _ := NewRR("www.example.org. 2700 IN A 127.0.0.1")
	a2, _ := NewRR("www.example.org. IN A 127.0.0.1")
	if !IsDuplicate(a1, a2) {
		t.Errorf("expected %s/%s to be duplicates, but got false", a1.String(), a2.String())
	}

	a2, _ = NewRR("www.example.org. IN A 127.0.0.2")
	if IsDuplicate(a1, a2) {
		t.Errorf("expected %s/%s not to be duplicates, but got true", a1.String(), a2.String())
	}
}

func TestDuplicateTXT(t *testing.T) {
	a1, _ := NewRR("www.example.org. IN TXT \"aa\"")
	a2, _ := NewRR("www.example.org. IN TXT \"aa\"")

	if !IsDuplicate(a1, a2) {
		t.Errorf("expected %s/%s to be duplicates, but got false", a1.String(), a2.String())
	}

	a2, _ = NewRR("www.example.org. IN TXT \"aa\" \"bb\"")
	if IsDuplicate(a1, a2) {
		t.Errorf("expected %s/%s not to be duplicates, but got true", a1.String(), a2.String())
	}

	a1, _ = NewRR("www.example.org. IN TXT \"aa\" \"bc\"")
	if IsDuplicate(a1, a2) {
		t.Errorf("expected %s/%s not to be duplicates, but got true", a1.String(), a2.String())
	}
}

func TestDuplicateOwner(t *testing.T) {
	a1, _ := NewRR("www.example.org. IN A 127.0.0.1")
	a2, _ := NewRR("www.example.org. IN A 127.0.0.1")
	if !IsDuplicate(a1, a2) {
		t.Errorf("expected %s/%s to be duplicates, but got false", a1.String(), a2.String())
	}

	a2, _ = NewRR("WWw.exaMPle.org. IN A 127.0.0.2")
	if IsDuplicate(a1, a2) {
		t.Errorf("expected %s/%s to be duplicates, but got false", a1.String(), a2.String())
	}
}

func TestDuplicateDomain(t *testing.T) {
	a1, _ := NewRR("www.example.org. IN CNAME example.org.")
	a2, _ := NewRR("www.example.org. IN CNAME example.org.")
	if !IsDuplicate(a1, a2) {
		t.Errorf("expected %s/%s to be duplicates, but got false", a1.String(), a2.String())
	}

	a2, _ = NewRR("www.example.org. IN CNAME exAMPLe.oRG.")
	if !IsDuplicate(a1, a2) {
		t.Errorf("expected %s/%s to be duplicates, but got false", a1.String(), a2.String())
	}
}
