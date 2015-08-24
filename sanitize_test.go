package dns

import "testing"

func TestDedup(t *testing.T) {
	in := []RR{
		newRR(t, "miek.nl. IN A 127.0.0.1"),
		newRR(t, "miek.nl. IN A 127.0.0.1"),
	}
	out := Dedup(in)
	if len(out) != 1 && out[0].String() != "miek.nl. IN A 127.0.0.1" {
		dump(out, t)
		t.Errorf("dedup failed, expected %d, got %d", 1, len(out))
	}

	in = []RR{}
	out = Dedup(in)
	if len(out) != 0 {
		dump(out, t)
		t.Errorf("dedup failed, expected %d, got %d", 0, len(out))
	}

	in = []RR{
		newRR(t, "miEk.nl. 2000 IN A 127.0.0.1"),
		newRR(t, "mieK.Nl. 1000 IN A 127.0.0.1"),
	}
	out = Dedup(in)
	if len(out) != 1 {
		dump(out, t)
		t.Errorf("dedup failed, expected %d, got %d", 2, len(out))
	}

	in = []RR{
		newRR(t, "miek.nl. IN A 127.0.0.1"),
		newRR(t, "miek.nl. CH A 127.0.0.1"),
	}
	out = Dedup(in)
	if len(out) != 2 {
		dump(out, t)
		t.Errorf("dedup failed, expected %d, got %d", 2, len(out))
	}
	in = []RR{
		newRR(t, "miek.nl. CH A 127.0.0.1"),
		newRR(t, "miek.nl. IN A 127.0.0.1"),
		newRR(t, "mIek.Nl. IN A 127.0.0.1"),
	}
	out = Dedup(in)
	if len(out) != 2 {
		// TODO(miek): check ordering.
		dump(out, t)
		t.Errorf("dedup failed, expected %d, got %d", 2, len(out))
	}
}

func dump(rrs []RR, t *testing.T) {
	t.Logf("********\n")
	for _, r := range rrs {
		t.Logf("%v\n", r)
	}
}

func TestNormalizedString(t *testing.T) {
	tests := map[RR]string{
		newRR(t, "mIEk.Nl. 3600 IN A 127.0.0.1"):     "miek.nl.\tIN\tA\t127.0.0.1",
		newRR(t, "m\\ iek.nL. 3600 IN A 127.0.0.1"):  "m\\ iek.nl.\tIN\tA\t127.0.0.1",
		newRR(t, "m\\\tIeK.nl. 3600 in A 127.0.0.1"): "m\\tiek.nl.\tIN\tA\t127.0.0.1",
	}
	for tc, expected := range tests {
		a1 := normalizedString(tc)
		if a1 != expected {
			t.Logf("expected %s, got %s", expected, a1)
			t.Fail()
		}
	}
}

func newRR(t *testing.T, s string) RR {
	r, e := NewRR(s)
	if e != nil {
		t.Logf("newRR: %s", e)
	}
	return r
}
