package dns

import "testing"

func TestDedup(t *testing.T) {
	in := []RR{
		newRR("miek.nl. IN A 127.0.0.1"),
		newRR("miek.nl. IN A 127.0.0.1"),
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
		newRR("miek.nl. 1000 IN A 127.0.0.1"),
		newRR("miek.nl. 2000 IN A 127.0.0.1"),
	}
	out = Dedup(in)
	if len(out) != 1 {
		dump(out, t)
		t.Errorf("dedup failed, expected %d, got %d", 2, len(out))
	}

	in = []RR{
		newRR("miek.nl. IN A 127.0.0.1"),
		newRR("miek.nl. CH A 127.0.0.1"),
	}
	out = Dedup(in)
	if len(out) != 2 {
		dump(out, t)
		t.Errorf("dedup failed, expected %d, got %d", 2, len(out))
	}
	in = []RR{
		newRR("miek.nl. CH A 127.0.0.1"),
		newRR("miek.nl. IN A 127.0.0.1"),
		newRR("miek.nl. IN A 127.0.0.1"),
	}
	out = Dedup(in)
	if len(out) != 2 {
		// TODO(miek): check ordering.
		dump(out, t)
		t.Errorf("dedup failed, expected %d, got %d", 2, len(out))
	}
}

func newRR(s string) RR {
	r, _ := NewRR(s)
	return r
}

func dump(rrs []RR, t *testing.T) {
	t.Logf("********\n")
	for _, r := range rrs {
		t.Logf("%v\n", r)
	}
}
