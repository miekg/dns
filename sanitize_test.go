package dns

import "testing"

func TestDedup(t *testing.T) {
	testcases := map[[3]RR]string{
		[...]RR{
			newRR(t, "mIek.nl. IN A 127.0.0.1"),
			newRR(t, "mieK.nl. IN A 127.0.0.1"),
			newRR(t, "miek.Nl. IN A 127.0.0.1"),
		}: "mIek.nl.\t3600\tIN\tA\t127.0.0.1",
		[...]RR{
			newRR(t, "miEk.nl. 2000 IN A 127.0.0.1"),
			newRR(t, "mieK.Nl. 1000 IN A 127.0.0.1"),
			newRR(t, "Miek.nL. 500 IN A 127.0.0.1"),
		}: "miEk.nl.\t500\tIN\tA\t127.0.0.1",
		[...]RR{
			newRR(t, "miek.nl. IN A 127.0.0.1"),
			newRR(t, "miek.nl. CH A 127.0.0.1"),
			newRR(t, "miek.nl. IN A 127.0.0.1"),
		}: "miek.nl.\t3600\tIN\tA\t127.0.0.1",
		[...]RR{
			newRR(t, "miek.nl. CH A 127.0.0.1"),
			newRR(t, "miek.nl. IN A 127.0.0.1"),
			newRR(t, "miek.nl. IN A 127.0.0.1"),
		}: "miek.nl.\t3600\tCH\tA\t127.0.0.1",
	}

	for rr, expected := range testcases {
		out := Dedup([]RR{rr[0], rr[1], rr[2]})
		if len(out) == 0 || len(out) == 3 {
			t.Logf("dedup failed, wrong number of RRs returned")
			t.Fail()
		}
		if o := out[0].String(); o != expected {
			t.Logf("dedup failed, expected %s, got %s", expected, o)
			t.Fail()
		}
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
