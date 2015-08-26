package dns

import "testing"

func TestDedup(t *testing.T) {
	// make it []string
	testcases := map[[3]RR][]string{
		[...]RR{
			newRR(t, "mIek.nl. IN A 127.0.0.1"),
			newRR(t, "mieK.nl. IN A 127.0.0.1"),
			newRR(t, "miek.Nl. IN A 127.0.0.1"),
		}: []string{"mIek.nl.\t3600\tIN\tA\t127.0.0.1"},
		[...]RR{
			newRR(t, "miEk.nl. 2000 IN A 127.0.0.1"),
			newRR(t, "mieK.Nl. 1000 IN A 127.0.0.1"),
			newRR(t, "Miek.nL. 500 IN A 127.0.0.1"),
		}: []string{"miEk.nl.\t500\tIN\tA\t127.0.0.1"},
		[...]RR{
			newRR(t, "miek.nl. IN A 127.0.0.1"),
			newRR(t, "miek.nl. CH A 127.0.0.1"),
			newRR(t, "miek.nl. IN A 127.0.0.1"),
		}: []string{"miek.nl.\t3600\tIN\tA\t127.0.0.1",
			"miek.nl.\t3600\tCH\tA\t127.0.0.1",
		},
		[...]RR{
			newRR(t, "miek.nl. CH A 127.0.0.1"),
			newRR(t, "miek.nl. IN A 127.0.0.1"),
			newRR(t, "miek.de. IN A 127.0.0.1"),
		}: []string{"miek.nl.\t3600\tCH\tA\t127.0.0.1",
			"miek.nl.\t3600\tIN\tA\t127.0.0.1",
			"miek.de.\t3600\tIN\tA\t127.0.0.1",
		},
		[...]RR{
			newRR(t, "miek.de. IN A 127.0.0.1"),
			newRR(t, "miek.nl. 200 IN A 127.0.0.1"),
			newRR(t, "miek.nl. 300 IN A 127.0.0.1"),
		}: []string{"miek.de.\t3600\tIN\tA\t127.0.0.1",
			"miek.nl.\t200\tIN\tA\t127.0.0.1",
		},
	}

	for rr, expected := range testcases {
		out := Dedup([]RR{rr[0], rr[1], rr[2]})
		for i, o := range out {
			if o.String() != expected[i] {
				t.Fatalf("expected %v, got %v", expected[i], o.String())
			}
		}
	}
}

func TestDedupWithCNAMEDNAME(t *testing.T) {
	testcases := map[[4]RR][]string{
		[...]RR{
			newRR(t, "miek.Nl. CNAME a."),
			newRR(t, "miEk.nl. IN A 127.0.0.1"),
			newRR(t, "miek.Nl. IN A 127.0.0.1"),
			newRR(t, "miek.de. IN A 127.0.0.1"),
		}: []string{"miek.Nl.\t3600\tIN\tCNAME\ta.",
			"miek.de.\t3600\tIN\tA\t127.0.0.1"},
		[...]RR{
			newRR(t, "Miek.nl. CNAME a."),
			newRR(t, "mIek.nl. CNAME a."),
			newRR(t, "miEk.nl. CNAME a."),
			newRR(t, "mieK.nl. CNAME a."),
		}: []string{"Miek.nl.\t3600\tIN\tCNAME\ta."},
		[...]RR{
			newRR(t, "miek.nl. CNAME a."),
			newRR(t, "a.miek.nl. CNAME a."),
			newRR(t, "a.miek.nl. CNAME a."),
			newRR(t, "a.miek.nl. CNAME a."),
		}: []string{"miek.nl.\t3600\tIN\tCNAME\ta.",
			"a.miek.nl.\t3600\tIN\tCNAME\ta."},
		[...]RR{
			newRR(t, "miek.nl. DNAME a."),
			newRR(t, "a.miek.nl. CNAME a."),
			newRR(t, "b.miek.nl. IN A 127.0.0.1"),
			newRR(t, "a.miek.de. IN A 127.0.0.1"),
		}: []string{"miek.nl.\t3600\tIN\tDNAME\ta.",
			"a.miek.de.\t3600\tIN\tA\t127.0.0.1"},
		[...]RR{
			newRR(t, "miek.nl. DNAME a."),
			newRR(t, "a.miek.nl. DNAME a."),
			newRR(t, "b.miek.nl. DNAME b."),
			newRR(t, "a.b.miek.nl. DNAME a.b"),
		}: []string{"miek.nl.\t3600\tIN\tDNAME\ta."},
	}

	for rr, expected := range testcases {
		out := Dedup([]RR{rr[0], rr[1], rr[2], rr[3]})
		for i, o := range out {
			if o.String() != expected[i] {
				t.Fatalf("expected %v, got %v", expected[i], o.String())
			}
		}
	}
}

// BenchMark test as well TODO(miek)

func TestNormalizedString(t *testing.T) {
	tests := map[RR]string{
		newRR(t, "mIEk.Nl. 3600 IN A 127.0.0.1"):     "miek.nl.\tIN\tA\t127.0.0.1",
		newRR(t, "m\\ iek.nL. 3600 IN A 127.0.0.1"):  "m\\ iek.nl.\tIN\tA\t127.0.0.1",
		newRR(t, "m\\\tIeK.nl. 3600 in A 127.0.0.1"): "m\\tiek.nl.\tIN\tA\t127.0.0.1",
	}
	for tc, expected := range tests {
		a1, _ := normalizedString(tc)
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
