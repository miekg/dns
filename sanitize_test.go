package dns

import "testing"

func TestDedup(t *testing.T) {
	in := []RR{
		newRR("miek.nl. IN A 127.0.0.1"),
		newRR("miek.nl. IN A 127.0.0.1"),
	}
	in = Dedup(in)
	t.Logf("%v\n", in)

	in = []RR{}
	in = Dedup(in)
	t.Logf("%v\n", in)

	in = []RR{
		newRR("miek.nl. IN A 127.0.0.1"),
		newRR("miek.nl. IN A 127.0.0.2"),
	}
	in = Dedup(in)
	t.Logf("%v\n", in)

	in = []RR{
		newRR("miek.nl. IN A 127.0.0.1"),
		newRR("miek.nl. IN A 127.0.0.2"),
		newRR("miek.nl. IN A 127.0.0.1"),
	}
	in = Dedup(in)
	t.Logf("%v\n", in)

	in = []RR{
		newRR("miek.nl. 300 IN A 127.0.0.1"),
		newRR("miek.nl. 200 IN A 127.0.0.1"),
	}
	in = Dedup(in)
	t.Logf("%v\n", in)

	t.Fail()
}

// Mainly here to disregard the error.
func newRR(s string) RR {
	r, _ := NewRR(s)
	return r
}
