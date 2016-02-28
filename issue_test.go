package dns

import "testing"

// Tests that solve that a specific issue has been solved.

func TestTCPRtt(t *testing.T) {
	m := new(Msg)
	m.RecursionDesired = true
	m.SetQuestion("example.org.", TypeA)

	c := &Client{}
	in, rtt, err := c.Exchange(m, "8.8.4.4:53")
	if err != nil {
		t.Fatal(err)
	}
	if rtt == 0 {
		t.Fatalf("expecting non zero rtt, got zero")
	}
	t.Logf("%s", in)

	c.Net = "tcp"
	in, rtt, err = c.Exchange(m, "8.8.4.4:53")
	if err != nil {
		t.Fatal(err)
	}
	if rtt == 0 {
		t.Fatalf("expecting non zero rtt, got zero")
	}
	t.Logf("%s", in)
}
