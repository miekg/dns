package dns

import "testing"

func TestSprintf(t *testing.T) {
	ra, _ := NewRR("miek.nl. 2700 IN A 127.0.0.1")

	s := Sprintf("%n hello, %T\n", ra)
	if s != "miek.nl. hello, 2700\n" {
		t.Logf("%v\n", s)
		t.Fail()
	}
}
