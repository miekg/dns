package dns

import "testing"

// special input test
func TestNewRRSpecial(t *testing.T) {
	var (
		rr     RR
		err    error
		expect string
	)

	rr, err = NewRR("; comment")
	expect = ""
	if err != nil {
		t.Errorf("unexpect err: %s", err)
	}
	if rr != nil {
		t.Errorf("unexpect result: [%s] != [%s]", rr, expect)
	}

	rr, err = NewRR("")
	expect = ""
	if err != nil {
		t.Errorf("unexpect err: %s", err)
	}
	if rr != nil {
		t.Errorf("unexpect result: [%s] != [%s]", rr, expect)
	}

	rr, err = NewRR("$ORIGIN foo.")
	expect = ""
	if err != nil {
		t.Errorf("unexpect err: %s", err)
	}
	if rr != nil {
		t.Errorf("unexpect result: [%s] != [%s]", rr, expect)
	}

	rr, err = NewRR(" ")
	expect = ""
	if err != nil {
		t.Errorf("unexpect err: %s", err)
	}
	if rr != nil {
		t.Errorf("unexpect result: [%s] != [%s]", rr, expect)
	}

	rr, err = NewRR("\n")
	expect = ""
	if err != nil {
		t.Errorf("unexpect err: %s", err)
	}
	if rr != nil {
		t.Errorf("unexpect result: [%s] != [%s]", rr, expect)
	}

	rr, err = NewRR("foo. A 1.1.1.1\nbar. A 2.2.2.2")
	expect = "foo.\t3600\tIN\tA\t1.1.1.1"
	if err != nil {
		t.Errorf("unexpect err: %s", err)
	}
	if rr == nil || rr.String() != expect {
		t.Errorf("unexpect result: [%s] != [%s]", rr, expect)
	}
}
