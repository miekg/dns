package dns

import (
	"fmt"
	"testing"
)

func TestCompareLabels(t *testing.T) {
	s1 := "www.miek.nl."
	s2 := "miek.nl."
	s3 := "www.bla.nl."
	s4 := "nl.www.bla."
	s5 := "nl"

	if CompareLabels(s1, s2) != 2 {
		t.Logf("%s with %s should be %d", s1, s2, 2)
		t.Fail()
	}
	if CompareLabels(s1, s3) != 1 {
		t.Logf("%s with %s should be %d", s1, s3, 1)
		t.Fail()
	}
	if CompareLabels(s3, s4) != 0 {
		t.Logf("%s with %s should be %d", s3, s4, 0)
		t.Fail()
	}
	if CompareLabels(s1, s5) != 1 {
		t.Logf("%s with %s should be %d", s1, s5, 1)
		t.Fail()
	}
}

func TestSplitLabels(t *testing.T) {
        s1 := "www.miek.nl."
        s2 := "www.miek.nl"
        s3 := `www\.miek.nl.`
        s4 := `www\\.miek.nl.`

        println(len(SplitLabels(s1)))
        fmt.Printf("%v\n", SplitLabels(s1))
        println(len(SplitLabels(s2)))
        fmt.Printf("%v\n", SplitLabels(s2))
        println(len(SplitLabels(s3)))
        fmt.Printf("%v\n", SplitLabels(s3))
        println(len(SplitLabels(s4)))
        fmt.Printf("%v\n", SplitLabels(s4))
}
