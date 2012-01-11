package dns

import (
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

func TestOffLabelFromRight(t *testing.T) {
        s1 := "www.miek.nl" // fqdn??

        t.Log(offsetLabelFromRight(s1, 4))
        t.Log(offsetLabelFromRight(s1, 3))
        t.Log(offsetLabelFromRight(s1, 2))
        t.Log(offsetLabelFromRight(s1, 1))
        t.Log(offsetLabelFromRight(s1, 0))
//        t.Fail()
}
