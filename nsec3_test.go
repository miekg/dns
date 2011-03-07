package dns

import (
	"testing"
)

func TestPackNsec3(t *testing.T) {
        nsec3 := Nsec3Hash("dnsex.nl", 1, 0, "DEAD")
        t.Logf("%v\n", nsec3)
        t.Fail()
}
