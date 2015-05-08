package dns

import (
	"bytes"
	"fmt"
	"net"
	"runtime"
	"testing"
	"time"
)

func getzonememcost(t *testing.T) []RR {
	const LENGTH = 1000000

	buf := bytes.NewBuffer(nil)
	for i := 0; i < LENGTH; i++ {
		fmt.Fprintf(buf, "node%d.example.org 3600 IN A 1.2.3.4\n", i)
	}

	var rr_storage = make([]RR, LENGTH)

	// garbage-collect now to avoid delays in test
	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	var memBefore, memAfter runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	start := time.Now().UnixNano()
	to := ParseZone(buf, "", "parse_test.db")
	var i int
	for x := range to {
		if x.Error != nil {
			t.Error(x.Error)
			continue
		}
		rr_storage[i] = x.RR
		i++
	}
	delta := time.Now().UnixNano() - start

	time.Sleep(10 * time.Millisecond)
	runtime.ReadMemStats(&memAfter)
	t.Log("TotalAlloc:", memAfter.TotalAlloc-memBefore.TotalAlloc, "  HeapInuse:", memAfter.HeapInuse-memBefore.HeapInuse, "  HeapObjects:", memAfter.HeapObjects-memBefore.HeapObjects)

	t.Logf("%d RRs parsed in %.2f s (%.2f RR/s)", i, float32(delta)/1e9, float32(i)/(float32(delta)/1e9))

	return rr_storage
}

func oldSetA(h RR_Header, c chan lex, o, f string) (RR, *ParseError, string) {
	rr := new(A)
	rr.Hdr = h

	l := <-c
	if l.length == 0 { // Dynamic updates.
		return rr, nil, ""
	}
	rr.A = net.ParseIP(l.token)
	if rr.A == nil {
		return nil, &ParseError{f, "bad A A", l}, ""
	}
	return rr, nil, ""
}

func TestZoneMemCostNew(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}
	_ = getzonememcost(t)
}

func TestZoneMemCostOld(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}
	oldParser := typeToparserFunc[TypeA]
	defer func() {
		typeToparserFunc[TypeA] = oldParser
	}()
	typeToparserFunc[TypeA] = parserFunc{oldSetA, false}
	_ = getzonememcost(t)
}
