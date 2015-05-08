package dns

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"runtime"
	"testing"
	"time"
)

var testbuffer []byte

const testzonelength = 50

func testreader() io.Reader {
	if testbuffer == nil {
		buf := bytes.NewBuffer(nil)
		for i := 0; i < testzonelength; i++ {
			fmt.Fprintf(buf, "node%d.example.org 3600 IN A 1.2.3.4\n", i)
		}
		testbuffer = buf.Bytes()
	}
	return bytes.NewBuffer(testbuffer)
}

func zoneparserbenchmark(b *testing.B) []RR {
	zoneinput := testreader()
	rr_storage := make([]RR, testzonelength*300000)

	// garbage-collect now to avoid delays in test
	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	item, alloc, lastalloc := 0, uint64(0), mem.TotalAlloc
	for bnum := 0; bnum < b.N; bnum++ {

		to := ParseZone(zoneinput, "", "parse_test.db")
		for x := range to {
			if x.Error != nil {
				b.Fatal(x.Error)
				continue
			}
			rr_storage[item] = x.RR
			item++
		}
		runtime.ReadMemStats(&mem)
		alloc += mem.TotalAlloc - lastalloc
		lastalloc = mem.TotalAlloc

	}

	b.Logf("Average alloc growth per iteration: %d (%d parsing rounds)", int(float64(alloc)/float64(b.N)), b.N)
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

func BenchmarkZoneParseWithStringToIPv4(b *testing.B) {
	_ = zoneparserbenchmark(b)
}

func BenchmarkZoneParseWithNetParseIP(b *testing.B) {
	oldParser := typeToparserFunc[TypeA]
	defer func() {
		typeToparserFunc[TypeA] = oldParser
	}()
	typeToparserFunc[TypeA] = parserFunc{oldSetA, false}
	_ = zoneparserbenchmark(b)
}
