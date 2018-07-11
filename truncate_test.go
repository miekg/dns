package dns

import (
	"fmt"
	"testing"
)

func TestTruncate(t *testing.T) {
	type opts struct {
		edns0    uint16
		compress bool
	}
	type expectation struct {
		truncated         bool
		answer, extra, ns int
	}
	newMsg := func(o opts) *Msg {
		m := new(Msg)
		m.Compress = o.compress
		m.SetQuestion("truncation.example.org.", TypeANY)
		for i := 1; i < 31; i++ {
			m.Answer = append(m.Answer, testRR(fmt.Sprintf("truncation.example.org. 3600 IN SRV 0 0 80 10-10-0-%d.example.org.", i)))
			m.Extra = append(m.Extra, testRR(fmt.Sprintf("10-10-0-%d.example.org. 3600 IN A 10.10.0.%d", i, i)))
		}
		for i := 0; i < 5; i++ {
			m.Ns = append(m.Ns, testRR(fmt.Sprintf("example.org. 86400 IN NS ns%d.example.org.", i)))
			m.Extra = append(m.Extra, testRR(fmt.Sprintf("ns%d.example.org. 3600 IN A 10.1.0.%d", i, i)))
		}
		if o.edns0 > 0 {
			r := &OPT{
				Hdr: RR_Header{
					Name:   ".",
					Rrtype: TypeOPT,
				},
			}
			r.SetVersion(0)
			r.SetUDPSize(o.edns0)
			m.Extra = append(m.Extra, r)
		}
		return m
	}

	tests := []struct {
		name string
		opts opts
		size int
		expt expectation
	}{
		{
			name: "truncated",
			size: 512,
			expt: expectation{truncated: true, answer: 7},
		},
		{
			name: "truncated with edns0",
			opts: opts{edns0: 1024},
			size: 1024,
			expt: expectation{truncated: true, answer: 15, extra: 1},
		},
		{
			name: "answers fit",
			opts: opts{edns0: 2048},
			size: 2048,
			expt: expectation{truncated: false, answer: 30, extra: 1},
		},
		{
			name: "answers and authority fit",
			opts: opts{edns0: 2560},
			size: 2560,
			expt: expectation{truncated: false, answer: 30, extra: 11, ns: 5},
		},
		{
			name: "everything fits",
			opts: opts{edns0: 2048, compress: true},
			size: 2048,
			expt: expectation{truncated: false, answer: 30, extra: 36, ns: 5},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			m := newMsg(test.opts)

			m.Truncate(test.size)

			if want, got := test.size, m.Len(); want < got {
				t.Errorf("want message to fit %d bytes buffer, but size is %d", want, got)
			}
			if want, got := test.expt.truncated, m.Truncated; want != got {
				t.Errorf("want message to be truncated=%t, but got truncated=%t", want, got)
			}
			if want, got := test.expt.answer, len(m.Answer); want != got {
				t.Errorf("want message to have %d answers, but got %d", want, got)
			}
			if want, got := test.expt.extra, len(m.Extra); want != got {
				t.Errorf("want message to have %d additional records, but got %d", want, got)
			}
			if want, got := test.expt.ns, len(m.Ns); want != got {
				t.Errorf("want message to have %d authority records, but got %d", want, got)
			}
			if test.opts.edns0 > 0 && m.IsEdns0() == nil {
				t.Errorf("want message to include OPT header")
			}
		})
	}
}
