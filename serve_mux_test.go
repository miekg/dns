package dns

import "testing"

func TestDotAsCatchAllWildcard(t *testing.T) {
	mux := NewServeMux()
	mux.Handle(".", HandlerFunc(HelloServer))
	mux.Handle("example.com.", HandlerFunc(AnotherHelloServer))

	handler := mux.match("www.miek.nl.", TypeTXT)
	if handler == nil {
		t.Error("wildcard match failed")
	}

	handler = mux.match("www.example.com.", TypeTXT)
	if handler == nil {
		t.Error("example.com match failed")
	}

	handler = mux.match("a.www.example.com.", TypeTXT)
	if handler == nil {
		t.Error("a.www.example.com match failed")
	}

	handler = mux.match("boe.", TypeTXT)
	if handler == nil {
		t.Error("boe. match failed")
	}
}

func TestCaseFolding(t *testing.T) {
	mux := NewServeMux()
	mux.Handle("_udp.example.com.", HandlerFunc(HelloServer))

	handler := mux.match("_dns._udp.example.com.", TypeSRV)
	if handler == nil {
		t.Error("case sensitive characters folded")
	}

	handler = mux.match("_DNS._UDP.EXAMPLE.COM.", TypeSRV)
	if handler == nil {
		t.Error("case insensitive characters not folded")
	}
}

func TestRootServer(t *testing.T) {
	mux := NewServeMux()
	mux.Handle(".", HandlerFunc(HelloServer))

	handler := mux.match(".", TypeNS)
	if handler == nil {
		t.Error("root match failed")
	}
}

func BenchmarkMuxMatch(b *testing.B) {
	mux := NewServeMux()
	mux.Handle("_udp.example.com.", HandlerFunc(HelloServer))

	bench := func(q string) func(*testing.B) {
		return func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				handler := mux.match(q, TypeSRV)
				if handler == nil {
					b.Fatal("couldn't find match")
				}
			}
		}
	}
	b.Run("lowercase", bench("_dns._udp.example.com."))
	b.Run("uppercase", bench("_DNS._UDP.EXAMPLE.COM."))
}

func BenchmarkMuxMatchConcurrent(b *testing.B) {
	var mux ServeMux
	mux.HandleFunc("_udp.example.com.", HelloServer)

	b.RunParallel(func(pb *testing.PB) {
		for i := 0; pb.Next(); i++ {
			if mux.match("_dns._udp.example.com.", TypeSRV) == nil {
				b.Error("couldn't find match")
			}
		}
	})
}

func runMuxBenchmarks(b *testing.B, fn func(*testing.B, *ServeMux), pfn func(*testing.PB, *ServeMux)) {
	b.Run("fresh", func(b *testing.B) {
		fn(b, NewServeMux())
	})
	b.Run("claimed", func(b *testing.B) {
		var mux ServeMux
		mux.match("example.com.", TypeSRV)

		fn(b, &mux)
	})
	b.Run("concurrent+fresh", func(b *testing.B) {
		var mux ServeMux

		b.RunParallel(func(pb *testing.PB) {
			pfn(pb, &mux)
		})
	})
	b.Run("concurrent+claimed", func(b *testing.B) {
		var mux ServeMux
		mux.match("example.com.", TypeSRV)

		b.RunParallel(func(pb *testing.PB) {
			pfn(pb, &mux)
		})
	})
}

func BenchmarkMuxHandleFunc(b *testing.B) {
	runMuxBenchmarks(b, func(b *testing.B, mux *ServeMux) {
		for n := 0; n < b.N; n++ {
			mux.HandleFunc("_dns._udp.example.com.", HelloServer)
		}
	}, func(pb *testing.PB, mux *ServeMux) {
		for pb.Next() {
			mux.HandleFunc("_dns._udp.example.com.", HelloServer)
		}
	})
}

func BenchmarkMuxHandleRemove(b *testing.B) {
	runMuxBenchmarks(b, func(b *testing.B, mux *ServeMux) {
		for n := 0; n < b.N; n++ {
			mux.HandleRemove("_dns._udp.example.com.")
		}
	}, func(pb *testing.PB, mux *ServeMux) {
		for pb.Next() {
			mux.HandleRemove("_dns._udp.example.com.")
		}
	})
}

func BenchmarkMuxHandleAddRemove(b *testing.B) {
	runMuxBenchmarks(b, func(b *testing.B, mux *ServeMux) {
		for n := 0; n < b.N; n++ {
			mux.HandleFunc("_dns._udp.example.com.", HelloServer)
			mux.HandleRemove("_dns._udp.example.com.")
		}
	}, func(pb *testing.PB, mux *ServeMux) {
		for pb.Next() {
			mux.HandleFunc("_dns._udp.example.com.", HelloServer)
			mux.HandleRemove("_dns._udp.example.com.")
		}
	})
}
