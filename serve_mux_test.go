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

type mockHandler string

func (mockHandler) ServeDNS(w ResponseWriter, r *Msg) {
	panic("implement me")
}

func TestWildcardMatch(t *testing.T) {
	mux := NewServeMux()
	mux.Handle("example.com.", mockHandler("example.com"))
	mux.Handle("*.example.com.", mockHandler("*.example.com"))
	mux.Handle("a.example.com.", mockHandler("a.example.com"))

	handler := mux.match("www.example.com.", TypeTXT)
	if handler == nil {
		t.Error("example.com match failed")
	}
	if string(handler.(mockHandler)) != "*.example.com" {
		t.Error("www.example.com did not match *.example.com wildcard")
	}

	handler = mux.match("a.example.com.", TypeTXT)
	if handler == nil {
		t.Error("a.example.com match failed")
	}
	if string(handler.(mockHandler)) != "a.example.com" {
		t.Error("a.example.com did not match subdomain a")
	}

	handler = mux.match("example.com", TypeTXT)
	if handler == nil {
		t.Error("example.com match failed")
	}
	if string(handler.(mockHandler)) != "example.com" {
		t.Error("example.com did not match example.com, but with", handler)
	}

	handler = mux.match("foo.bar.example.com", TypeTXT)
	// see https://datatracker.ietf.org/doc/html/rfc4592#section-2.2.1
	// a wildcard does not match names below its zone
	if handler != nil && string(handler.(mockHandler)) == "*.example.com" {
		t.Error("foo.bar.example.com matched unexpectedly with non terminal")
	}
}

func TestTwoWildcardMatch(t *testing.T) {
	mux := NewServeMux()
	mux.Handle(".", mockHandler("root"))
	mux.Handle("example.com.", mockHandler("example"))
	mux.Handle("*.*.example.com.", mockHandler("2wildcard"))

	handler := mux.match("foo.bar.example.com.", TypeTXT)
	if handler == nil {
		t.Error("example.com match failed")
	}
	if string(handler.(mockHandler)) != "wildcard" {
		t.Error("foo.bar.example.com did not match *.*.example.com wildcard")
	}

	handler = mux.match("www.example.com.", TypeTXT)
	if handler != nil {
		t.Error("www.example.com matched *.*.example.com")
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
