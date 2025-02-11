module github.com/zmap/dns

go 1.19

require (
	github.com/miekg/dns v1.1.62
	golang.org/x/net v0.31.0
	golang.org/x/sync v0.7.0
	golang.org/x/sys v0.27.0
	golang.org/x/tools v0.22.0
)

replace github.com/miekg/dns => ./

require golang.org/x/mod v0.18.0 // indirect
