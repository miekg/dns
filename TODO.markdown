# TODO

* Support for on-the-fly-signing
* Use BIND10 memory efficient zone structure?
* allow multiple edns0 options to exist in the record when converting
  from/to wireformat
* NSEC3 support propper in the zone structure(s)
* Test all rdata packing with zero rdata -- allowed for dynamic updates
* TSIG is not added in q when the query is for . 

## Nice to have

* Speed, we can always go faster. A simple reflect server now hits 45/50K qps
* go test; only works correct on my machine
* privatekey.Precompute() when signing? 
