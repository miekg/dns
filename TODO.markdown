# TODO

* Support for on-the-fly-signing or check how to do it
* Use BIND10 memory efficient zone structure?
* NSEC3 support propper in the zone structure(s)
* Test all rdata packing with zero rdata -- allowed for dynamic updates
* NSEC3/NSEC support function for generating NXDOMAIN respsonse?
* Actually mimic net/ ? Dial. Read/Write ?
* Make compare/split labels faster
* Ratelimiting?

## Nice to have

* Speed, we can always go faster. A simple reflect server now hits 75/80K qps
* go test; only works correct on my machine
* privatekey.Precompute() when signing? 

## RRs not implemented

These are deprecated, or rarely used (or just a bitch to implement).

NSAP
NSAP-PTR
PX
GPOS
NIMLOC
ATMA
A6
KEY
SIG
NXT
