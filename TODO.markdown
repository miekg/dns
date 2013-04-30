# TODO

* Support for on-the-fly-signing
* Use BIND10 memory efficient zone structure?
* NSEC3 support propper in the zone structure(s)
* Test all rdata packing with zero rdata -- allowed for dynamic updates
* Ratelimiting?
* NSEC3/NSEC support function for generating NXDOMAIN respsonse?
* Actually mimic net/ ? Dial. Read/Write ?
* Make compare/split labels faster

## Nice to have

* Speed, we can always go faster. A simple reflect server now hits 45/50K qps
* go test; only works correct on my machine
* privatekey.Precompute() when signing? 

## RR not implemented

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
