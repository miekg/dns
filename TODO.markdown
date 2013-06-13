# TODO

* Support for on-the-fly-signing or check how to do it
* Test all rdata packing with zero rdata -- allowed for dynamic updates
* NSEC3/NSEC support function for generating NXDOMAIN respsonse?
* Actually mimic net/ ? Dial. Read/Write ?
* Make compare/split labels faster
* Ratelimiting?
* Have infrastructure to keep track of outbound queries and hold some

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
