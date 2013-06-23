# TODO

* Support for on-the-fly-signing or check how to do it
* Test all rdata packing with zero rdata -- allowed for dynamic updates
* NSEC3/NSEC support function for generating NXDOMAIN response?
* Actually mimic net/ ? Dial. Read/Write ?
* Ratelimiting? server side (rrl)
* Ratelimiting? client side (outstanding queries)

## Nice to have

* Speed, we can always go faster. A simple reflect server now hits 75/80K qps on
    moderate hardware
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
