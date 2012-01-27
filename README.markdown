# Alternative (more granular) approach to a DNS library.

Complete and usable DNS library. Most widely used Resource Records are
supported, including the DNSSEC types. It follows a lean and mean philosophy.
If there is stuff you should know as a DNS programmer there isn't a convenience
function for it. For instance I'm pondering if a zone-like structure should be
implemented in the library.

Goals:
* KISS;
* Small API;
* If its easy to code in Go, don't make a function of it.

Features:

* UDP/TCP queries, IPv4 and IPv6;
* RFC 1035 zone file parsing;
* Fast: 
    * reply speed around 30K qps (Faster hardware -> more qps);
    * Parsing RRs (zone files) with 30K RR/s; 
    * This is expected to be optimized further.
* Client and server side programming (mimicking the http package);
* Asynchronous queries for client and server;
* DNSSEC;
* EDNS0;
* AXFR/IXFR;
* TSIG;
* DNS name compression.

Sample programs can be found in the `examples` directory. They can 
be build with: `make examples` (after the dns package has been installed)

See this [mini howto](http://www.miek.nl/blog/archives/2012/01/23/super-short_guide_to_getting_q/index.html)
to get things going (including Go itself).

Have fun!

Miek Gieben  -  2010-2012 - miek@miek.nl

## Supported RFCs

All of them:

* 103{4,5}  - DNS standard
* 1982 - Serial Arithmetic
* 1876 - LOC record (incomplete)
* 1995 - IXFR
* 1996 - DNS notify
* 2136 - DNS Update (dynamic updates)
* 2181 - RRset definition
* 2537 - RSAMD5 DNS keys
* 2065 - DNSSEC (updated in later RFCs)
* 2671 - EDNS
* 2782 - SRV
* 2845 - TSIG
* 2915 - NAPTR
* 3110 - RSASHA1 DNS keys
* 3225 - DO bit (DNSSEC OK)
* 340{1,2,3} - NAPTR
* 3597 - Unkown RRs
* 403{3,4,5} - DNSSEC + validation functions
* 4255 - SSHFP
* 4408 - SPF
* 4509 - SHA256 Hash in DS
* 4635 - HMAC SHA TSIG
* 4892 - id.server
* 5001 - NSID 
* 5155 - NSEC3
* 5933 - GOST
* 5936 - AXFR
* xxxx - ECDSA

## Loosely based upon:

* `ldns`
* `NSD`
* `Net::DNS`
* `GRONG`
