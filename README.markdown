# Alternative (more granular) approach to a DNS library.

> Less is more.

Complete and usable DNS library. Most widely used Resource Records are
supported, including the DNSSEC types. It follows a lean and mean philosophy.
If there is stuff you should know as a DNS programmer there isn't a convenience
function for it. 

Goals:

* KISS;
* Symmetric API: client and server side should be very similar;
* Small API;
* If its easy to code in Go, don't make a function for it.

Features:

* UDP/TCP queries, IPv4 and IPv6;
* RFC 1035 zone file parsing;
* Fast: 
    * reply speed around 35K qps (Faster hardware -> more qps);
    * Parsing RRs (zone files) with 35K RR/s, that 5M records in about 142 seconds;
    * This is expected to be optimized further.
* Client and server side programming (mimicking the net/http package);
* Asynchronous queries/replies for client and server;
* DNSSEC;
* EDNS0, NSID;
* AXFR/IXFR;
* TSIG;
* DNS name compression.

Building is done with the `go` tool. If you have setup your GOPATH
correctly the following should work:

    go build dns

Sample programs can be found in the `ex` directory. They can 
be build with: `make -C ex` (after the dns package has been installed)

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
* 3445 - Limiting the scope of (DNS)KEY
* 3597 - Unkown RRs
* 403{3,4,5} - DNSSEC + validation functions
* 4255 - SSHFP
* 4408 - SPF
* 4509 - SHA256 Hash in DS
* 4592 - Wildcards in the DNS
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
