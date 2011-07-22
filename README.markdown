# Alternative (more granular) approach to a DNS library.

Completely usable DNS library. Most widely used Resource Records are
supported including DNSSEC types.

Feaures:

* UDP/TCP queries, IPv4 and IPv6
* TSIG
* EDNS0 (see edns.go)
* AXFR (and IXFR probably)
* Client and server side programming (mimicking the http package)
* Asynchronous queries (client/server)
* RFC 1035 zone file parsing (everything, except multiline records work)

Sample programs can be found in the `_examples` directory. They can 
be build with: `make examples` (after the dns package has been installed)

Everything else should be present and working. If not, drop me an email.

Have fun!

Miek Gieben  -  2010, 2011 - miek@miek.nl

## Supported RFCs and features include:

* 103{4,5}  - DNS standard
* 1982 - Serial Arithmetic
* 1876 - LOC record (incomplete)
* 1995 - IXFR
* 1996 - DNS notify
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
* 5001 - NSID 
* 5155 - NSEC
* 5933 - GOST
* 5936 - AXFR
* xxxx - ECDSA

## Loosely based upon:

* `ldns`
* `NSD`
* `Net::DNS`
* `GRONG`
