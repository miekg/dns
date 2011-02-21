# Alternative (more granular) approach to a DNS library.

Completely usable DNS library. Most widely used Resource Records are
supported. DNSSEC types too.
EDNS0 is (see edns.go), UDP/TCP queries, TSIG, AXFR (and IXFR probably)
too. Both client and server side programming is supported.

Sample programs can be found in the `_examples` directory. They can 
be build with: `make examples` (after the dns package has been installed)

The major omission at the moment is parsing Resource Records from
strings. (i.e. supporting the RFC 1035 zone file format).

Everything else should be present and working. If not, drop me an email.

Have fun!

Miek Gieben  -  2010, 2011 - miek@miek.nl

## Supported RFCs and features include:

* 1034/1035  - DNS standard
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
* 3597 - Unkown RRs
* 4033/4034/4035 - DNSSEC + validation functions
* 4255 - SSHFP
* 4408 - SPF
* 5001 - NSID 
* 5155 - NSEC
* 5936 - AXFR

## Loosely based upon:

* `ldns`
* `NSD`
* `Net::DNS`
* `GRONG`
