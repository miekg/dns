# Alternative (more granular) approach to a DNS library.

> Less is more.

Complete and usable DNS library. Most widely used Resource Records are
supported, including the DNSSEC types. It follows a lean and mean philosophy.
If there is stuff you should know as a DNS programmer there isn't a convenience
function for it. 

## Goals:

* KISS;
* Symmetric API: client and server side should be very similar;
* Small API, if its easy to code in Go, don't make a function for it.

## Features:

* UDP/TCP queries, IPv4 and IPv6;
* RFC 1035 zone file parsing;
* Fast: 
    * reply speed around 35/40K qps (Faster hardware -> more qps);
    * Parsing RRs (zone files) with 95/100K RR/s, that's 5M records in about 50 seconds;
    * This is expected to be optimized further.
* Client and server side programming (mimicking the net/http package);
* Asynchronous queries/replies for client and server;
* DNSSEC;
* EDNS0, NSID;
* AXFR/IXFR;
* TSIG;
* DNS name compression.

Have fun!

Miek Gieben  -  2010-2012 - miek@miek.nl

## Building

Building is done with the `go` tool. If you have setup your GOPATH
correctly the following should work:

    go build dns

Sample programs can be found in the `ex` directory. They can 
be build with: `make -C ex`, or also with the `go` tool.

## Building (from scratch)

The development of the language [Go](http://www.golang.org) is
going at a fast pace, hence an updated version of
[Super-short guide to gettinq](http://www.miek.nl/blog/archives/2012/01/23/super-short_guide_to_getting_q/index.html).

Get the latest version (called `weekly`) of Go:

1. Get Go: `hg clone -u release https://go.googlecode.com/hg/ go`
   Note the directory you have downloaded it to and set add its `bin`
   directory to your PATH: `PATH=$PWD/go/bin`.

2. Update Go to the latest weekly: `cd go; hg pull; hg update weekly`

3. Compile Go: `cd src`, you should now sit in `go/src`.
   And compile: `./all.bash`

>    Install missing commands (gcc, sed, bison, etc.) if needed.

The latest Go is now installed. You should now have the `go`-tool,
this is the central interface to all Go program building tasks.

    $ go
    Go is a tool for managing Go source code.

    Usage: go command [arguments]

    The commands are:

    build       compile packages and dependencies
    clean       remove object files
    doc         run godoc on package sources
    fix         run go tool fix on packages
    ....
    ....
    lost more

If you can not run `go`, check your PATH.

### Install Go DNS and set GOPATH

The GOPATH variable specifies (among things) where *your* GO
code lives. Using the `go` tool does bring a few requirement
to the table in how to layout the directory structure.

1. Create toplevel directory (`~/g`)for your code: `mkdir -p ~/g/src`
2. Set GOPATH to this toplevel directory: `export GOPATH=~/g`
1. Get dns: `cd ~/g/src; git clone git://github.com/miekg/dns.git`
2. Compile it: `cd dns; go build`
3. Compile and install the examples, there is a helper `Makefile` here, but it
   just calls `go` multiple times: `cd ex; make`
4. Look in `$GOPATH/bin` for the binaries, in this setup that will be `~/g/bin`
4. Query with q: `~/g/bin/q mx miek.nl` (or add `~/g/bin` to your $PATH too)
5. Report bugs

## Supported RFCs

All of them:

* 103{4,5}  - DNS standard
* 1982 - Serial Arithmetic
* 1876 - LOC record
* 1995 - IXFR
* 1996 - DNS notify
* 2136 - DNS Update (dynamic updates)
* 2181 - RRset definition
* 2537 - RSAMD5 DNS keys
* 2065 - DNSSEC (updated in later RFCs)
* 2671 - EDNS record
* 2782 - SRV record
* 2845 - TSIG record
* 2915 - NAPTR record
* 3110 - RSASHA1 DNS keys
* 3225 - DO bit (DNSSEC OK)
* 340{1,2,3} - NAPTR record
* 3445 - Limiting the scope of (DNS)KEY
* 3597 - Unkown RRs
* 403{3,4,5} - DNSSEC + validation functions
* 4255 - SSHFP record
* 4408 - SPF record
* 4509 - SHA256 Hash in DS
* 4592 - Wildcards in the DNS
* 4635 - HMAC SHA TSIG
* 4701 - DHCID
* 4892 - id.server
* 5001 - NSID 
* 5155 - NSEC3 record
* 5205 - HIP record
* 5702 - SHA2 in the DNS
* 5933 - GOST
* 5936 - AXFR
* xxxx - ECDSA
* xxxx - URI record

## Loosely based upon:

* `ldns`
* `NSD`
* `Net::DNS`
* `GRONG`
