# TODO

Must of the stuff is working, but there is a list of smaller
things that need to be fixed.

* Parsing
* Speed, we can always go faster. A simple reflect server now hits 30/40K qps
* Add handy zone data structure (r/b tree)? Or not...
* Use the Exchange structure to deal with errors when resolving, esp. Timeout
* IsSubdomain, IsGlue helper functions;
* SaltLength in NSEC3 is ugly to set, should be automatically done. There are prolly a few more
   settings just like that -- need to look at them.
   -edns NSID is another
* Add tsig check in 'q'?
* More RRs to add. Parsing of strings within the rdata
* Unknown RR parsing
* \DDD in zonefiles

## BUGS

* ListenAndServe has trouble with v6:
    Failed to setup the udp6 server: listen udp6 <nil>:8053: address already in use
    Failed to setup the tcp6 server: listen tcp6 <nil>:8053: address already in use

## Examples to add

* Nameserver, with a small zone, 1 KSK and online signing;
* Recursor - ala FunkenSturm?
