# TODO

Must of the stuff is working, but there is a list of smaller things that
need to be fixed.

* Speed, we can always go faster. A simple reflect server now hits 35/45K qps
* go test; only works correct on my machine
* Add handy zone data structure (r/b tree)? Or not...
* privatekey.Precompute() when signing? 
* Add source/dest and RTT timing in dns.Msg structure???

## Examples to add

* Nameserver, with a small zone, 1 KSK and online signing;
* Recursor - ala FunkenSturm?


