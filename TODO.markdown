# TODO

Must of the stuff is working, but there is a list of smaller things that
need to be fixed.

* Speed, we can always go faster. A simple reflect server now hits 35/45K qps
* go test; only works correct on my machine
* Add handy zone data structure (r/b tree)? Or not...
* Query source address?

* NSECx bitmap length
  array of 256 block lens set to 0. scan RRs, save highest RR / 8 in
  each block. len is 2 * # non-0 blocks + sum block len
  We now allocate 32 bytes for each nsec3 seen

master¹% ./q -dnssec -tsig axfr.:so6ZGir4GPAqINNh9U5c3A== @localhost mx miek.nl
dns: overflow unpacking OPT
dns: overflow unpacking OPT
;; opcode: QUERY, status: NOERROR, id: 32082
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 1, AD
  
## Examples to add

* Nameserver, with a small zone, 1 KSK and online signing;
* Recursor - ala FunkenSturm?


