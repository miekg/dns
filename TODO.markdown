# TODO

* outgoing [AI]xfr
* test multiple edns0 options
* fix 'q' standardize ipv6 input with [::1]#53 ?
* use function callback with {}interface...  for async querying...?
* merge send/receive in Exchange*()

## Nice to have

* Speed, we can always go faster. A simple reflect server now hits 35/45K qps
* go test; only works correct on my machine
* privatekey.Precompute() when signing? 

## Examples to add

* Nameserver, with a small zone, 1 KSK and online signing;
* Recursor - ala FunkenSturm?
