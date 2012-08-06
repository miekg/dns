# TODO

* outgoing [AI]xfr
* zonereader that extracts glue (or at least signals it) and other usefull stuff?
* a complete dnssec resolver
* test multiple edns0 options
* fix 'q' standardize ipv6 input with [::1]#53 ?
* simplify querying use function callback with {}interface...  for async querying...?
  Maybe in version v2 of this lib
  Us

## Nice to have

* Speed, we can always go faster. A simple reflect server now hits 35/45K qps
* go test; only works correct on my machine
* privatekey.Precompute() when signing? 

## Examples to add

* Nameserver, with a small zone, 1 KSK and online signing;
* Recursor - ala FunkenSturm?
