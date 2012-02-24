# TODO

Must of the stuff is working, but there is a list of smaller things that
need to be fixed.

* Speed, we can always go faster. A simple reflect server now hits 30/40K qps
* go test; only work correct on my machine
* Add handy zone data structure (r/b tree)? Or not...
* Use the Exchange structure to deal with errors when resolving, esp. Timeout
* Add tsig check in 'q'?
* ReplyChannel with errors, also do this in axfr/ixfr

## Examples to add

* Nameserver, with a small zone, 1 KSK and online signing;
* Recursor - ala FunkenSturm?
