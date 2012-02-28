# TODO

Must of the stuff is working, but there is a list of smaller things that
need to be fixed.

* Speed, we can always go faster. A simple reflect server now hits 35/45K qps
* go test; only works correct on my machine
* Add handy zone data structure (r/b tree)? Or not...
* Use the Exchange structure to deal with errors when resolving, esp. Timeout
* Add tsig check in 'q'?
* Tsig is handled in the library, api for querying tsig status
* Query source address?
* TEST nsec with TYPE65534

## Examples to add

* Nameserver, with a small zone, 1 KSK and online signing;
* Recursor - ala FunkenSturm?
