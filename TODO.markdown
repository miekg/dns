# TODO

Must of the stuff is working, but there is a list of smaller things that need to
be fixed.

* Speed, we can always go faster. A simple reflect server now hits 35/45K qps
* go test; only works correct on my machine
* privatekey.Precompute() when signing? 
* outgoing [AI]xfr
* zonereader that extracts glue (or at least signals it) and other usefull stuff?

## Examples to add

* Nameserver, with a small zone, 1 KSK and online signing;
* Recursor - ala FunkenSturm?
