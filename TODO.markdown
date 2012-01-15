# TODO

Must of the stuff is working, but there is a list of smaller
things that need to be fixed.

* Parsing
    * $INCLUDE 
* Add handy zone data structure (r/b tree)?
* Use the Exchange structure to deal with errors when resolving, esp. Timeout
* IsSubdomain, IsGlue helper functions;
* Speed
* SaltLength in NSEC3 is ugly to set, should be automatically done. There are prolly a few more
    settings just like that -- need to look at them.

## Examples to add

* Nameserver, with a small zone, 1 KSK and online signing;
* Recursor - ala FunkenSturm?
