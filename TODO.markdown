# TODO

Must of the stuff is working, but there is a list of smaller
things that need to be fixed.

* Parsing
    * $INCLUDE 
* Add handy zone data structure (r/b tree)?

* Use the Exchange structure to deal with errors when resolving, esp. Timeout
* encoding NSEC3/NSEC bitmaps, DEcoding works;
* IsSubdomain, IsGlue helper functions;

## Issues

* Check the network order, it works now, but this is on Intel?

## Examples to create

* Nameserver, with a small zone, 1 KSK and online signing;
* Recursor - ala FunkenSturm?
