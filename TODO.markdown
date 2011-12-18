# TODO

Must of the stuff is working, but there is a list of smaller
things that need to be fixed.

* Parsing
    * $ORIGIN and $INCLUDE 
    * HIP RR (needs list of domain names, need slice for that);
* Need to define a handy zone data structure (r/b tree)?.

* Use the Exchange structure to deal with errors when resolving, esp. Timeout
* encoding NSEC3/NSEC bitmaps, DEcoding works;
* IsSubdomain, IsGlue helper functions;
* Cleanup?
* String compression *inside* the library, so the string
  miek.nl is stored once and all RRs reference it. Would be
  a major memory saver;

## Issues

* Check the network order, it works now, but this is on Intel?
* Compression. Take stuff from Jan Mercl.

## Examples to create

* Nameserver, with a small zone, 1 KSK and online signing;
* Recursor - ala FunkenSturm?
