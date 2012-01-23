# TODO

Must of the stuff is working, but there is a list of smaller
things that need to be fixed.

* Parsing
    * TXT record isn't parsed correctly, if followed by a comment
        - Need to make " important in the parsing
* Speed, we can always go faster. A simple reflect server now hits 30/40K qps
* Add handy zone data structure (r/b tree)?
* Use the Exchange structure to deal with errors when resolving, esp. Timeout
* IsSubdomain, IsGlue helper functions;
* SaltLength in NSEC3 is ugly to set, should be automatically done. There are prolly a few more
    settings just like that -- need to look at them.
    -edns NSID is another
* Add tsig check in 'q'?

## BUGS

## Examples to add

* Nameserver, with a small zone, 1 KSK and online signing;
* Recursor - ala FunkenSturm?
