/*
Funkensturm rewrites DNS packets in the broadest sense of the word.
The rewriting can include delayed (re)sending of packets, (re)sending
packets to multiple servers, rewriting the packet contents, for instance
by signing a packet, or the other way around, stripping the signatures.

In its essence this is no different that a recursive nameserver, which also
receives and sends queries. The difference is the huge amount of tweaking
Funkensturm offers.

The configuration of Funkensturm is done by writing it in Go - a
separate configuration language was deemed to be unpractical and
would limit the possibilities.

*/
package documentation
