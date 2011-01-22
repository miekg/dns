/*
Funkensturm rewrites DNS packets in the broadest sense of the word.
The rewritting can include delayed (re)sending of packets, (re)sending
packets to multiple servers, rewriting the packet contents, for instance
by signing a packet, or the other way around, stripping the signatures.

In its essence this is no different that a recursive nameserver, which also
receives and sends queries. The difference is the huge amount of tweaking
funkensturm offers.

It includes a configuration language which makes setting up funkensturm
real easy. (It may be the case that this configuration language will be Go)

Not sure if this is doable:
- support packet of death (TSIG signed) for stopping funkensturm
- support packet of config (TSIG signed) for configuring funkensturm on the fly

*/
package documentation
