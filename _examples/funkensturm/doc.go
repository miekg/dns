// Copyright 2011 Miek Gieben. All rights reserved.
// Lisenced under the GPLv2

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

Usage:
        funkensturm [flags]

The flags are:

        -sserver
                        Listener address and port for the server. This has to be
                        specified as: address:port, for instance 127.0.0.1:8053.
                        This is also the default.
        -rserver 
                        Remote server address in address:port format. This can be
                        repeated, for each rserver a resolver channel is created.
                        The first begin `qr[0]`, the second `qr[1]`, etc.
                        The default is: 127.0.0.1:53

Debugging flags:

        -verbose
                        Print packets as they flow through Funkensturm.

Predefined configurations are shown in `config_delay.go` and `config_sign.go`. The
default `config.go` implements a transparant proxy.

Also see: http://www.miek.nl/blog/archives/2011/01/23/funkensturm/index.html
*/
package documentation
