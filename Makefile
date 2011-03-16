# Copyright 2009 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.
.PHONY: examples _examples

include $(GOROOT)/src/Make.inc

TARG=dns
GOFILES=\
	xfr.go\
	config.go\
	defaults.go\
	dns.go\
	dnssec.go\
	edns.go\
	keygen.go\
	msg.go\
	nsec3.go \
	resolver.go\
	server.go \
	string.go\
	tsig.go\
	types.go\
#	y.go\

include $(GOROOT)/src/Make.pkg

#y.go:	dns.y
#	goyacc dns.y

_examples:
	gomake -C _examples

examples:
	gomake -C _examples
