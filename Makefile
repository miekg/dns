# Copyright 2009 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.
.PHONY: examples _examples

include $(GOROOT)/src/Make.inc

TARG=dns
GOFILES=\
	dns.go\
	msg.go\
	types.go\
	edns.go\
	tsig.go\
	dnssec.go\
	keygen.go\


include $(GOROOT)/src/Make.pkg

all: package
	gomake -C resolver package
	gomake -C responder package
	gomake -C strconv package

dnstest:
	gotest
	gomake -C resolver test
	gomake -C responder test
#	gomake -C strconv test

_examples:
	gomake -C _examples

examples:
	gomake -C _examples
