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

include $(GOROOT)/src/Make.pkg

all: package
	gomake -C dnssec package
	gomake -C resolver package
#	gomake -C strconv package

install: $(INSTALLFILES)
	gomake -C dnssec install
	gomake -C resolver install
#	gomake -C strconv install

dnstest:
	gotest
	gomake -C dnssec test
	gomake -C resolver test
#	gomake -C strconv test

_examples:
	gomake -C _examples

examples:
	gomake -C _examples
