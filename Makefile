# Copyright 2009 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

include $(GOROOT)/src/Make.inc

TARG=dns
GOFILES=\
	msg.go\
	resolver.go \
	types.go\
	dnssec.go\
	edns.go \

include $(GOROOT)/src/Make.pkg

.PHONY: examples

examples:
	(cd examples; make)

progs: manglertest dnssectest

# too lazy to lookup how this works again in Makefiles
manglertest: manglertest.go $(GOFILES)
	6g -I _obj manglertest.go && 6l -L _obj -o manglertest manglertest.6

dnssectest: dnssectest.go $(GOFILES)
	6g -I _obj dnssectest.go && 6l -L _obj -o dnssectest dnssectest.6
