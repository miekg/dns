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
	edns.go\

include $(GOROOT)/src/Make.pkg

.PHONY: examples

examples:
	(cd examples; make)

progs: dnssectest keytest readtest

# too lazy to lookup how this works again in Makefiles
dnssectest: dnssectest.go $(GOFILES)
	6g -I _obj dnssectest.go && 6l -L _obj -o dnssectest dnssectest.6

keytest: keytest.go $(GOFILES)
	6g -I _obj keytest.go && 6l -L _obj -o keytest keytest.6

readtest: readtest.go $(GOFILES)
	6g -I _obj readtest.go && 6l -L _obj -o readtest readtest.6
