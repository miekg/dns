# Copyright 2009 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

include $(GOROOT)/src/Make.inc

TARG=dns
GOFILES=\
	parse.go\
	msg.go\
	resolver.go \
	types.go\
	edns.go \

include $(GOROOT)/src/Make.pkg

p: restest manglertest ednstest dnssectest

# too lazy to lookup how this works again in Makefiles
restest: restest.go $(GOFILES)
	6g -I _obj restest.go && 6l -L _obj -o restest restest.6

ednstest: ednstest.go $(GOFILES)
	6g -I _obj ednstest.go && 6l -L _obj -o ednstest ednstest.6

manglertest: manglertest.go $(GOFILES)
	6g -I _obj manglertest.go && 6l -L _obj -o manglertest manglertest.6

dnssectest: dnssectest.go $(GOFILES)
	6g -I _obj dnssectest.go && 6l -L _obj -o dnssectest dnssectest.6
