# Copyright 2009 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

include $(GOROOT)/src/Make.inc

TARG=dns
GOFILES=\
	msg.go\
	resolver.go \
	types.go\
	edns.go\

include $(GOROOT)/src/Make.pkg

.PHONY: examples

examples:
	(cd examples; make)
