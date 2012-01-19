# Copyright 2009 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.
.PHONY: examples _examples

include $(GOROOT)/src/Make.inc

TARG=dns
GOFILES=\
	clientconfig.go\
	client.go\
	defaults.go\
	dns.go\
	dnssec.go\
	edns.go\
	keygen.go\
	kscan.go\
	labels.go\
	msg.go\
	nsec3.go \
	rawmsg.go \
	server.go \
	tsig.go\
	types.go\
	update.go\
	xfr.go\
	zscan.go\
	zscan_rr.go\


include $(GOROOT)/src/Make.pkg

examples:
	gomake -C _examples
