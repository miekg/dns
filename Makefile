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
	kparse.go\
	msg.go\
	nsec3.go \
	qnamestring.go\
	server.go \
	rawmsg.go \
	tsig.go\
	types.go\
	update.go\
	xfr.go\
	zparse.go\
	zscan.go\
	zscan_rr.go\


include $(GOROOT)/src/Make.pkg

_examples:
	gomake -C _examples

examples:
	gomake -C _examples

# doesn't work with r59 - disabled until Ragel catches up
# yes, hardcoded path, yes ugly, yes, deal with it
#zparse.go: zparse.rl types.rl
#	/home/miekg/svn/ragel/ragel/ragel -Z -G2 -o $@ $<
#	gofmt -w zparse.go
#
#kparse.go: kparse.rl
#	/home/miekg/svn/ragel/ragel/ragel -Z -G2 -o $@ $<
#	gofmt -w kparse.go
