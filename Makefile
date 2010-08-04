# Copyright 2009 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

include $(GOROOT)/src/Make.$(GOARCH)

TARG=dns
GOFILES=\
	parse.go\
	dns.go\
	dnsmsg.go\
	dnsconfig.go\
	dnstypes.go\

include $(GOROOT)/src/Make.pkg

restest: restest.go
	6g -I _obj restest.go && 6l -L _obj -o restest restest.6

packtest: packtest.go
	6g -I _obj packtest.go && 6l -L _obj -o packtest packtest.6
