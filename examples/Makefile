# Copyright 2009 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

all: mx

# too lazy to lookup how this works again in Makefiles
mx: mx.go
	6g -I ../_obj mx.go && 6l -L ../_obj -o mx mx.6
