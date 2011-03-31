// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Generic configuration that is used for nameserver.
// It is meant to be as generic as possible.

package dns

type Config interface {
        // Returns any Tsig information.
        Tsig() *Tsig
}
