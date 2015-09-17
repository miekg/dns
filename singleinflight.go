// Copyright 2013 The Go Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Adapted for dns package usage by Miek Gieben.

package dns

import (
	"sync"
	"time"
)

// call is an in-flight or completed singleflight.Do call
type call struct {
	val *Msg
	rtt time.Duration
	err error
	dup bool
	sync.WaitGroup
}

// singleflight represents a class of work and forms a namespace in
// which units of work can be executed with duplicate suppression.
type singleflight struct {
	sync.Mutex                  // protects m
	m          map[string]*call // lazily initialized
}

// Do executes and returns the results of the given function, making
// sure that only one execution is in-flight for a given key at a
// time. If a duplicate comes in, the duplicate caller waits for the
// original to complete and receives the same results.
// The return value shared indicates whether v was given to multiple callers.
func (g *singleflight) Do(key string, fn func() (*Msg, time.Duration, error)) (v *Msg, rtt time.Duration, err error) {

	g.Lock()
	// initialize
	if g.m == nil {
		g.m = make(map[string]*call)
	}
	// see if there is line at the gate we need
	c, ok := g.m[key]
	if ok { // wait in line and copy the result
		c.dup = true
		g.Unlock()
		c.Wait()
		if c.val == nil {
			return c.val, c.rtt, c.err
		}
		return c.val.Copy(), c.rtt, c.err
	}

	// leader falls here
	c = new(call)
	c.Add(1)
	defer c.Done()

	g.m[key] = c
	g.Unlock()

	c.val, c.rtt, c.err = fn()

	g.Lock()
	defer g.Unlock()

	delete(g.m, key)
	if !c.dup || c.val == nil {
		// nobody can join anymore
		return c.val, c.rtt, c.err
	}
	return c.val.Copy(), c.rtt, c.err
}
