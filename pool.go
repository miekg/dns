// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

// Inspired copied from:
// http://blog.cloudflare.com/recycling-memory-buffers-in-go
// ... carries no license ...

import (
	"container/list"
	"time"
)

func mkBuf(size int) []byte { return make([]byte, size) }

type queued struct {
	when time.Time
	buf  []byte
}

func pool(size, bufsize int) (get, give chan []byte) {
	get = make(chan []byte, bufsize)
	give = make(chan []byte, bufsize)

	go func() {
		q := new(list.List)
		for {
			e := q.Front()
			if e == nil {
				q.PushFront(queued{when: time.Now(), buf: mkBuf(size)})
				e = q.Front()
			}

			timeout := time.NewTimer(time.Minute)
			select {
			case b := <-give:
				timeout.Stop()
				q.PushFront(queued{when: time.Now(), buf: b})

			case get <- e.Value.(queued).buf:
				timeout.Stop()
				q.Remove(e)

			case <-timeout.C:
				e := q.Front()
				for e != nil {
					n := e.Next()
					if time.Since(e.Value.(queued).when) > time.Minute {
						q.Remove(e)
						e.Value = nil
					}
					e = n
				}
			}
		}

	}()
	return
}
