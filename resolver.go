// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// DNS resolver client: see RFC 1035.

package dns

import (
	"os"
)

// Request a query by sending to this channel.
var QueryRequest chan Query // *Query
// Listen for replies on this channel.
var QueryReply chan Query

// Query is used to communicate with the Query* functions.
type Query struct {
	// The query message. 
	Msg *Msg
	// A Conn. Its only required to fill out Conn.RemoteAddr.
	// Optionally you may set Conn.Tsig if TSIG is required.
	// The rest of the structure is filled by the Query functions.
	Conn *Conn
        //
        Err os.Error
}

// QueryAndServeTCP listens for incoming requests on channel in and
// then calls f.
// The function f is executed in a seperate goroutine and performs the actual
// TCP query.
func QueryAndServeTCP(f func(*Conn, *Msg)) os.Error {
        if f == nil {
                return ErrHandle
        }
        if QueryReply == nil {
                QueryReply = make(chan Query)
        }
        if QueryRequest == nil {
                QueryRequest = make(chan Query)
        }
	query("tcp", f)
	return nil
}

// QueryAndServeUDP listens for incoming requests on channel in and
// then calls f.
// The function f is executed in a seperate goroutine and performs the actual
// UDP query.
func QueryAndServeUDP(f func(*Conn, *Msg)) os.Error {
        if f == nil {
                return ErrHandle
        }
        if QueryReply == nil {
                QueryReply = make(chan Query)
                println("Creating channel reply")
        }
        if QueryRequest == nil {
                QueryRequest = make(chan Query)
                println("Creating channel request")
        }
	query("udp", f)
	return nil
}

func query(n string, f func(*Conn, *Msg)) {
        println("in query")
	for {
		select {
		case q := <-QueryRequest:
                        println("recveived request")
			err := q.Conn.Dial(n)
			if err != nil {
				QueryReply <- Query{Err: err}
			}
			go f(q.Conn, q.Msg)
		}
	}
	panic("not reached")
}

// Simple query function that waits for and returns the reply.
func QuerySimple(d *Conn, m *Msg) (*Msg, os.Error) {
	buf, ok := m.Pack()
	if !ok {
		return nil, ErrPack
	}
	// Dialing should happen in the client

	ret, err := d.Exchange(buf, false)
	if err != nil {
		return nil, err
	}
	o := new(Msg)
	if ok := o.Unpack(ret); !ok {
		return nil, ErrUnpack
	}
	return o, nil
}
