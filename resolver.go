// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// DNS resolver client: see RFC 1035.

package dns

import (
	"os"
)

// These channels are global so that all parts of the application
// can send queries (or even pick them up).
var (
        // Request an async query by sending to this channel.
        QueryRequest chan *Query
        // Listen for replies to previously sent queries on this channel.
        QueryReply chan *Query
)

// Query is used to communicate with the Query* functions.
type Query struct {
	// The query message which is to be send.
	Query *Msg

        // Any reply message that came back from the wire.
        Reply *Msg

	// It is only required to fill out Conn.RemoteAddr.
	// Optionally you may set Conn.Tsig if TSIG is required.
	// The rest of the structure is filled by the Query functions.
	Conn *Conn

	// If there are any errors there Err is not nil
	Err os.Error
}

// Initialize the QueryRequest and QueryReply channels. This
// is only required when async. queries are wanted.
func InitQueryChannels() {
	QueryRequest = make(chan *Query)
	QueryReply = make(chan *Query)
}

// QueryAndServeTCP listens for incoming requests on channel in and then calls f.
// The function f is executed in a seperate goroutine and performs the actual
// TCP query and should return the result on the QueryReply channel.
func QueryAndServeTCP(f func(*Conn, *Msg)) os.Error {
	if f == nil {
		return ErrHandle
	}
	if QueryReply == nil || QueryRequest == nil {
		return ErrChan
	}
	query("tcp", f)
	return nil
}

// QueryAndServeUDP listens for incoming requests on channel in and then calls f.
// The function f is executed in a seperate goroutine and performs the actual
// UDP query and should return the result on the QueryReply channel.
func QueryAndServeUDP(f func(*Conn, *Msg)) os.Error {
	if f == nil {
		return ErrHandle
	}
	if QueryReply == nil || QueryRequest == nil {
		return ErrChan
	}
	query("udp", f)
	return nil
}

func query(n string, f func(*Conn, *Msg)) {
	for {
		select {
		case q := <-QueryRequest:
			err := q.Conn.Dial(n)
			if err != nil {
				QueryReply <- &Query{Err: err}
			}
			go f(q.Conn, q.Query)
		}
	}
	panic("not reached")
}

// QuerySimple performs a query and waits for the reply before
// returning.
func SimpleQuery(n string, d *Conn, m *Msg) (*Msg, os.Error) {
        err := d.Dial(n)
        if err != nil {
                return nil, err
        }
        o, err := d.ExchangeMsg(m, false)
        d.Close()
	return o, err
}
