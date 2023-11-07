// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dns

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// SharedClients holds a set of SharedClient instances.
type SharedClients struct {
	sync.Mutex
	// clients are created and destroyed on demand, hence 'Mutex' needs to be taken.
	clients map[string]*SharedClient
}

func NewSharedClients(ctx context.Context) *SharedClients {
	return &SharedClients{}
}

// GetSharedClient gets or creates an instance of SharedClient keyed with 'key'.
// if 'key' is an empty sting, a new client is always created and it is not actually shared.
func (s *SharedClients) GetSharedClient(key string, conf *Client, serverAddrStr string) (client *SharedClient, closer func()) {
	s.Lock()
	defer s.Unlock()

	if key != "" {
		// locate client to re-use if possible.
		client = s.clients[key]
	}
	if client == nil {
		client = newSharedClient(conf, serverAddrStr)
		if key != "" {
			s.clients[key] = client
		}
	}
	client.refcount++

	return client, func() {
		s.Lock()
		defer s.Unlock()

		client.refcount--
		if client.refcount == 0 {
			// Make client unreachable and close it's connection.
			// Must hold the proxy mutex for this.
			if key != "" {
				delete(s.clients, key)
			}
			// connection must be closed while holding the proxy lock to avoid a race
			// where a new client is created with the same 5-tuple before this one is
			// closed, which could happen if the proxy lock is released before this
			// Close call.
			if client.conn != nil {
				client.conn.Close()
			}
		}
	}
}

var errNoReader = errors.New("Reader stopped")

type Response struct {
	*Msg
	err error
}

// A Client keeps state for concurrent transactions on the same upstream connection.
type SharedClient struct {
	serverAddr string

	*Client

	refcount int // protected by SharedClient's lock

	// this mutex protects writes on 'conn' and all access to 'reqs'
	sync.Mutex
	reqs map[uint16]chan Response // outstanding requests

	// 'readerLock' mutex is used to serialize reads on 'conn'. It is always taken and released
	// while holding the main lock but the main lock can be released and re-acquired while
	// holding 'readerLock' mutex.
	readerLock sync.Mutex

	// Client's connection shared among all requests from the same source address/port. The
	// locks above are used to serialize reads and writes on this connection, but reads and
	// writes can happen at the same time.
	conn *Conn
}

func newSharedClient(conf *Client, serverAddr string) *SharedClient {
	return &SharedClient{
		serverAddr: serverAddr,
		Client:     conf,
		reqs:       make(map[uint16]chan Response),
	}
}

// ExchangeAsync writes the request to the Client's connection and co-operatively
// reads responses from the connection and distributes them to the requestors.
// At most one caller is reading from Client's connection at any time.
func (c *SharedClient) ExchangeAsync(m *Msg) (r *Msg, rtt time.Duration, err error) {
	// Lock allows only one request to be written at a time, but that can happen
	// concurrently with reading.
	c.Lock()
	defer c.Unlock()
	if _, exists := c.reqs[m.Id]; exists {
		return nil, 0, fmt.Errorf("duplicate request: %d", m.Id)
	}

	// Dial if needed
	if c.conn == nil {
		c.conn, err = c.Dial(c.serverAddr)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to dial connection to %v: %w", c.serverAddr, err)
		}
	}

	// Send while holding the client lock, as Client is not made to be usable from
	// concurrent goroutines.
	start := time.Now()
	err = c.SendContext(context.Background(), m, c.conn, start)
	if err != nil {
		return nil, 0, err
	}

	// Create channel for the response with buffer of one, so that write to it
	// does not block if we happen to do it ourselves.
	ch := make(chan Response, 1)
	c.reqs[m.Id] = ch

	// Wait for the response
	var resp Response
	for {
		// Try taking the reader lock
		if c.readerLock.TryLock() {
			// We are responsible for reading responses for all users
			// of this client until we get our own response or an error occurs.
			var err error
			for err == nil {
				// Release the client lock for the duration of the blocking read
				// operation to allow concurrent writes to the underlying
				// connection.
				var r *Msg
				c.Unlock()
				// This ReadMsg() will eventually fail due to the read deadline set
				// by 'Client' on the underlying connection when sending the
				// (last) request.
				r, err = c.conn.ReadMsg()
				c.Lock()
				if err != nil {
					break
				}
				// Locate the request for this response, skipping if not found
				ch, exists := c.reqs[r.Id]
				if !exists {
					continue
				}
				// Pass the response to the waiting requester
				delete(c.reqs, r.Id)
				ch <- Response{Msg: r}
				if r.Id == m.Id {
					// Got our response, quit reading and tell others that
					// its their turn to read.
					err = errNoReader
				}
			}
			// Releasing the reader lock before sending errors on waiter's channels
			// so that when they get them, one of them can take the reader lock.
			c.readerLock.Unlock()
			for id, ch := range c.reqs {
				// Another reader will pick up if any errNoReader errors are sent.
				// Only delete the pending request in other error cases.
				if !errors.Is(err, errNoReader) {
					delete(c.reqs, id)
				}
				ch <- Response{err: err}
			}
		}
		// Get the response of error from the current reader.
		// Unlock for the blocking duration to allow concurrent writes
		// on the client's connection.
		c.Unlock()
		resp = <-ch
		c.Lock()
		if !errors.Is(resp.err, errNoReader) {
			break
		}
		// Trying again
	}
	return resp.Msg, time.Since(start), resp.err
}
