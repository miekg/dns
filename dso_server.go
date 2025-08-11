package dns

/*
Caveats:
  - The requirement to abort when unexpected Primary TLV is included in a DSO message sent via
    Early Data is not implemented because crypto/tls does allow to discern it from a regular read.
*/

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"
)

// DSOHandler responds to a DSO message.
type DSOHandler interface {
	// Serve a DSO message.
	// See RFC 8490 Sections 5.4 (specifically 5.4.5) and 5.5.
	//
	// DSOHandler.ServeDSO may write a response and, if appropriate, spawn a long lived operation.
	// This call is blocking and the implementation should return as soon as possible. However,
	// DSOResponseWriter can be retained for future unidirectional and request messages.
	//
	// Cancelation of the passed context signals that the handler should stop its long-lived operations.
	ServeDSO(ctx context.Context, w DSOResponseWriter, m *DSOMsg)
}

// The DSOHandlerFunc type is an adapter to allow the use of ordinary functions
// as DSO handlers. If f is a function with the appropriate signature, DSOHandlerFunc(f)
// is a DSOHandler object that calls f.
type DSOHandlerFunc func(context.Context, DSOResponseWriter, *DSOMsg)

// ServeDSO implements DSOHandler.ServeDSO and calls f(ctx, w, r)
func (f DSOHandlerFunc) ServeDSO(ctx context.Context, w DSOResponseWriter, m *DSOMsg) {
	f(ctx, w, m)
}

// DSOSessionState is the list of states a DSOResponseWriter can take.
type DSOSessionState uint32

const (
	// Waiting for a request to establish a session.
	dsoSessionWaiting DSOSessionState = 0
	// Received a request that may establish a session.
	dsoSessionRequested DSOSessionState = 1 << iota
	// In process of communicating result of the session establishment.
	dsoSessionPending
	// The session is successfully established.
	DSOSessionEstablished
	// CloseDSO was called and the server is waiting for the client to gracefully
	// close the connection. New messages are not accepted.
	// dsoSessionClosing
	// The session is closed and not longer accepts new messages.
	DSOSessionClosed
)

// DSOResponseWriter is an "upgraded" ResponseWriter that accepts DSO messages.
type DSOResponseWriter interface {
	ResponseWriter

	// WaitDSOSession waits until the DSO session is either established or closed.
	//
	// A context may be passed to limit how long to wait for the session to reach the state.
	// When cancelled, WaitDSOSession returns the context's error and the state value should
	// be disregarded.
	WaitDSOSession(ctx context.Context) (DSOSessionState, error)
	// WriteDSOMsg writes a DSO message to the client.
	//
	// Before a DSO session is established only the DSO response message with Id that
	// matches client's initial DSO request message is allowed.
	//
	// Returned ErrDSOMsg and ErrDSOState indicate that passed message is malformed or it's not valid
	// for the current DSO state. Other values indicate a writing error.
	WriteDSOMsg(m *DSOMsg) error
	// CancelDSOMsg asks the client to cancel long-lived operation which it previously requested.
	//
	// See RFC 8490, Section 5.6
	CancelDSOMsg(reqId uint16, rcode int) error
	// CloseDSO asks the client to close the DSO session gracefully.
	//
	// See RFC 8490, Sections 6.6 and 7.2 for circumstances to call this method
	// as well as for acceptable values of retryDelay.
	CloseDSO(retryDelay time.Duration, rcode int) error
	// AbortDSO forcibly closes the connection.
	//
	// Search RFC 8490 for "forcibly abort" for circumstances to call this method.
	AbortDSO() error
}

type dsoSession struct {
	sync.RWMutex
	state DSOSessionState
	// ctx is cancelled when the session is closed.
	ctx    context.Context
	cancel context.CancelFunc
	// pendingCond is broadcasted on to signal that the session changed state from Pending.
	pendingCond *sync.Cond
	// establishedChan is closed to signal that the session is Established.
	establishedChan chan struct{}
	// DSO message id of the initial request to establish DSO session
	initReqId uint16
}

// dsoresponse is an "upgraded" response that implements DSOResponseWriter.
type dsoresponse struct {
	*response

	dso *dsoSession
}

var _ DSOResponseWriter = &dsoresponse{}

func newDSOSession() *dsoSession {
	ctx, cancel := context.WithCancel(context.Background())
	s := &dsoSession{
		ctx:             ctx,
		cancel:          cancel,
		establishedChan: make(chan struct{}),
	}
	s.pendingCond = sync.NewCond(s.RLocker())
	return s
}

func newDSOResponse(w *response) *dsoresponse {
	dsow := &dsoresponse{
		response: w,
		dso:      newDSOSession(),
	}
	return dsow
}

// WaitDSOSession implements the DSOResponseWriter.WaitDSOSession method.
func (dsow *dsoresponse) WaitDSOSession(ctx context.Context) (DSOSessionState, error) {
	select {
	case <-dsow.dso.establishedChan:
	case <-dsow.dso.ctx.Done():
	case <-ctx.Done():
		return dsow.dso.state, context.Cause(ctx)
	}

	dsow.dso.RLock()
	defer dsow.dso.RUnlock()
	switch dsow.dso.state {
	case DSOSessionEstablished:
		return DSOSessionEstablished, nil
	case DSOSessionClosed:
		return DSOSessionClosed, nil
	default:
		panic("dns: internal error: unexpected DSO state")
	}
}

// WriteDSOMsg implements the DSOResponseWriter.WriteDSOMsg method.
func (dsow *dsoresponse) WriteDSOMsg(m *DSOMsg) error {
	buf, err := m.Pack()
	if err != nil {
		return errors.Join(ErrDSOMsg, err)
	}

	// We allow graceful close messages in states where any other message would be disallowed
	// because we follow intent to close DSO session, rather than explicit desire to write bytes
	// to the socket.
	isCloseMsg := m.IsUnidirectional() && len(m.Values) > 0 && m.Values[0].DSOType() == DSOTypeRetryDelay

	dsow.dso.Lock()
	unlockOnce := sync.OnceFunc(dsow.dso.Unlock)
	defer unlockOnce()
	switch dsow.dso.state {
	case dsoSessionWaiting:
		if isCloseMsg {
			dsow.closeSession()
			return nil
		}
		return fmt.Errorf("%w: WriteDSOMsg is called before client requested session", ErrDSOPending)
	case dsoSessionRequested:
		// RFC 8490, Section 5.1.1
		// - User wants to close DSO before it had a chance to establish and thus the RetryDelay
		// unidirectional couldn't be sent. The client will eventually abort and either retry DSO
		// or mark the server as not supporting DSO.
		if isCloseMsg {
			dsow.closeSession()
			return nil
		}

		// RFC 8490, Section 5.1: a server MUST NOT initiate DSO request messages or DSO unidirectional
		// messages until a DSO Session has been mutually established by at least one successful DSO
		// request/response exchange initiated by the client.
		if !m.IsResponse() {
			return errors.Join(ErrDSOMsg, ErrResponse)
		}

		// RFC 8490, Section 5.1: A DSO Session is established over a connection by the client ...
		// receiving a response with a matching MESSAGE ID ...
		if  m.Id != dsow.dso.initReqId {
			return errors.Join(ErrDSOMsg, ErrId)
		}

		dsow.pendingSession()
	case dsoSessionPending:
		return fmt.Errorf("%w: concurrent WriteDSOMsg before session is established", ErrDSOPending)
	case DSOSessionEstablished:
		// RFC 8490, Section 6.6.1.1: At the instant a server chooses to initiate a DSO Retry Delay
		// message, there may be DNS requests already in flight from client to server on this
		// DSO Session, which will arrive at the server after its DSO Retry Delay message has
		// been sent.  The server MUST silently ignore such incoming requests and MUST NOT
		// generate any response messages for them.
		if isCloseMsg {
			dsow.closeSession()
		}
	case DSOSessionClosed:
		return ErrDSOClosed
	default:
		panic("dns: internal error: unknown DSO state")
	}
	unlockOnce()

	_, err = dsow.writer.Write(buf)

	dsow.dso.Lock()
	unlockOnce = sync.OnceFunc(dsow.dso.Unlock)
	defer unlockOnce()
	switch dsow.dso.state {
	case dsoSessionWaiting:
		panic("dns: internal error: unexpected DSO state")
	case dsoSessionRequested:
		panic("dns: internal error: unexpected DSO state")
	case dsoSessionPending:
		defer dsow.dso.pendingCond.Broadcast()
		switch m.Rcode {
		// RFC 8490, Section 5.1.2: When the server receives a DSO request message from a client, and
		// transmits a successful NOERROR response to that request, the server considers the DSO Session
		// established.
		case RcodeSuccess:
			dsow.establishSession()

		// RFC 8490, Section 5.1.1: If the server returns DSOTYPENI, then a DSO Session is not considered
		// established. The client is, however, permitted to continue sending DNS messages on the connection,
		// including other DSO messages such as the DSO Keepalive, which may result in a successful NOERROR
		// response, yielding the establishment of a DSO Session.
		case RcodeStatefulTypeNotImplemented:
			dsow.resetSession()

		// RFC 8490, Section 5.1.1: If the response RCODE is set to NOTIMP (4), or in practice any value other
		// than NOERROR (0) or DSOTYPENI (defined below), then the client MUST assume that the server does not
		// implement DSO at all. In this case, the client is permitted to continue sending DNS messages on that
		// connection but MUST NOT issue further DSO messages on that connection.
		default:
			dsow.closeSession()
		}
		return err
	case DSOSessionEstablished:
		switch {
		case errors.Is(err, syscall.EPIPE) || errors.Is(err, net.ErrClosed):
			dsow.closeSession()
			return errors.Join(ErrDSOClosed, err)
		default:
			return err
		}
	case DSOSessionClosed:
		return errors.Join(ErrDSOClosed, err)
	default:
		panic("dns: internal error: unknown DSO state")
	}
}

// CancelDSOMsg implements the DSOResponseWriter.CancelDSOMsg method.
func (dsow *dsoresponse) CancelDSOMsg(reqId uint16, rcode int) error {
	// RFC 8490, Section 5.6: The responder performs this selective cancellation by sending a new
	// DSO response message ... with nonzero RCODE ...
	if rcode == RcodeSuccess {
		return errors.Join(ErrDSOMsg, ErrRcode)
	}

	resp := new(DSOMsg)
	resp.Id = reqId
	resp.Response = true
	resp.Opcode = OpcodeStateful
	resp.Rcode = rcode
	return dsow.WriteDSOMsg(resp)
}

// CloseDSO implements the DSOResponseWriter.CloseDSO method.
func (dsow *dsoresponse) CloseDSO(retryDelay time.Duration, rcode int) error {
	uni := new(DSOMsg)
	uni.SetClose(retryDelay, rcode)
	err := dsow.WriteDSOMsg(uni)
	if errors.Is(err, ErrDSOClosed) {
		return nil
	}
	return err
}

// AbortDSO implements the DSOResponseWriter.AbortDSO method.
func (dsow *dsoresponse) AbortDSO() error {
	// RFC 8490, Section 5.3: Where this specification says "forcibly abort",
	// it means sending a TCP RST
	// RFC 8765, Section 1.2: Where this specification says "forcibly abort",
	// it means sending a TCP RST to terminate the TCP connection and the TLS
	// session running over that TCP connection.
	setLinger(dsow.tcp, 0)
	return dsow.Close()
}

func (dsow *dsoresponse) requestSession(id uint16) {
	if dsow.dso.state&(dsoSessionWaiting|dsoSessionPending) == 0 {
		panic("dns: internal error: unexpected DSO state")
	}
	dsow.dso.initReqId = id
	dsow.dso.state = dsoSessionRequested
}

func (dsow *dsoresponse) pendingSession() {
	if dsow.dso.state != dsoSessionRequested {
		panic("dns: internal error: unexpected DSO state")
	}
	dsow.dso.state = dsoSessionPending
}

func (dsow *dsoresponse) resetSession() {
	if dsow.dso.state != dsoSessionPending {
		panic("dns: internal error: unexpected DSO state")
	}
	dsow.dso.initReqId = 0
	dsow.dso.state = dsoSessionWaiting
}

func (dsow *dsoresponse) establishSession() {
	if dsow.dso.state != dsoSessionPending {
		panic("dns: internal error: unexpected DSO state")
	}
	dsow.dso.state = DSOSessionEstablished
	close(dsow.dso.establishedChan)
}

func (dsow *dsoresponse) closeSession() {
	if dsow.dso.state == dsoSessionPending {
		defer dsow.dso.pendingCond.Broadcast()
	}
	dsow.dso.state = DSOSessionClosed
	dsow.dso.cancel()
}

func (dsow *dsoresponse) abortSession(locker sync.Locker) {
	if locker != nil {
		locker.Lock()
	}
	dsow.closeSession()
	if locker != nil {
		locker.Unlock()
	}
	if !dsow.hijacked {
		// RFC 8490, Section 5.3: Where this specification says "forcibly abort",
		// it means sending a TCP RST
		setLinger(dsow.tcp, 0)
		dsow.Close()
	}
}

func (srv *Server) serveDSOWithHeader(dh Header, buf []byte, off int, dsow *dsoresponse) {
	// This is a quick check and doesn't have to be reliable.
	if dsow.dso.state == DSOSessionClosed {
		return
	}

	msg := new(DSOMsg)
	msg.setHdr(dh)

	switch action := srv.MsgAcceptFunc(dh); action {
	case MsgAccept:
		err := msg.unpack(dh, buf, off)
		if err == nil {
			break
		}
		err = msg.Validate(false, nil)
		if err != nil {
			srv.MsgInvalidFunc(buf, err)
			dsow.abortSession(sync.Locker(dsow.dso))
			return
		}

		srv.MsgInvalidFunc(buf, err)
		fallthrough
	case MsgReject, MsgRejectNotImplemented:
		msg.SetResponse(msg, RcodeFormatError)
		if action == MsgRejectNotImplemented {
			msg.Rcode = RcodeNotImplemented
		}
		msg.Values = nil
		msg.Zero = 0
		buf, _ := msg.Pack()
		dsow.writer.Write(buf)
		fallthrough
	case MsgIgnore:
		return
	case MsgAbort:
		dsow.abortSession(sync.Locker(dsow.dso))
		return
	}

	dsow.dso.RLock()
	rUnlockOnce := sync.OnceFunc(dsow.dso.RUnlock)
	defer rUnlockOnce()

	for dsow.dso.state == dsoSessionPending {
		dsow.dso.pendingCond.Wait()
	}

	// RFC 8490, Section 6.6.1.1: At the instant a server chooses to initiate a DSO Retry Delay
	// message, there may be DNS requests already in flight from client to server on this
	// DSO Session, which will arrive at the server after its DSO Retry Delay message has
	// been sent.  The server MUST silently ignore such incoming requests and MUST NOT generate
	// any response messages for them.
	if dsow.dso.state == DSOSessionClosed {
		return
	}

	isResponse := dh.Bits&_QR != 0 && dh.Id != 0
	isRequest := dh.Bits&_QR == 0 && dh.Id != 0
	isUnidirectional := dh.Bits&_QR == 0 && dh.Id == 0

	// RFC 8490, Section 5.5.2: If a client or server receives a response (QR=1) where
	// the MESSAGE ID ... is any other value that does not match the MESSAGE ID of any of
	// its outstanding operations, this is a fatal error and the recipient MUST forcibly abort
	// the connection immediately.
	// - in this case client replied to a request that couldn't be sent.
	if isResponse && dsow.dso.state != DSOSessionEstablished {
		rUnlockOnce()
		dsow.abortSession(sync.Locker(dsow.dso))
		return
	}

	// RFC 8490, Section 5.1: Until a DSO Session has been implicitly or explicitly established, a
	// client MUST NOT initiate DSO unidirectional messages.
	if isUnidirectional && dsow.dso.state != DSOSessionEstablished {
		rUnlockOnce()
		dsow.abortSession(sync.Locker(dsow.dso))
		return
	}

	maybeState := dsow.dso.state
	rUnlockOnce()

	// Only serveDSO can advance Waiting to a non-Closed state and it is called strictly sequentially.
	if isRequest && maybeState == dsoSessionWaiting {
		dsow.dso.Lock()
		switch dsow.dso.state {
		case dsoSessionWaiting:
			dsow.requestSession(msg.Id)
			dsow.dso.Unlock()
		case DSOSessionClosed:
			dsow.dso.Unlock()
			return
		default:
			dsow.dso.Unlock()
			panic("dns: internal error: unexpected DSO state")
		}
	}

	srv.DSOHandler.ServeDSO(dsow.dso.ctx, dsow, msg)
}
