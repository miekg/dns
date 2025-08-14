package dns

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"time"
)

// DSO is a generic DSO TLV.
type DSO interface {
	// DSOType returns the numerical TLV type.
	DSOType() uint16
	// String converts TLV to a readable string.
	String() string
	// Len returns the length of the uncompressed DSO TLV in wire format.
	Len() int
	// Copy creates a deep-copy of TLV.
	Copy() DSO
	// validate checks that the TLV can appear in msg at i.
	// respPrimary indicates whether TLV is a Response Primary or Response Additional TLV.
	validate(server bool, msg *Msg, i int, primary bool, respPrimary bool) error
	// len calculates and returns TLV length in an (un)compressed wire format.
	//
	// If compression is nil, the uncompressed size will be returned, otherwise the compressed
	// size will be returned and domain names will be added to the map for future compression.
	len(off int, compression map[string]struct{}) int
	// pack converts TLV to a wire format.
	pack(buf []byte, off int, compression compressionMap, compress bool) (off1 int, err error)
	// unpack sets TLV according to the wire format.
	unpack(buf []byte, off int) (int, error)
}

// makeDSO creates DSO TLV from the type.
func makeDSO(t uint16) DSO {
	switch t {
	case StatefulTypeKeepAlive:
		return new(DSOKeepAlive)
	case StatefulTypeRetryDelay:
		return new(DSORetryDelay)
	case StatefulTypeEncryptionPadding:
		return new(DSOEncryptionPadding)
	case StatefulType8765Subscribe:
		return new(DSO8765Subscribe)
	case StatefulType8765Push:
		return new(DSO8765Push)
	case StatefulType8765Unsubscribe:
		return new(DSO8765Unsubscribe)
	case StatefulType8765Reconfirm:
		return new(DSO8765Reconfirm)
	case StatefulTypeReserved:
		return nil
	default:
		tlv := new(DSOLocal)
		tlv.dsotype = t
		return tlv
	}
}

// dsoTypeToString converts DSO TLV type to a readable value. Accepts unassigned
// as well as experimental/local types.
func dsoTypeToString(t uint16) string {
	str, ok := StatefulTypeToString[t]
	if !ok {
		str = fmt.Sprintf("type%04X", t)
	}
	return str
}

// PackDSO creates wire format from the DSO TLV.
func PackDSO(tlv DSO, msg []byte, off int, compression compressionMap, compress bool) (headerEnd int, off1 int, err error) {
	if tlv == nil {
		return len(msg), len(msg), &Error{"nil dso"}
	}

	off, err = packUint16(uint16(tlv.DSOType()), msg, off)
	headerEnd = off
	if err != nil {
		return headerEnd, off, ErrBuf
	}

	// Length is set after the TLV is packed due possible of compression.
	off, err = packUint16(0, msg, off)
	headerEnd = off
	if err != nil {
		return headerEnd, off, ErrBuf
	}

	off, err = tlv.pack(msg, off, compression, compress)
	if err != nil {
		return headerEnd, off, err
	}

	vlen := off - headerEnd
	if int(uint16(vlen)) != vlen { // overflow
		return len(msg), len(msg), ErrRdata
	}

	// Set the DSO length field once wire length is known.
	binary.BigEndian.PutUint16(msg[headerEnd-2:], uint16(vlen))
	return headerEnd, off, nil
}

// UnpackDSO creates DSO TLV from the wire format.
func UnpackDSO(msg []byte, off int) (tlv DSO, off1 int, err error) {
	vtype, off, err := unpackUint16(msg, off)
	if err != nil {
		return nil, len(msg), ErrBuf
	}

	vlen, off, err := unpackUint16(msg, off)
	if err != nil {
		return nil, len(msg), ErrBuf
	}
	end := off + int(vlen)
	if end > len(msg) {
		return nil, len(msg), fmt.Errorf("%w: bad DSO data length", ErrRdata)
	}

	tlv = makeDSO(vtype)
	if tlv == nil {
		return nil, end, fmt.Errorf("%w: bad DSO type %d", ErrRdata, vtype)
	}
	if off, err = tlv.unpack(msg[:end], off); err != nil {
		return nil, end, err
	}
	if off != end {
		return nil, end, fmt.Errorf("%w: bad DSO data length", ErrRdata)
	}

	return tlv, off, nil
}

// SetDSOUnidirectional sets Msg to a unidirectional message.
func SetDSOUnidirectional(m *Msg) *Msg {
	m.Id = 0
	m.Response = false
	m.Opcode = OpcodeStateful
	m.Rcode = RcodeSuccess
	return m
}

// SetDSORequest sets Msg to a request message with the ID.
func SetDSORequest(m *Msg, id uint16) *Msg {
	m.Id = id
	m.Response = false
	m.Opcode = OpcodeStateful
	m.Rcode = RcodeSuccess
	return m
}

// SetDSOResponse sets Msg to a response message for the request.
func SetDSOResponse(m *Msg, req *Msg, rcode int) *Msg {
	m.Id = req.Id
	m.Response = true
	m.Opcode = OpcodeStateful
	m.Rcode = RcodeSuccess
	return m
}

// SetDSOClose sets Msg to a graceful close unidirectional message.
// See RFC 8490, Section 6.6.1
func SetDSOClose(m *Msg, retryDelay time.Duration, rcode int) *Msg {
	SetDSOUnidirectional(m)
	m.Rcode = rcode
	m.Stateful = []DSO{&DSORetryDelay{uint32(retryDelay.Milliseconds())}}
	return m
}

// IsDSOHeader checks whether Header (wire format) is appropriate for DSO message.
// See RFC 8490, Section 5.4 and 5.4.1
func IsDSOHeader(dh Header) bool {
	opcode := int(dh.Bits>>11) & 0xF
	response := dh.Bits&_QR != 0

	isStateful := opcode == OpcodeStateful
	isStateful = isStateful && (!response || dh.Id != 0)
	isStateful = isStateful && dh.Qdcount == 0 && dh.Ancount == 0 && dh.Nscount == 0 && dh.Arcount == 0
	return isStateful
}

// IsDSOMsg checks whether Msg is a DSO message.
//
// The decision is based on MsgHdr. To verify that message's TLV(s) are appopriate
// use the IsValidDSOMsg.
func IsDSOMsg(m *Msg) bool {
	switch {
	case m == nil:
		return false
	case m.MsgHdr.Opcode != OpcodeStateful:
		return false
	case m.MsgHdr.Response && m.MsgHdr.Id == 0:
		return false
	case len(m.Question) != 0 || len(m.Answer) != 0 || len(m.Ns) != 0 || len(m.Extra) != 0:
		return false
	default:
		return true
	}
}

// IsDSORequest checks whether Msg is a DSO request message.
//
// The decision is based on MsgHdr. To verify that message's TLV(s) are appopriate
// use the IsValidDSOMsg.
func IsDSORequest(m *Msg) bool {
	return IsDSOMsg(m) && m.MsgHdr.Id != 0 && !m.MsgHdr.Response && len(m.Stateful) > 0
}

// IsDSOUnidirectional checks whether Msg is a DSO unidirectional message.
//
// The decision is based on MsgHdr. To verify that message's TLV(s) are appopriate
// use the IsValidDSOMsg.
func IsDSOUnidirectional(m *Msg) bool {
	return IsDSOMsg(m) && m.MsgHdr.Id == 0 && !m.MsgHdr.Response && len(m.Stateful) > 0
}

// IsDSOResponse checks whether Msg is a DSO unidirectional message.
//
// The decision is based on MsgHdr. To verify that message's TLV(s) are appopriate
// use the IsValidDSOMsg.
func IsDSOResponse(m *Msg) bool {
	return IsDSOMsg(m) && m.MsgHdr.Id != 0 && m.MsgHdr.Response
}

// IsValidDSOMsg checks that Msg, including its TLVs, is valid when composed on server (server = true)
// or client (server = false). Optionally, the request message can be passed to verify that Msg
// is a valid response.
//
// Validation errors are fatal and must be followed up by forcibly closing the connection.
// Error type indicates invalid part of the message.
func IsValidDSOMsg(m *Msg, server bool, req *Msg) error {
	if !IsDSOMsg(m) {
		return &Error{"invalid dso header"}
	}
	if req != nil && !IsDSORequest(req) {
		return &Error{"req is invalid dso request"}
	}
	// RFC 8490, Section 5.4.1: If a DSO response message (QR=1) is received where the
	// MESSAGE ID is zero, this is a fatal error
	if m.Response && m.Id == 0 {
		return ErrId
	}

	if req != nil {
		if !m.Response {
			return ErrResponse
		}
		if m.Id != req.Id {
			return ErrId
		}
	}

	// RFC 8490, Section 5.4.2: A DSO request message or DSO unidirectional message
	// MUST contain at least one TLV.
	if !m.Response && len(m.Stateful) == 0 {
		return fmt.Errorf("%w: missing primary tlv", ErrRdata)
	}

	// RFC 8490, Section 3: in a DSO response, any TLVs with the same DSO-TYPE as
	// the Primary TLV from the corresponding DSO request message. If present,
	// any Response Primary TLV(s) MUST appear first in the DSO response message,
	// before any Response Additional TLVs.
	respPrimary := req != nil && len(m.Stateful) > 0 && m.Stateful[0].DSOType() == req.Stateful[0].DSOType()
	for i, tlv := range m.Stateful {
		if respPrimary && i > 0 {
			respPrimary = tlv.DSOType() == m.Stateful[i-1].DSOType()
		}
		err := tlv.validate(server, m, i, i == 0, respPrimary)
		if err != nil {
			return err
		}
	}

	return nil
}

// unpackDSOslice unpacks msg[off:] into []DSO.
// If we cannot unpack the whole array, then it will return nil
func unpackDSOslice(msg []byte, off int) (dst1 []DSO, off1 int, err error) {
	var v DSO
	var dst []DSO
	for off < len(msg) {
		v, off, err = UnpackDSO(msg, off)
		if err != nil {
			return nil, len(msg), err
		}
		dst = append(dst, v)
	}
	return dst, off, err
}

// isDSOCompressible checks whether Msg has compressible DSO TLVs.
func isDSOCompressible(m *Msg) bool {
	switch {
	case len(m.Stateful) == 0:
		return false
	case m.Stateful[0].DSOType() == StatefulType8765Push:
		return true
	case m.Stateful[0].DSOType() == StatefulType8765Reconfirm:
		return true
	default:
		return false
	}
}

// All values are in milliseconds.
const (
	// RFC 8490, Section 6.2: On a new DSO Session, if no explicit DSO Keepalive message exchange
    // has taken place, the default value for both timeouts is 15 seconds.
	DSOInactivityTimeoutDefault    = 15 * 1000
	DSOKeepAliveIntervalDefault    = 15 * 1000
	// RFC 8490, Section 6.5.2: By default, it is RECOMMENDED that clients request, and servers
    // grant, a keepalive interval of 60 minutes.
	DSOKeepAliveIntervalRecommened = 60 * 60 * 1000
	// RFC 8490, Section 7.1: The keepalive interval MUST NOT be less than ten seconds.
	DSOKeepAliveIntervalMin        = 10 * 1000
	// RFC 8490, Section 6.5.2: A keepalive interval value of 0xFFFFFFFF represents "infinity"
	// and informs the client that it should generate no DSO keepalive traffic.
	DSOKeepAliveIntervalNever      = 0xFFFFFFFF
	// RFC 8490, Section 6.4.2: An inactivity timeout of 0xFFFFFFFF represents "infinity"
	// and informs the client that it may keep an idle connection open as long as it wishes.
	DSOInactivityTimeoutNever	   = 0xFFFFFFFF
)

// RFC 8490, Section 7.1: Keepalive TLV.
type DSOKeepAlive struct {
	// This is the timeout at which the client MUST begin closing an inactive DSO Session.
	InactivityTimeout uint32
	// This is the interval at which a client MUST generate DSO keepalive traffic to maintain
	// connection state.
	KeepAliveInterval uint32
}

// DSOType implements DSO.DSOType
func (tlv *DSOKeepAlive) DSOType() uint16 {
	return StatefulTypeKeepAlive
}

// String implements DSO.Len
func (tlv *DSOKeepAlive) String() string {
	return fmt.Sprintf("timeout %dms, interval %dms", tlv.InactivityTimeout, tlv.KeepAliveInterval)
}

// Len implements DSO.Len
func (tlv *DSOKeepAlive) Len() int {
	return tlv.len(0, nil)
}

// Copy implements DSO.Copy
func (tlv *DSOKeepAlive) Copy() DSO {
	return &DSOKeepAlive{tlv.InactivityTimeout, tlv.KeepAliveInterval}
}

// validate implements DSO.validate
func (tlv *DSOKeepAlive) validate(server bool, msg *Msg, i int, primary bool, respPrimary bool) error {
	usage := tlvUsage{server, primary, respPrimary, msg}
	switch {
	case usage.c_p():
		// valid
	case usage.c_u():
		return fmt.Errorf("%w: bad keepalive primary tlv", ErrRdata)
	case usage.c_a():
		return fmt.Errorf("%w: bad keepalive additional tlv", ErrRdata)
	case usage.crp():
		// valid
	case usage.cra():
		return fmt.Errorf("%w: bad keepalive response additional tlv", ErrRdata)
	case usage.s_p():
		return fmt.Errorf("%w: bad keepalive primary tlv", ErrRdata)
	case usage.s_u():
		// valid
	case usage.s_a():
		return fmt.Errorf("%w: bad keepalive additional tlv", ErrRdata)
	case usage.srp():
		fallthrough
	case usage.sra():
		return fmt.Errorf("%w: bad keepalive response tlv", ErrRdata)
	}

	if server && tlv.KeepAliveInterval < DSOKeepAliveIntervalMin {
		return fmt.Errorf("%w: bad keepalive interval", ErrRdata)
	}

	return nil
}

// len implements DSO.len
func (tlv *DSOKeepAlive) len(off int, compression map[string]struct{}) int {
	return 8
}

// pack implements DSO.pack
func (tlv *DSOKeepAlive) pack(buf []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	off, err = packUint32(tlv.InactivityTimeout, buf, off)
	if err != nil {
		return len(buf), ErrBuf
	}

	off, err = packUint32(tlv.KeepAliveInterval, buf, off)
	if err != nil {
		return len(buf), ErrBuf
	}
	return off, nil
}

// unpack implements DSO.unpack
func (tlv *DSOKeepAlive) unpack(buf []byte, off int) (off1 int, err error) {
	tlv.InactivityTimeout, off, err = unpackUint32(buf, off)
	if err != nil {
		return len(buf), ErrBuf
	}

	tlv.KeepAliveInterval, off, err = unpackUint32(buf, off)
	if err != nil {
		return len(buf), ErrBuf
	}
	return off, nil
}

// RFC 8490, Section 7.2: Retry Delay TLV.
type DSORetryDelay struct {
	// A time value within which the initiator MUST NOT retry this operation or retry connecting
	// to this server.
	RetryDelay uint32
}

// DSOType implements DSO.DSOType
func (tlv *DSORetryDelay) DSOType() uint16 {
	return StatefulTypeRetryDelay
}

// String implements DSO.String
func (tlv *DSORetryDelay) String() string {
	return (time.Duration(tlv.RetryDelay) * time.Millisecond).String()
}

// Len implements DSO.Len
func (tlv *DSORetryDelay) Len() int {
	return tlv.len(0, nil)
}

// Copy implements DSO.Copy
func (tlv *DSORetryDelay) Copy() DSO {
	return &DSORetryDelay{tlv.RetryDelay}
}

// validate implements DSO.validate
func (tlv *DSORetryDelay) validate(server bool, msg *Msg, i int, primary bool, respPrimary bool) error {
	usage := tlvUsage{server, primary, respPrimary, msg}
	switch {
	case usage.c_p():
		fallthrough
	case usage.c_u():
		return fmt.Errorf("%w: bad retry delay primary tlv", ErrRdata)
	case usage.c_a():
		return fmt.Errorf("%w: bad retry delay additional tlv", ErrRdata)
	case usage.crp():
		return fmt.Errorf("%w: bad retry delay response primary tlv", ErrRdata)
	case usage.cra():
		// valid
	case usage.s_p():
		return fmt.Errorf("%w: bad retry delay primary tlv", ErrRdata)
	case usage.s_u():
		// valid
	case usage.s_a():
		return fmt.Errorf("%w: bad retry delay additional tlv", ErrRdata)
	case usage.srp():
		return fmt.Errorf("%w: bad retry delay response primary tlv", ErrRdata)
	case usage.sra():
		// valid
	}
	return nil
}

// len implements DSO.len
func (tlv *DSORetryDelay) len(off int, compression map[string]struct{}) int {
	return 4
}

// pack implements DSO.pack
func (tlv *DSORetryDelay) pack(buf []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	off, err = packUint32(tlv.RetryDelay, buf, off)
	if err != nil {
		return len(buf), ErrBuf
	}
	return off, nil
}

// unpack implements DSO.unpack
func (tlv *DSORetryDelay) unpack(buf []byte, off int) (off1 int, err error) {
	tlv.RetryDelay, off, err = unpackUint32(buf, off)
	if err != nil {
		return len(buf), ErrBuf
	}
	return off, nil
}

// RFC 8490, Section 7.3: Encryption Padding TLV.
//
// Even the empty TLV adds 4 bytes due to header.
// See also RFC 8467.
type DSOEncryptionPadding struct {
	Padding []byte
}

// DSOType implements the DSO.DSOType
func (tlv *DSOEncryptionPadding) DSOType() uint16 {
	return StatefulTypeEncryptionPadding
}

// String implements DSO.String
func (tlv *DSOEncryptionPadding) String() string {
	return fmt.Sprintf("%0X", tlv.Padding)
}

// Len implements DSO.Len
func (tlv *DSOEncryptionPadding) Len() int {
	return tlv.len(0, nil)
}

// Copy implements DSO.Copy
func (tlv *DSOEncryptionPadding) Copy() DSO {
	return &DSOEncryptionPadding{cloneSlice(tlv.Padding)}
}

// validate implements DSO.validate
func (tlv *DSOEncryptionPadding) validate(server bool, msg *Msg, i int, primary bool, respPrimary bool) error {
	usage := tlvUsage{server, primary, respPrimary, msg}
	switch {
	case usage.c_p():
		fallthrough
	case usage.c_u():
		return fmt.Errorf("%w: bad encryption padding primary tlv", ErrRdata)
	case usage.c_a():
		// valid
	case usage.crp():
		return fmt.Errorf("%w: bad encryption padding response primary tlv", ErrRdata)
	case usage.cra():
		// valid
	case usage.s_p():
		fallthrough
	case usage.s_u():
		return fmt.Errorf("%w: bad encryption padding primary tlv", ErrRdata)
	case usage.s_a():
		// valid
	case usage.srp():
		return fmt.Errorf("%w: bad encryption padding response primary tlv", ErrRdata)
	case usage.sra():
		// valid
	}
	return nil
}

// len implements DSO.len
func (tlv *DSOEncryptionPadding) len(off int, compression map[string]struct{}) int {
	return len(tlv.Padding)
}

// pack implements DSO.pack
func (tlv *DSOEncryptionPadding) pack(buf []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	packLen := len(tlv.Padding)
	if len(buf)-off < packLen {
		return len(buf), ErrBuf
	}
	copy(buf[off:], tlv.Padding)
	off += packLen
	return off, nil
}

// unpack implements DSO.unpack
//
// Takes buf[off:] as DSO-Data. Limit buf if necessary.
func (tlv *DSOEncryptionPadding) unpack(buf []byte, off int) (int, error) {
	tlv.Padding = cloneSlice(buf[off:])
	return len(buf), nil
}

// DSOLocal is intended for experimental/private use as well as for unrecognized TLVs.
type DSOLocal struct {
	dsotype uint16
	// TLV data in wire format verbatim.
	Data    []byte
}

// DSOType implements DSO.DSOType
func (tlv *DSOLocal) DSOType() uint16 {
	return tlv.dsotype
}

// String implements DSO.String
func (tlv *DSOLocal) String() string {
	return fmt.Sprintf("%0X", tlv.Data)
}

// Len implements DSO.Len
func (tlv *DSOLocal) Len() int {
	return tlv.len(0, nil)
}

// Copy implements DSO.Copy
func (tlv *DSOLocal) Copy() DSO {
	return &DSOLocal{tlv.dsotype, cloneSlice(tlv.Data)}
}

// validate implements DSO.validate
func (tlv *DSOLocal) validate(server bool, msg *Msg, i int, primary bool, respPrimary bool) error {
	return nil
}

// len implements DSO.len
func (tlv *DSOLocal) len(off int, compression map[string]struct{}) int {
	return len(tlv.Data)
}

// pack implements DSO.pack
func (tlv *DSOLocal) pack(buf []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	packLen := len(tlv.Data)
	if len(buf)-off < packLen {
		return len(buf), ErrBuf
	}
	copy(buf[off:], tlv.Data)
	off += packLen
	return off, nil
}

// unpack implements DSO.unpack
//
// Takes buf[off:] as DSO-Data. Limit buf if necessary.
func (tlv *DSOLocal) unpack(buf []byte, off int) (int, error) {
	tlv.Data = cloneSlice(buf[off:])
	return len(buf), nil
}

// RFC 8765, Section 6.2: Subscribe TLV.
type DSO8765Subscribe struct {
	// Domain name of RR that subscriber wants.
	//
	// DNS wildcarding is not supported, case insensitivity applies, CNAME matches
	// only a CNAME record.
	Name   string
	// Type of RR that subscriber wants.
	//
	// TypeANY (255) is interepreted to mean "ALL".
	Rrtype uint16
	// Class of RR that subscriber wants.
	//
	// ClassANY (255) is interpreted to mean "ALL".
	Class  uint16
}

// DSOType implements DSO.DSOType
func (tlv *DSO8765Subscribe) DSOType() uint16 {
	return StatefulType8765Subscribe
}

// String implements DSO.String
func (tlv *DSO8765Subscribe) String() (s string) {
	s = ";" + sprintName(tlv.Name) + "\t"
	s += Class(tlv.Class).String() + "\t"
	s += " " + Type(tlv.Rrtype).String()
	return s
}

// Len implements DSO.Len
func (tlv *DSO8765Subscribe) Len() int {
	return tlv.len(0, nil)
}

// Copy implements DSO.Copy
func (tlv *DSO8765Subscribe) Copy() DSO {
	return &DSO8765Subscribe{tlv.Name, tlv.Rrtype, tlv.Class}
}

// validate implements DSO.validate
func (tlv *DSO8765Subscribe) validate(server bool, msg *Msg, i int, primary bool, respPrimary bool) error {
	usage := tlvUsage{server, primary, respPrimary, msg}
	switch {
	case usage.c_p():
		// valid
	case usage.c_u():
		return fmt.Errorf("%w: bad rfc8765 subscribe primary tlv", ErrRdata)
	case usage.c_a():
		return fmt.Errorf("%w: bad rfc8765 subscribe additional tlv", ErrRdata)
	case usage.crp():
		fallthrough
	case usage.cra():
		// RFC 8765, Section 6.2.2: A SUBSCRIBE response message MUST NOT include
		// a SUBSCRIBE TLV.If a client receives a SUBSCRIBE response message containing
		// a SUBSCRIBE TLV, then the response message is processed but the SUBSCRIBE TLV
		// MUST be silently ignored.
	case usage.s_p():
		fallthrough
	case usage.s_u():
		return fmt.Errorf("%w: bad rfc8765 subscribe primary tlv", ErrRdata)
	case usage.s_a():
		return fmt.Errorf("%w: bad rfc8765 subscribe additional tlv", ErrRdata)
	case usage.srp():
		fallthrough
	case usage.sra():
		return fmt.Errorf("%w: bad rfc8765 subscribe response tlv", ErrRdata)
	}
	return nil
}

// len implements DSO.len
func (tlv *DSO8765Subscribe) len(off int, compression map[string]struct{}) int {
	l := domainNameLen(tlv.Name, off, compression, true)
	l += 2 + 2
	return l
}

// pack implements DSO.pack
func (tlv *DSO8765Subscribe) pack(buf []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	off, err = packDomainName(tlv.Name, buf, off, compression, compress)
	if err != nil {
		return len(buf), err
	}

	off, err = packUint16(tlv.Rrtype, buf, off)
	if err != nil {
		return len(buf), ErrBuf
	}

	off, err = packUint16(tlv.Class, buf, off)
	if err != nil {
		return len(buf), ErrBuf
	}

	return off, nil
}

// unpack implements DSO.unpack
func (tlv *DSO8765Subscribe) unpack(buf []byte, off int) (off1 int, err error) {
	tlv.Name, off, err = UnpackDomainName(buf, off)
	if err != nil {
		return len(buf), err
	}

	tlv.Rrtype, off, err = unpackUint16(buf, off)
	if err != nil {
		return len(buf), ErrBuf
	}

	tlv.Class, off, err = unpackUint16(buf, off)
	if err != nil {
		return len(buf), ErrBuf
	}
	return off, nil
}

const (
	// RFC 8765, Section 6.3.1: If the TTL has the value 0xFFFFFFFF, then the DNS Resource Record
	// with the given name, type, class, and RDATA is removed.
	DSO8765PushTTLRemove 		   = 0xFFFFFFFF
	// RFC 8765, Section 6.3.1: If the TTL has the value 0xFFFFFFFE, then this is a 'collective'
	// remove notification.
	DSO8765PushTTLCollectiveRemove = 0xFFFFFFFE
	// If the TTL is in the range 0 to 2,147,483,647 seconds (0 to 231 - 1, or 0x7FFFFFFF),
	// then a new DNS Resource Record with the given name, type, class, and RDATA is added.
	DSO8765PushTTLAddMin = 0
	// If the TTL is in the range 0 to 2,147,483,647 seconds (0 to 231 - 1, or 0x7FFFFFFF),
	// then a new DNS Resource Record with the given name, type, class, and RDATA is added.
	DSO8765PushTTLAddMax = 0x7FFFFFFF
)

// RFC 8765, Section 6.3: Push TLV.
type DSO8765Push struct {
	// Changes (at least one) in RRs the receiver is subscribed to.
	//
	// RR's TTL value may carry special meaning, see RFC 8765, Section 6.3.1 for details.
	Change []RR
}

// DSOType implements DSO.DSOType
func (tlv *DSO8765Push) DSOType() uint16 {
	return StatefulType8765Push
}

// String implements DSO.String
func (tlv *DSO8765Push) String() string {
	switch {
	case len(tlv.Change) == 0:
		return "<nil>"
	case len(tlv.Change) == 1:
		return tlv.Change[0].String()
	default:
		s := "\t" + tlv.Change[0].String()
		for _, r := range tlv.Change[1:] {
			s += "\n\t" + r.String()
		}
		return s
	}
}

// Len implements DSO.Len
func (tlv *DSO8765Push) Len() int {
	return tlv.len(0, nil)
}

// Copy implements DSO.Copy
func (tlv *DSO8765Push) Copy() DSO {
	tlv1 := DSO8765Push{}
	tlv1.Change = make([]RR, len(tlv.Change))
	for i, r := range tlv.Change {
		tlv1.Change[i] = r.copy()
	}
	return &tlv1
}

// validate implements DSO.validate
func (tlv *DSO8765Push) validate(server bool, msg *Msg, i int, primary bool, respPrimary bool) error {
	usage := tlvUsage{server, primary, respPrimary, msg}
	switch {
	case usage.c_p():
		fallthrough
	case usage.c_u():
		return fmt.Errorf("%w: bad rfc8765 push primary tlv", ErrRdata)
	case usage.c_a():
		return fmt.Errorf("%w: bad rfc8765 push additional tlv", ErrRdata)
	case usage.crp():
		fallthrough
	case usage.cra():
		return fmt.Errorf("%w: bad rfc8765 push response tlv", ErrRdata)
	case usage.s_p():
		return fmt.Errorf("%w: bad rfc8765 push primary tlv", ErrRdata)
	case usage.s_u():
		// valid
	case usage.s_a():
		return fmt.Errorf("%w: bad rfc8765 push additional tlv", ErrRdata)
	case usage.srp():
		fallthrough
	case usage.sra():
		return fmt.Errorf("%w: bad rfc8765 push response tlv", ErrRdata)
	}

	// RFC 8765, Section 6.3.1: A PUSH Message MUST contain at least one change notification.
	if len(tlv.Change) == 0 {
		return fmt.Errorf("%w: empty rfc8765 push tlv", ErrRdata)
	}

	for _, r := range tlv.Change {
		h := r.Header()
		switch {
		// RFC 8765, Section 6.3.1: If the TTL is in the range ... 0x7FFFFFFF then a new DNS
		// Resource Record with the given name, type, class, and RDATA is added. Type and class
		// MUST NOT be 255 (ANY).
		case h.Ttl <= 0x7FFFFFFF && (h.Class == ClassANY || h.Rrtype == TypeANY):
			fallthrough
		// RFC 8765, Section 6.3.1: If the TTL has the value 0xFFFFFFFF, then the DNS Resource
		// Record with the given name, type, class, and RDATA is removed. Type and class
		// MUST NOT be 255 (ANY)
		case h.Ttl == 0xFFFFFFFF && (h.Class == ClassANY || h.Rrtype == TypeANY):
			return fmt.Errorf("%w: bad class / type in rfc8765 push tlv", ErrRdata)
		// RFC 8765, Section 6.3.1: If the TTL has the value 0xFFFFFFFE, then this is a
		// 'collective' remove notification. For collective remove notifications,
		// RDLEN MUST be zero
		case h.Ttl == 0xFFFFFFFE && h.Rdlength != 0:
			return fmt.Errorf("%w: non-empty collective removal in rfc8765 push tlv", ErrRdata)
		// RFC 8765, Section 6.3.1: If the TTL is any value other than 0xFFFFFFFF, 0xFFFFFFFE,
		// or a value in the range 0 to 0x7FFFFFFF, then the receiver SHOULD silently ignore
		// this particular change notification record.
		default:
		}
	}

	return nil
}

// len implements DSO.len
func (tlv *DSO8765Push) len(off int, compression map[string]struct{}) int {
	l := off
	for _, r := range tlv.Change {
		l += r.len(l, compression)
	}
	return l - off
}

// pack implements DSO.pack
func (tlv *DSO8765Push) pack(buf []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	for _, r := range tlv.Change {
		_, off, err = packRR(r, buf, off, compression, compress)
		if err != nil {
			return len(buf), err
		}
	}
	return off, nil
}

// unpack implements DSO.unpack
//
// Attempts to unpack as many RRs as possible. Limit buf if necessary.
func (tlv *DSO8765Push) unpack(buf []byte, off int) (off1 int, err error) {
	var r RR
	for off < len(buf) {
		off1 := off
		r, off, err = UnpackRR(buf, off)
		if err != nil {
			return len(buf), err
		}
		if off1 == off {
			break
		}
		tlv.Change = append(tlv.Change, r)
	}
	return off, nil
}

// RFC 8765, Section 6.4: Unsubscribe TLV.
type DSO8765Unsubscribe struct {
	// ID of the previously sent Subscribe request message.
	SubscribeId uint16
}

// DSOType implements DSO.DSOType
func (tlv *DSO8765Unsubscribe) DSOType() uint16 {
	return StatefulType8765Unsubscribe
}

// String implements DSO.String
func (tlv *DSO8765Unsubscribe) String() (s string) {
	return strconv.Itoa(int(tlv.SubscribeId))
}

// Len implements DSO.Len
func (tlv *DSO8765Unsubscribe) Len() int {
	return tlv.len(0, nil)
}

// Copy implements DSO.Copy
func (tlv *DSO8765Unsubscribe) Copy() DSO {
	return &DSO8765Unsubscribe{tlv.SubscribeId}
}

// validate implements DSO.validate
func (tlv *DSO8765Unsubscribe) validate(server bool, msg *Msg, i int, primary bool, respPrimary bool) error {
	usage := tlvUsage{server, primary, respPrimary, msg}
	switch {
	case usage.c_p():
		return fmt.Errorf("%w: bad rfc8765 unsubscribe primary tlv", ErrRdata)
	case usage.c_u():
		// valid
	case usage.c_a():
		return fmt.Errorf("%w: bad rfc8765 unsubscribe additional tlv", ErrRdata)
	case usage.crp():
		fallthrough
	case usage.cra():
		return fmt.Errorf("%w: bad rfc8765 unsubscribe response tlv", ErrRdata)
	case usage.s_p():
		fallthrough
	case usage.s_u():
		return fmt.Errorf("%w: bad rfc8765 unsubscribe primary tlv", ErrRdata)
	case usage.s_a():
		return fmt.Errorf("%w: bad rfc8765 unsubscribe additional tlv", ErrRdata)
	case usage.srp():
		fallthrough
	case usage.sra():
		return fmt.Errorf("%w: bad rfc8765 unsubscribe response tlv", ErrRdata)
	}
	return nil
}

// len implements DSO.len
func (tlv *DSO8765Unsubscribe) len(off int, compression map[string]struct{}) int {
	return 2
}

// pack implements DSO.pack
func (tlv *DSO8765Unsubscribe) pack(buf []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	off, err = packUint16(uint16(tlv.SubscribeId), buf, off)
	if err != nil {
		return len(buf), ErrBuf
	}
	return off, nil
}

// unpack implements DSO.unpack
func (tlv *DSO8765Unsubscribe) unpack(buf []byte, off int) (off1 int, err error) {
	tlv.SubscribeId, off, err = unpackUint16(buf, off)
	if err != nil {
		return len(buf), ErrBuf
	}
	return off, nil
}

// RFC 8765, Section 6.5: Reconfirm TLV.
type DSO8765Reconfirm struct {
	// RR that the sender belives to be stale.
	//
	// RR's type must not be TypeANY (255), class must not be ClassANY (255), wildcarding
	// is not supported, case insensitivity applies, CNAME matches only a CNAME record.
	// RR's TTL is ignored and Rdlength is re-calculated.
	Rr RR
}

// DSOType implements DSO.DSOType
func (tlv *DSO8765Reconfirm) DSOType() uint16 {
	return StatefulType8765Reconfirm
}

// String implements DSO.String
func (tlv *DSO8765Reconfirm) String() (s string) {
	return tlv.Rr.String()
}

// Len implements DSO.Len
func (tlv *DSO8765Reconfirm) Len() int {
	return tlv.len(0, nil)
}

// Copy implements DSO.Copy
func (tlv *DSO8765Reconfirm) Copy() DSO {
	return &DSO8765Reconfirm{tlv.Rr.copy()}
}

// validate implements DSO.validate
func (tlv *DSO8765Reconfirm) validate(server bool, msg *Msg, i int, primary bool, respPrimary bool) error {
	usage := tlvUsage{server, primary, respPrimary, msg}
	switch {
	case usage.c_p():
		return fmt.Errorf("%w: bad rfc8765 reconfirm primary tlv", ErrRdata)
	case usage.c_u():
		// valid
	case usage.c_a():
		return fmt.Errorf("%w: bad rfc8765 reconfirm additional tlv", ErrRdata)
	case usage.crp():
		fallthrough
	case usage.cra():
		return fmt.Errorf("%w: bad rfc8765 reconfirm response tlv", ErrRdata)
	case usage.s_p():
		fallthrough
	case usage.s_u():
		return fmt.Errorf("%w: bad rfc8765 reconfirm primary tlv", ErrRdata)
	case usage.s_a():
		return fmt.Errorf("%w: bad rfc8765 reconfirm additional tlv", ErrRdata)
	case usage.srp():
		fallthrough
	case usage.sra():
		return fmt.Errorf("%w: bad rfc8765 reconfirm response tlv", ErrRdata)
	}

	if h := tlv.Rr.Header(); h.Class == ClassANY || h.Rrtype == TypeANY {
		return fmt.Errorf("%w: bad class / type in rfc8765 reconfirm tlv", ErrRdata)
	}

	return nil
}

// len implements DSO.len
func (tlv *DSO8765Reconfirm) len(off int, compression map[string]struct{}) int {
	l := tlv.Rr.len(off, compression) - 4 - 2 // Ttl and Rdlength are not packed
	return l
}

// pack implements DSO.pack
func (tlv *DSO8765Reconfirm) pack(buf []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	h := tlv.Rr.Header()

	// RR Header w/o Ttl and Rdlength
	off, err = packDomainName(h.Name, buf, off, compression, compress)
	if err != nil {
		return len(buf), err
	}
	off, err = packUint16(h.Rrtype, buf, off)
	if err != nil {
		return len(buf), err
	}
	off, err = packUint16(h.Class, buf, off)
	if err != nil {
		return len(buf), err
	}

	// Actual RR data
	off, err = tlv.Rr.pack(buf, off, compression, compress)
	if err != nil {
		return len(buf), err
	}

	return off, nil
}

// unpack implements DSO.unpack
func (tlv *DSO8765Reconfirm) unpack(buf []byte, off int) (off1 int, err error) {
	var h RR_Header

	// RR Header w/o Ttl and Rdlength
	h.Name, off, err = UnpackDomainName(buf, off)
	if err != nil {
		return len(buf), err
	}
	h.Rrtype, off, err = unpackUint16(buf, off)
	if err != nil {
		return len(buf), ErrBuf
	}
	h.Class, off, err = unpackUint16(buf, off)
	if err != nil {
		return len(buf), ErrBuf
	}
	headerEnd := off

	// Actual RR data
	tlv.Rr, off, err = UnpackRRWithHeader(h, buf, headerEnd)
	if err != nil {
		return len(buf), err
	}
	h.Rdlength = uint16(off - headerEnd)
	return off, nil
}

// RFC 8490, Section 8.2 TLV usage matrix.
type tlvUsage struct {
	server      bool
	primary     bool
	respPrimary bool
	msg         *Msg
}

func (u tlvUsage) c_p() bool { return !u.server && IsDSORequest(u.msg) && u.primary }
func (u tlvUsage) c_u() bool { return !u.server && IsDSOUnidirectional(u.msg) && u.primary }
func (u tlvUsage) c_a() bool { return !u.server && !IsDSOResponse(u.msg) && !u.primary }
func (u tlvUsage) crp() bool { return u.server && IsDSOResponse(u.msg) && u.respPrimary }
func (u tlvUsage) cra() bool { return u.server && IsDSOResponse(u.msg) && !u.respPrimary }
func (u tlvUsage) s_p() bool { return u.server && IsDSORequest(u.msg) && u.primary }
func (u tlvUsage) s_u() bool { return u.server && IsDSOUnidirectional(u.msg) && u.primary }
func (u tlvUsage) s_a() bool { return u.server && !IsDSOResponse(u.msg) && !u.primary }
func (u tlvUsage) srp() bool { return !u.server && IsDSOResponse(u.msg) && u.respPrimary }
func (u tlvUsage) sra() bool { return !u.server && IsDSOResponse(u.msg) && !u.respPrimary }
