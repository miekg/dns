package dns

import (
	"fmt"
	"strconv"
	"time"
)

// DSOType is the type of a DSO TLV.
type DSOType uint16

const (
	// DSO types defined in RFC 8490, Section 10.3
	DSOTypeReserved          = DSOType(StatefulTypeReserved)
	DSOTypeKeepAlive         = DSOType(StatefulTypeKeepAlive)
	DSOTypeRetryDelay        = DSOType(StatefulTypeRetryDelay)
	DSOTypeEncryptionPadding = DSOType(StatefulTypeEncryptionPadding)

	// DSO types defined in RFC 8765, Section 8
	DSOType8765Subscribe   = DSOType(StatefulType8765Subscribe)
	DSOType8765Push        = DSOType(StatefulType8765Push)
	DSOType8765Unsubscribe = DSOType(StatefulType8765Unsubscribe)
	DSOType8765Reconfirm   = DSOType(StatefulType8765Reconfirm)
)

// String converts DSOType to a readable value.
// Accepts unassigned as well as experimental/local types.
func (t DSOType) String() string {
	str, ok := StatefulTypeToString[uint16(t)]
	if !ok {
		str = fmt.Sprintf("type%04X", uint16(t))
	}
	return str
}

// makeDSOValue creates DSOValue from the type.
func makeDSOValue(t DSOType) DSOValue {
	// All the DSOType.* constants above need to be in this switch.
	switch t {
	case DSOTypeKeepAlive:
		return new(DSOKeepAlive)
	case DSOTypeRetryDelay:
		return new(DSORetryDelay)
	case DSOTypeEncryptionPadding:
		return new(DSOEncryptionPadding)
	case DSOType8765Subscribe:
		return new(DSO8765Subscribe)
	case DSOType8765Push:
		return new(DSO8765Push)
	case DSOType8765Unsubscribe:
		return new(DSO8765Unsubscribe)
	case DSOType8765Reconfirm:
		return new(DSO8765Reconfirm)
	case DSOTypeReserved:
		return nil
	default:
		tlv := new(DSOLocal)
		tlv.dsotype = t
		return tlv
	}
}

// DSOValue is a generic DSO TLV.
type DSOValue interface {
	// DSOType returns the numerical TLV type.
	DSOType() DSOType
	// String converts TLV to a readable string.
	String() string
	// validate checks that the TLV can appear in msg.
	validate(server bool, msg *DSOMsg, i int, primary bool, respPrimary bool) error
	// len calculates and returns TLV length in an (un)compressed wire format.
	//
	// If compression is nil, the uncompressed size will be returned, otherwise the compressed
	// size will be returned and domain names will be added to the map for future compression.
	len(off int, compression map[string]struct{}) int
	// pack converts TLV to a wire format.
	pack(buf []byte, off int, compression compressionMap, compress bool) (off1 int, err error)
	// unpack sets TLV according to the wire format.
	unpack(buf []byte, off int) (int, error)
	// copy creates a deep-copy of TLV.
	copy() DSOValue
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

// Section 7.1: Keepalive TLV
type DSOKeepAlive struct {
	InactivityTimeout uint32
	KeepAliveInterval uint32
}

// DSOType implements DSOValue.DSOType
func (tlv *DSOKeepAlive) DSOType() DSOType {
	return DSOTypeKeepAlive
}

// String implements DSOValue.Len
func (tlv *DSOKeepAlive) String() string {
	return fmt.Sprintf("timeout %dms, interval %dms", tlv.InactivityTimeout, tlv.KeepAliveInterval)
}

// validate implements DSOValue.validate
func (tlv *DSOKeepAlive) validate(server bool, msg *DSOMsg, i int, primary bool, respPrimary bool) error {
	usage := tlvUsage{server, primary, respPrimary, msg}
	switch {
	case usage.c_p():
		// valid
	case usage.c_u():
		return fmt.Errorf("%w: bad keepalive primary tlv", ErrDSOData)
	case usage.c_a():
		return fmt.Errorf("%w: bad keepalive additional tlv", ErrDSOData)
	case usage.crp():
		// valid
	case usage.cra():
		return fmt.Errorf("%w: bad keepalive response additional tlv", ErrDSOData)
	case usage.s_p():
		return fmt.Errorf("%w: bad keepalive primary tlv", ErrDSOData)
	case usage.s_u():
		// valid
	case usage.s_a():
		return fmt.Errorf("%w: bad keepalive additional tlv", ErrDSOData)
	case usage.srp():
		fallthrough
	case usage.sra():
		return fmt.Errorf("%w: bad keepalive response tlv", ErrDSOData)
	}

	if server && tlv.KeepAliveInterval < DSOKeepAliveIntervalMin {
		return fmt.Errorf("%w: bad keepalive interval", ErrDSOData)
	}

	return nil
}

// len implements DSOValue.len
func (tlv *DSOKeepAlive) len(off int, compression map[string]struct{}) int {
	return 8
}

// pack implements DSOValue.pack
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

// unpack implements DSOValue.unpack
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

// copy implements DSOValue.copy
func (tlv *DSOKeepAlive) copy() DSOValue {
	return &DSOKeepAlive{tlv.InactivityTimeout, tlv.KeepAliveInterval}
}

// RFC 8490, Section 7.2: Retry Delay TLV
type DSORetryDelay struct {
	RetryDelay uint32
}

// DSOType implements DSOValue.DSOType
func (tlv *DSORetryDelay) DSOType() DSOType {
	return DSOTypeRetryDelay
}

// String implements DSOValue.String
func (tlv *DSORetryDelay) String() string {
	return (time.Duration(tlv.RetryDelay) * time.Millisecond).String()
}

// validate implements DSOValue.validate
func (tlv *DSORetryDelay) validate(server bool, msg *DSOMsg, i int, primary bool, respPrimary bool) error {
	usage := tlvUsage{server, primary, respPrimary, msg}
	switch {
	case usage.c_p():
		fallthrough
	case usage.c_u():
		return fmt.Errorf("%w: bad retry delay primary tlv", ErrDSOData)
	case usage.c_a():
		return fmt.Errorf("%w: bad retry delay additional tlv", ErrDSOData)
	case usage.crp():
		return fmt.Errorf("%w: bad retry delay response primary tlv", ErrDSOData)
	case usage.cra():
		// valid
	case usage.s_p():
		return fmt.Errorf("%w: bad retry delay primary tlv", ErrDSOData)
	case usage.s_u():
		// valid
	case usage.s_a():
		return fmt.Errorf("%w: bad retry delay additional tlv", ErrDSOData)
	case usage.srp():
		return fmt.Errorf("%w: bad retry delay response primary tlv", ErrDSOData)
	case usage.sra():
		// valid
	}
	return nil
}

// len implements DSOValue.len
func (tlv *DSORetryDelay) len(off int, compression map[string]struct{}) int {
	return 4
}

// pack implements DSOValue.pack
func (tlv *DSORetryDelay) pack(buf []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	off, err = packUint32(tlv.RetryDelay, buf, off)
	if err != nil {
		return len(buf), ErrBuf
	}
	return off, nil
}

// unpack implements DSOValue.unpack
func (tlv *DSORetryDelay) unpack(buf []byte, off int) (off1 int, err error) {
	tlv.RetryDelay, off, err = unpackUint32(buf, off)
	if err != nil {
		return len(buf), ErrBuf
	}
	return off, nil
}

// copy implements DSOValue.copy
func (tlv *DSORetryDelay) copy() DSOValue {
	return &DSORetryDelay{tlv.RetryDelay}
}

// RFC 8490, Section 7.3: Encryption Padding TLV
type DSOEncryptionPadding struct {
	Padding []byte
}

// DSOType implements the DSOValue.DSOType
func (tlv *DSOEncryptionPadding) DSOType() DSOType {
	return DSOTypeEncryptionPadding
}

// String implements DSOValue.String
func (tlv *DSOEncryptionPadding) String() string {
	return fmt.Sprintf("%0X", tlv.Padding)
}

// validate implements DSOValue.validate
func (tlv *DSOEncryptionPadding) validate(server bool, msg *DSOMsg, i int, primary bool, respPrimary bool) error {
	usage := tlvUsage{server, primary, respPrimary, msg}
	switch {
	case usage.c_p():
		fallthrough
	case usage.c_u():
		return fmt.Errorf("%w: bad encryption padding primary tlv", ErrDSOData)
	case usage.c_a():
		// valid
	case usage.crp():
		return fmt.Errorf("%w: bad encryption padding response primary tlv", ErrDSOData)
	case usage.cra():
		// valid
	case usage.s_p():
		fallthrough
	case usage.s_u():
		return fmt.Errorf("%w: bad encryption padding primary tlv", ErrDSOData)
	case usage.s_a():
		// valid
	case usage.srp():
		return fmt.Errorf("%w: bad encryption padding response primary tlv", ErrDSOData)
	case usage.sra():
		// valid
	}
	return nil
}

// len implements DSOValue.len
func (tlv *DSOEncryptionPadding) len(off int, compression map[string]struct{}) int {
	return len(tlv.Padding)
}

// pack implements DSOValue.pack
func (tlv *DSOEncryptionPadding) pack(buf []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	packLen := len(tlv.Padding)
	if len(buf)-off < packLen {
		return len(buf), ErrBuf
	}
	copy(buf[off:], tlv.Padding)
	off += packLen
	return off, nil
}

// unpack implements DSOValue.unpack
func (tlv *DSOEncryptionPadding) unpack(buf []byte, off int) (int, error) {
	tlv.Padding = cloneSlice(buf[off:])
	return len(buf), nil
}

// copy implements DSOValue.copy
func (tlv *DSOEncryptionPadding) copy() DSOValue {
	return &DSOEncryptionPadding{cloneSlice(tlv.Padding)}
}

// DSOLocal is intended for experimental/private use as well as for unrecognized TLVs.
type DSOLocal struct {
	dsotype DSOType
	Data    []byte
}

// DSOType implements DSOValue.DSOType
func (tlv *DSOLocal) DSOType() DSOType {
	return tlv.dsotype
}

// String implements DSOValue.String
func (tlv *DSOLocal) String() string {
	return fmt.Sprintf("%0X", tlv.Data)
}

// validate implements DSOValue.validate
func (tlv *DSOLocal) validate(server bool, msg *DSOMsg, i int, primary bool, respPrimary bool) error {
	return nil
}

// len implements DSOValue.len
func (tlv *DSOLocal) len(off int, compression map[string]struct{}) int {
	return len(tlv.Data)
}

// pack implements DSOValue.pack
func (tlv *DSOLocal) pack(buf []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	packLen := len(tlv.Data)
	if len(buf)-off < packLen {
		return len(buf), ErrBuf
	}
	copy(buf[off:], tlv.Data)
	off += packLen
	return off, nil
}

// unpack implements DSOValue.unpack
func (tlv *DSOLocal) unpack(buf []byte, off int) (int, error) {
	tlv.Data = cloneSlice(buf[off:])
	return len(buf), nil
}

// copy implements DSOValue.copy
func (tlv *DSOLocal) copy() DSOValue {
	return &DSOLocal{tlv.dsotype, cloneSlice(tlv.Data)}
}

// RFC 8765, Section 6.2: DNS Push Notification SUBSCRIBE
type DSO8765Subscribe struct {
	Name   string
	Rrtype uint16
	Class  uint16
}

// DSOType implements DSOValue.DSOType
func (tlv *DSO8765Subscribe) DSOType() DSOType {
	return DSOType8765Subscribe
}

// String implements DSOValue.String
func (tlv *DSO8765Subscribe) String() (s string) {
	s = ";" + sprintName(tlv.Name) + "\t"
	s += Class(tlv.Class).String() + "\t"
	s += " " + Type(tlv.Rrtype).String()
	return s
}

// validate implements DSOValue.validate
func (tlv *DSO8765Subscribe) validate(server bool, msg *DSOMsg, i int, primary bool, respPrimary bool) error {
	usage := tlvUsage{server, primary, respPrimary, msg}
	switch {
	case usage.c_p():
		// valid
	case usage.c_u():
		return fmt.Errorf("%w: bad rfc8765 subscribe primary tlv", ErrDSOData)
	case usage.c_a():
		return fmt.Errorf("%w: bad rfc8765 subscribe additional tlv", ErrDSOData)
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
		return fmt.Errorf("%w: bad rfc8765 subscribe primary tlv", ErrDSOData)
	case usage.s_a():
		return fmt.Errorf("%w: bad rfc8765 subscribe additional tlv", ErrDSOData)
	case usage.srp():
		fallthrough
	case usage.sra():
		return fmt.Errorf("%w: bad rfc8765 subscribe response tlv", ErrDSOData)
	}
	return nil
}

// len implements DSOValue.len
func (tlv *DSO8765Subscribe) len(off int, compression map[string]struct{}) int {
	l := domainNameLen(tlv.Name, off, compression, true)
	l += 2 + 2
	return l
}

// pack implements DSOValue.pack
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

// unpack implements DSOValue.unpack
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

// copy implements DSOValue.copy
func (tlv *DSO8765Subscribe) copy() DSOValue {
	return &DSO8765Subscribe{tlv.Name, tlv.Rrtype, tlv.Class}
}

// RFC 8765, Section 6.3: DNS Push Notification Updates
type DSO8765Push struct {
	Change []RR
}

// DSOType implements DSOValue.DSOType
func (tlv *DSO8765Push) DSOType() DSOType {
	return DSOType8765Push
}

// String implements DSOValue.String
func (tlv *DSO8765Push) String() string {
	switch {
	case len(tlv.Change) == 0:
		return "<nil>"
	case len(tlv.Change) == 1:
		return tlv.Change[0].String()
	default:
		s := fmt.Sprintf("\t%s", tlv.Change[0])
		for _, r := range tlv.Change[1:] {
			s += fmt.Sprintf("\n\t%s", r)
		}
		return s
	}
}

// validate implements DSOValue.validate
func (tlv *DSO8765Push) validate(server bool, msg *DSOMsg, i int, primary bool, respPrimary bool) error {
	usage := tlvUsage{server, primary, respPrimary, msg}
	switch {
	case usage.c_p():
		fallthrough
	case usage.c_u():
		return fmt.Errorf("%w: bad rfc8765 push primary tlv", ErrDSOData)
	case usage.c_a():
		return fmt.Errorf("%w: bad rfc8765 push additional tlv", ErrDSOData)
	case usage.crp():
		fallthrough
	case usage.cra():
		return fmt.Errorf("%w: bad rfc8765 push response tlv", ErrDSOData)
	case usage.s_p():
		return fmt.Errorf("%w: bad rfc8765 push primary tlv", ErrDSOData)
	case usage.s_u():
		// valid
	case usage.s_a():
		return fmt.Errorf("%w: bad rfc8765 push additional tlv", ErrDSOData)
	case usage.srp():
		fallthrough
	case usage.sra():
		return fmt.Errorf("%w: bad rfc8765 push response tlv", ErrDSOData)
	}

	// RFC 8765, Section 6.3.1: A PUSH Message MUST contain at least one change notification.
	if len(tlv.Change) == 0 {
		return fmt.Errorf("%w: empty rfc8765 push tlv", ErrDSOData)
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
			return fmt.Errorf("%w: bad class / type in rfc8765 push tlv", ErrDSOData)
		// RFC 8765, Section 6.3.1: If the TTL has the value 0xFFFFFFFE, then this is a
		// 'collective' remove notification. For collective remove notifications,
		// RDLEN MUST be zero
		case h.Ttl == 0xFFFFFFFE && h.Rdlength != 0:
			return fmt.Errorf("%w: non-empty collective removal in rfc8765 push tlv", ErrDSOData)
		// RFC 8765, Section 6.3.1: If the TTL is any value other than 0xFFFFFFFF, 0xFFFFFFFE,
		// or a value in the range 0 to 0x7FFFFFFF, then the receiver SHOULD silently ignore
		// this particular change notification record.
		default:
		}
	}

	return nil
}

// len implements DSOValue.len
func (tlv *DSO8765Push) len(off int, compression map[string]struct{}) int {
	l := off
	for _, r := range tlv.Change {
		l += r.len(l, compression)
	}
	return l - off
}

// pack implements DSOValue.pack
func (tlv *DSO8765Push) pack(buf []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	for _, r := range tlv.Change {
		_, off, err = packRR(r, buf, off, compression, compress)
		if err != nil {
			return len(buf), err
		}
	}
	return off, nil
}

// unpack implements DSOValue.unpack
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

// copy implements DSOValue.copy
func (tlv *DSO8765Push) copy() DSOValue {
	tlv1 := DSO8765Push{}
	tlv1.Change = make([]RR, len(tlv.Change))
	for i, r := range tlv.Change {
		tlv1.Change[i] = r.copy()
	}
	return &tlv1
}

// RFC 8765, Section 6.4: DNS Push Notification UNSUBSCRIBE
type DSO8765Unsubscribe struct {
	SubscribeId uint16
}

// DSOType implements DSOValue.DSOType
func (tlv *DSO8765Unsubscribe) DSOType() DSOType {
	return DSOType8765Unsubscribe
}

// String implements DSOValue.String
func (tlv *DSO8765Unsubscribe) String() (s string) {
	return strconv.Itoa(int(tlv.SubscribeId))
}

// validate implements DSOValue.validate
func (tlv *DSO8765Unsubscribe) validate(server bool, msg *DSOMsg, i int, primary bool, respPrimary bool) error {
	usage := tlvUsage{server, primary, respPrimary, msg}
	switch {
	case usage.c_p():
		return fmt.Errorf("%w: bad rfc8765 unsubscribe primary tlv", ErrDSOData)
	case usage.c_u():
		// valid
	case usage.c_a():
		return fmt.Errorf("%w: bad rfc8765 unsubscribe additional tlv", ErrDSOData)
	case usage.crp():
		fallthrough
	case usage.cra():
		return fmt.Errorf("%w: bad rfc8765 unsubscribe response tlv", ErrDSOData)
	case usage.s_p():
		fallthrough
	case usage.s_u():
		return fmt.Errorf("%w: bad rfc8765 unsubscribe primary tlv", ErrDSOData)
	case usage.s_a():
		return fmt.Errorf("%w: bad rfc8765 unsubscribe additional tlv", ErrDSOData)
	case usage.srp():
		fallthrough
	case usage.sra():
		return fmt.Errorf("%w: bad rfc8765 unsubscribe response tlv", ErrDSOData)
	}
	return nil
}

// len implements DSOValue.len
func (tlv *DSO8765Unsubscribe) len(off int, compression map[string]struct{}) int {
	return 2
}

// pack implements DSOValue.pack
func (tlv *DSO8765Unsubscribe) pack(buf []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	off, err = packUint16(uint16(tlv.SubscribeId), buf, off)
	if err != nil {
		return len(buf), ErrBuf
	}
	return off, nil
}

// unpack implements DSOValue.unpack
func (tlv *DSO8765Unsubscribe) unpack(buf []byte, off int) (off1 int, err error) {
	tlv.SubscribeId, off, err = unpackUint16(buf, off)
	if err != nil {
		return len(buf), ErrBuf
	}
	return off, nil
}

// copy implements DSOValue.copy
func (tlv *DSO8765Unsubscribe) copy() DSOValue {
	return &DSO8765Unsubscribe{tlv.SubscribeId}
}

// RFC 8765, Section 6.5: DNS Push Notification RECONFIRM
type DSO8765Reconfirm struct {
	Rr RR
}

// DSOType implements DSOValue.DSOType
func (tlv *DSO8765Reconfirm) DSOType() DSOType {
	return DSOType8765Reconfirm
}

// String implements DSOValue.String
func (tlv *DSO8765Reconfirm) String() (s string) {
	return tlv.Rr.String()
}

// validate implements DSOValue.validate
func (tlv *DSO8765Reconfirm) validate(server bool, msg *DSOMsg, i int, primary bool, respPrimary bool) error {
	usage := tlvUsage{server, primary, respPrimary, msg}
	switch {
	case usage.c_p():
		return fmt.Errorf("%w: bad rfc8765 reconfirm primary tlv", ErrDSOData)
	case usage.c_u():
		// valid
	case usage.c_a():
		return fmt.Errorf("%w: bad rfc8765 reconfirm additional tlv", ErrDSOData)
	case usage.crp():
		fallthrough
	case usage.cra():
		return fmt.Errorf("%w: bad rfc8765 reconfirm response tlv", ErrDSOData)
	case usage.s_p():
		fallthrough
	case usage.s_u():
		return fmt.Errorf("%w: bad rfc8765 reconfirm primary tlv", ErrDSOData)
	case usage.s_a():
		return fmt.Errorf("%w: bad rfc8765 reconfirm additional tlv", ErrDSOData)
	case usage.srp():
		fallthrough
	case usage.sra():
		return fmt.Errorf("%w: bad rfc8765 reconfirm response tlv", ErrDSOData)
	}

	if h := tlv.Rr.Header(); h.Class == ClassANY || h.Rrtype == TypeANY {
		return fmt.Errorf("%w: bad class / type in rfc8765 reconfirm tlv", ErrDSOData)
	}

	return nil
}

// len implements DSOValue.len
func (tlv *DSO8765Reconfirm) len(off int, compression map[string]struct{}) int {
	l := tlv.Rr.len(off, compression) - 4 - 2 // Ttl and Rdlength are not packed
	return l
}

// pack implements DSOValue.pack
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

// unpack implements DSOValue.unpack
func (tlv *DSO8765Reconfirm) unpack(buf []byte, off int) (off1 int, err error) {
	var h RR_Header

	// RR Header
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

	rdlength := len(buf) - headerEnd
	if int(uint16(rdlength)) != rdlength {
		return len(buf), ErrDSOData
	}
	h.Rdlength = uint16(rdlength)

	// Actual RR data
	tlv.Rr, off, err = UnpackRRWithHeader(h, buf, off)
	if err != nil {
		return len(buf), err
	}
	return off, nil
}

// copy implements DSOValue.copy
func (tlv *DSO8765Reconfirm) copy() DSOValue {
	return &DSO8765Reconfirm{tlv.Rr.copy()}
}

// RFC 8490, Section 8.2 TLV usage matrix.
type tlvUsage struct {
	server      bool
	primary     bool
	respPrimary bool
	msg         *DSOMsg
}

func (u *tlvUsage) c_p() bool { return !u.server && u.msg.IsRequest() && u.primary }
func (u *tlvUsage) c_u() bool { return !u.server && u.msg.IsUnidirectional() && u.primary }
func (u *tlvUsage) c_a() bool { return !u.server && !u.msg.IsResponse() && !u.primary }
func (u *tlvUsage) crp() bool { return u.server && u.msg.IsResponse() && u.respPrimary }
func (u *tlvUsage) cra() bool { return u.server && u.msg.IsResponse() && !u.respPrimary }
func (u *tlvUsage) s_p() bool { return u.server && u.msg.IsRequest() && u.primary }
func (u *tlvUsage) s_u() bool { return u.server && u.msg.IsUnidirectional() && u.primary }
func (u *tlvUsage) s_a() bool { return u.server && !u.msg.IsResponse() && !u.primary }
func (u *tlvUsage) srp() bool { return !u.server && u.msg.IsResponse() && u.respPrimary }
func (u *tlvUsage) sra() bool { return !u.server && u.msg.IsResponse() && !u.respPrimary }
