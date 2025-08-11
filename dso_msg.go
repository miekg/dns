package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"time"
)

var (
	ErrDSOMsg  = errors.New("bad DSO message")
	ErrDSOData = ErrRdata

	ErrDSOState   = errors.New("bad DSO state for the operation")
	ErrDSOClosed  = fmt.Errorf("%w: closed", ErrDSOState)
	ErrDSOPending = fmt.Errorf("%w: not established", ErrDSOState)
)

// DSOMsgHdr represents a DSO header.
type DSOMsgHdr struct {
	Id       uint16 // Message Id
	Response bool
	Opcode   int
	Zero     uint16
	Rcode    int
}

// DSOMsg represents a DSO message with its header.
type DSOMsg struct {
	DSOMsgHdr
	// If true, the message will be compressed when converted to wire format.
	Compress bool
	Values   []DSOValue
}

// pack converts DSOMsgHdr to a wire format.
func (h *DSOMsgHdr) pack(buf []byte, off int) (off1 int, err error) {
	off, err = packUint16(h.Id, buf, off)
	if err != nil {
		return len(buf), ErrBuf
	}

	bits := uint16(h.Opcode)<<11 | uint16(h.Rcode&0xF) | (h.Zero&0x7F)<<4
	if h.Response {
		bits |= _QR
	}
	off, err = packUint16(bits, buf, off)
	if err != nil {
		return len(buf), ErrBuf
	}

	off, err = packUint64(0, buf, off)
	if err != nil {
		return len(buf), ErrBuf
	}
	return off, nil
}

// String converts DSOMsgHdr to a string with dig-like headers:
//
// ;; opcode: STATEFUL, status: NOERROR, id: 48404
//
// ;; flags: qr;
func (h *DSOMsgHdr) String() string {
	if h == nil {
		return "<nil> DSOMsgHdr"
	}

	s := ";; opcode: " + OpcodeToString[h.Opcode]
	s += ", status: " + RcodeToString[h.Rcode]
	s += ", id: " + strconv.Itoa(int(h.Id)) + "\n"

	s += ";; flags:"
	if h.Response {
		s += " qr"
	}

	s += ";"
	return s
}

// IsRequest returns true if DSOMsg is a request message.
func (dso *DSOMsg) IsRequest() bool {
	return !dso.Response && dso.Id != 0
}

// IsRequest returns true if DSOMsg is a unidirectional message.
func (dso *DSOMsg) IsUnidirectional() bool {
	return !dso.Response && dso.Id == 0
}

// IsRequest returns true if DSOMsg is a response message.
func (dso *DSOMsg) IsResponse() bool {
	return dso.Response && dso.Id != 0
}

// String converts DSOMsg to a string with dig-like output.
func (dso *DSOMsg) String() string {
	if dso == nil {
		return "<nil> DSOMsgHdr"
	}
	s := dso.DSOMsgHdr.String() + " "
	s += "TLV: " + strconv.Itoa(len(dso.Values)) + "\n"
	if len(dso.Values) > 0 {
		s += "\n;; TLV SECTION:\n"
		for _, v := range dso.Values {
			s += fmt.Sprintf("%s: %s\n", v.DSOType(), v.String())
		}
	}
	return s
}

// isCompressible returns true if DSOMsg may be compressible.
func (dso *DSOMsg) isCompressible() bool {
	if len(dso.Values) == 0 {
		return false
	}
	switch dso.Values[0].DSOType() {
	case DSOType8765Push:
		fallthrough
	case DSOType8765Reconfirm:
		return true
	default:
		return false
	}
}

// Len calculates and returns DSOMsg length in an (un)compressed wire format.
// If dso.Compress is true compression is taken into account.
//
// Len() is provided to be a faster way to get the size of the resulting packet, than packing
// it, measuring the size and discarding the buffer.
func (dso *DSOMsg) Len() int {
	if dso.Compress && dso.isCompressible() {
		compression := make(map[string]struct{})
		return dso.lenWithCompressionMap(compression)
	}
	return dso.lenWithCompressionMap(nil)
}

func (dso *DSOMsg) lenWithCompressionMap(compression map[string]struct{}) int {
	l := headerSize
	for _, tlv := range dso.Values {
		if tlv == nil {
			continue
		}
		l += 2 // tlv type
		l += 2 // tlv length
		l += tlv.len(l, compression)
	}
	return l
}

// Pack converts DSOMsg to a wire format.
func (dso *DSOMsg) Pack() ([]byte, error) {
	return dso.PackBuffer(nil)
}

// PackBuffer converts DSOMsg to a wire format using the buffer.
// If the buffer is too small a new buffer is allocated.
func (dso *DSOMsg) PackBuffer(buf []byte) ([]byte, error) {
	if dso.Rcode != OpcodeStateful {
		return nil, ErrOpcode
	}

	compression, compress := compressionMap{}, false
	if dso.Compress && dso.isCompressible() {
		compression, compress = compressionMap{int: make(map[string]uint16)}, true
	}

	uncompressedLen := dso.lenWithCompressionMap(nil)
	if packLen := uncompressedLen + 1; len(buf) < packLen {
		buf = make([]byte, packLen)
	}

	off := 0
	off, err := dso.DSOMsgHdr.pack(buf, off)
	if err != nil {
		return nil, err
	}
	for _, tlv := range dso.Values {
		off, err = packDSOValue(tlv, buf, off, compression, compress)
		if err != nil {
			return nil, err
		}
	}
	return buf[:off], nil
}

// Unpack sets DSOMsg according to the wire format.
func (dso *DSOMsg) Unpack(buf []byte) error {
	dh, off, err := unpackMsgHdr(buf, 0)
	if err != nil {
		return err
	}

	// RFC 8490, Section 5.4: If ... any of the count fields are not zero, then a FORMERR MUST be returned.
	if dh.Ancount != 0 || dh.Arcount != 0 || dh.Nscount != 0 || dh.Qdcount != 0 {
		return ErrDSOData
	}

	dso.setHdr(dh)
	if dso.Opcode != OpcodeStateful {
		return ErrOpcode
	}

	return dso.unpack(dh, buf, off)
}

// unpack sets TLVs of DSOMsg according to the wire format.
func (dso *DSOMsg) unpack(dh Header, buf []byte, off int) (err error) {
	var tlv DSOValue
	for off < len(buf) {
		tlv, off, err = unpackDSOValue(buf, off)
		if err != nil {
			break
		}
		dso.Values = append(dso.Values, tlv)
	}
	return err
}

// Copy creates a deep-copy of DSOMsg.
func (dso *DSOMsg) Copy() *DSOMsg { return dso.CopyTo(new(DSOMsg)) }

// CopyTo deep-copies DSOMsg to the message and returns it.
func (dso *DSOMsg) CopyTo(r1 *DSOMsg) *DSOMsg {
	r1.DSOMsgHdr = dso.DSOMsgHdr
	r1.Values = make([]DSOValue, len(dso.Values))
	for i, tlv := range dso.Values {
		r1.Values[i] = tlv.copy()
	}
	return r1
}

// Validate checks DSOMsg, including its TLVs, to be valid when composed on server (server = true)
// or client (server = false)
//
// TLV specification may require that it's used only in messages of certain types,
// only by a server or client, only at a certain index, exclusively or not, or any
// combination of these. See RFC 8490, Section 8
//
//
// Optionally, the request message can be passed to verify that DSOMsg is a valid response.
//
// Validation errors are fatal and must be followed up by forcibly closing the connection.
func (dso *DSOMsg) Validate(server bool, req *DSOMsg) error {
	// RFC 8490, Section 5.4.1: If a DSO response message (QR=1) is received where the
	// MESSAGE ID is zero, this is a fatal error
	if dso.Response && dso.Id == 0 {
		return ErrId
	}

	if req != nil {
		if !dso.Response {
			return ErrResponse
		}
		if dso.Id != req.Id {
			return ErrId
		}
	}

	// RFC 8490, Section 5.4.2: A DSO request message or DSO unidirectional message
	// MUST contain at least one TLV.
	if !dso.Response && len(dso.Values) == 0 {
		return fmt.Errorf("%w: missing primary tlv", ErrDSOData)
	}

	// RFC 8490, Section 3: in a DSO response, any TLVs with the same DSO-TYPE as
	// the Primary TLV from the corresponding DSO request message. If present,
	// any Response Primary TLV(s) MUST appear first in the DSO response message,
	// before any Response Additional TLVs.
	respPrimary := req != nil && len(dso.Values) > 0 && dso.Values[0].DSOType() == req.Values[0].DSOType()
	for i, tlv := range dso.Values {
		if respPrimary && i > 0 {
			respPrimary = tlv.DSOType() == dso.Values[i-1].DSOType()
		}
		err := tlv.validate(server, dso, i, i == 0, respPrimary)
		if err != nil {
			return err
		}
	}

	return nil
}

// setHdr sets DSOMsg header using data in dh.
func (dso *DSOMsg) setHdr(dh Header) {
	dso.Id = dh.Id
	dso.Response = dh.Bits&_QR != 0
	dso.Opcode = int(dh.Bits>>11) & 0xF
	dso.Zero = dh.Bits & 0x7F0
	dso.Rcode = int(dh.Bits & 0xF)
}

// SetUnidirectional sets DSOMsg to a unidirectional message.
func (dso *DSOMsg) SetUnidirectional() *DSOMsg {
	dso.Id = 0
	dso.Response = false
	dso.Opcode = OpcodeStateful
	dso.Rcode = RcodeSuccess
	return dso
}

// SetRequest sets DSOMsg to a request message with the ID.
func (dso *DSOMsg) SetRequest(id uint16) *DSOMsg {
	dso.Id = id
	dso.Response = false
	dso.Opcode = OpcodeStateful
	dso.Rcode = RcodeSuccess
	return dso
}

// SetResponse sets DSOMsg to a response message for the request.
func (dso *DSOMsg) SetResponse(request *DSOMsg, rcode int) *DSOMsg {
	dso.Id = request.Id
	dso.Response = true
	dso.Opcode = OpcodeStateful
	dso.Rcode = RcodeSuccess
	return dso
}

// SetClose sets DSOMsg to a graceful close unidirectional message.
func (dso *DSOMsg) SetClose(retryDelay time.Duration, rcode int) *DSOMsg {
	dso.SetUnidirectional()
	dso.Rcode = rcode
	dso.Values = []DSOValue{&DSORetryDelay{uint32(retryDelay.Milliseconds())}}
	return dso
}

// packDSOValue creates wite format from the DSOValue.
func packDSOValue(tlv DSOValue, buf []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	if tlv == nil {
		return len(buf), fmt.Errorf("%w: nil tlv")
	}

	off, err = packUint16(uint16(tlv.DSOType()), buf, off)
	if err != nil {
		return off, ErrBuf
	}

	off, err = packUint16(0, buf, off)
	if err != nil {
		return off, ErrBuf
	}
	headerEnd := off

	off, err = tlv.pack(buf, off, compression, compress)
	if err != nil {
		return off, err
	}

	vlength := off - headerEnd
	if int(uint16(vlength)) != vlength { // overflow
		return len(buf), ErrDSOData
	}

	// Set the DSO length field once wire length is known.
	binary.BigEndian.PutUint16(buf[headerEnd-2:], uint16(vlength))
	return off, nil
}

// unpackDSOValue creates DSOValue from the wire format.
func unpackDSOValue(buf []byte, off int) (tlv DSOValue, off1 int, err error) {
	vtype, off, err := unpackUint16(buf, off)
	if err != nil {
		return nil, len(buf), ErrBuf
	}

	vlen, off, err := unpackUint16(buf, off)
	if err != nil {
		return nil, len(buf), ErrBuf
	}
	end := off + int(vlen)
	if end > len(buf) {
		return nil, len(buf), fmt.Errorf("%w: bad DSO data length", ErrDSOData)
	}

	tlv = makeDSOValue(DSOType(vtype))
	if tlv == nil {
		return nil, end, fmt.Errorf("%w: bad DSO type %d", ErrDSOData, vtype)
	}
	if off, err = tlv.unpack(buf[:end], off); err != nil {
		return nil, end, err
	}
	if off != end {
		return nil, end, fmt.Errorf("%w: bad DSO data length", ErrDSOData)
	}

	return tlv, off, nil
}
