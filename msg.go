// DNS packet assembly, see RFC 1035. Converting from - Unpack() -
// and to - Pack() - wire format.
// All the packers and unpackers take a (msg []byte, off int)
// and return (off1 int, ok bool).  If they return ok==false, they
// also return off1==len(msg), so that the next unpacker will
// also fail.  This lets us avoid checks of ok until the end of a
// packing sequence.

package dns

//go:generate go run msg_generate.go

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"golang.org/x/crypto/cryptobyte"
)

const (
	maxCompressionOffset    = 2 << 13 // We have 14 bits for the compression pointer
	maxDomainNameWireOctets = 255     // See RFC 1035 section 2.3.4

	// This is the maximum number of compression pointers that should occur in a
	// semantically valid message. Each label in a domain name must be at least one
	// octet and is separated by a period. The root label won't be represented by a
	// compression pointer to a compression pointer, hence the -2 to exclude the
	// smallest valid root label.
	//
	// It is possible to construct a valid message that has more compression pointers
	// than this, and still doesn't loop, by pointing to a previous pointer. This is
	// not something a well written implementation should ever do, so we leave them
	// to trip the maximum compression pointer check.
	maxCompressionPointers = (maxDomainNameWireOctets+1)/2 - 2

	// This is the maximum length of a domain name in presentation format. The
	// maximum wire length of a domain name is 255 octets (see above), with the
	// maximum label length being 63. The wire format requires one extra byte over
	// the presentation format, reducing the number of octets by 1. Each label in
	// the name will be separated by a single period, with each octet in the label
	// expanding to at most 4 bytes (\DDD). If all other labels are of the maximum
	// length, then the final label can only be 61 octets long to not exceed the
	// maximum allowed wire length.
	maxDomainNamePresentationLength = 61*4 + 1 + 63*4 + 1 + 63*4 + 1 + 63*4 + 1
)

// Errors defined in this package.
var (
	ErrAlg           error = &Error{err: "bad algorithm"}                  // ErrAlg indicates an error with the (DNSSEC) algorithm.
	ErrAuth          error = &Error{err: "bad authentication"}             // ErrAuth indicates an error in the TSIG authentication.
	ErrBuf           error = &Error{err: "buffer size too small"}          // ErrBuf indicates that the buffer used is too small for the message.
	ErrConnEmpty     error = &Error{err: "conn has no connection"}         // ErrConnEmpty indicates a connection is being used before it is initialized.
	ErrExtendedRcode error = &Error{err: "bad extended rcode"}             // ErrExtendedRcode ...
	ErrFqdn          error = &Error{err: "domain must be fully qualified"} // ErrFqdn indicates that a domain name does not have a closing dot.
	ErrId            error = &Error{err: "id mismatch"}                    // ErrId indicates there is a mismatch with the message's ID.
	ErrKeyAlg        error = &Error{err: "bad key algorithm"}              // ErrKeyAlg indicates that the algorithm in the key is not valid.
	ErrKey           error = &Error{err: "bad key"}
	ErrKeySize       error = &Error{err: "bad key size"}
	ErrLongDomain    error = &Error{err: fmt.Sprintf("domain name exceeded %d wire-format octets", maxDomainNameWireOctets)}
	ErrNoSig         error = &Error{err: "no signature found"}
	ErrPrivKey       error = &Error{err: "bad private key"}
	ErrRcode         error = &Error{err: "bad rcode"}
	ErrRdata         error = &Error{err: "bad rdata"}
	ErrRRset         error = &Error{err: "bad rrset"}
	ErrSecret        error = &Error{err: "no secrets defined"}
	ErrShortRead     error = &Error{err: "short read"}
	ErrSig           error = &Error{err: "bad signature"} // ErrSig indicates that a signature can not be cryptographically validated.
	ErrSoa           error = &Error{err: "no SOA"}        // ErrSOA indicates that no SOA RR was seen when doing zone transfers.
	ErrTime          error = &Error{err: "bad time"}      // ErrTime indicates a timing error in TSIG authentication.
)

// Id by default returns a 16-bit random number to be used as a message id. The
// number is drawn from a cryptographically secure random number generator.
// This being a variable the function can be reassigned to a custom function.
// For instance, to make it return a static value for testing:
//
//	dns.Id = func() uint16 { return 3 }
var Id = id

// id returns a 16 bits random number to be used as a
// message id. The random provided should be good enough.
func id() uint16 {
	var output uint16
	err := binary.Read(rand.Reader, binary.BigEndian, &output)
	if err != nil {
		panic("dns: reading random id failed: " + err.Error())
	}
	return output
}

// MsgHdr is a a manually-unpacked version of (id, bits).
type MsgHdr struct {
	Id                 uint16
	Response           bool
	Opcode             int
	Authoritative      bool
	Truncated          bool
	RecursionDesired   bool
	RecursionAvailable bool
	Zero               bool
	AuthenticatedData  bool
	CheckingDisabled   bool
	Rcode              int
}

// Msg contains the layout of a DNS message.
type Msg struct {
	MsgHdr
	Compress bool       `json:"-"` // If true, the message will be compressed when converted to wire format.
	Question []Question // Holds the RR(s) of the question section.
	Answer   []RR       // Holds the RR(s) of the answer section.
	Ns       []RR       // Holds the RR(s) of the authority section.
	Extra    []RR       // Holds the RR(s) of the additional section.
}

// ClassToString is a maps Classes to strings for each CLASS wire type.
var ClassToString = map[uint16]string{
	ClassINET:   "IN",
	ClassCSNET:  "CS",
	ClassCHAOS:  "CH",
	ClassHESIOD: "HS",
	ClassNONE:   "NONE",
	ClassANY:    "ANY",
}

// OpcodeToString maps Opcodes to strings.
var OpcodeToString = map[int]string{
	OpcodeQuery:  "QUERY",
	OpcodeIQuery: "IQUERY",
	OpcodeStatus: "STATUS",
	OpcodeNotify: "NOTIFY",
	OpcodeUpdate: "UPDATE",
}

// RcodeToString maps Rcodes to strings.
var RcodeToString = map[int]string{
	RcodeSuccess:        "NOERROR",
	RcodeFormatError:    "FORMERR",
	RcodeServerFailure:  "SERVFAIL",
	RcodeNameError:      "NXDOMAIN",
	RcodeNotImplemented: "NOTIMP",
	RcodeRefused:        "REFUSED",
	RcodeYXDomain:       "YXDOMAIN", // See RFC 2136
	RcodeYXRrset:        "YXRRSET",
	RcodeNXRrset:        "NXRRSET",
	RcodeNotAuth:        "NOTAUTH",
	RcodeNotZone:        "NOTZONE",
	RcodeBadSig:         "BADSIG", // Also known as RcodeBadVers, see RFC 6891
	//	RcodeBadVers:        "BADVERS",
	RcodeBadKey:    "BADKEY",
	RcodeBadTime:   "BADTIME",
	RcodeBadMode:   "BADMODE",
	RcodeBadName:   "BADNAME",
	RcodeBadAlg:    "BADALG",
	RcodeBadTrunc:  "BADTRUNC",
	RcodeBadCookie: "BADCOOKIE",
}

// compressionMap is used to allow a more efficient compression map
// to be used for internal packDomainName calls without changing the
// signature or functionality of public API.
//
// In particular, map[string]uint16 uses 25% less per-entry memory
// than does map[string]int.
type compressionMap struct {
	ext map[string]int    // external callers
	int map[string]uint16 // internal callers
}

func (m compressionMap) valid() bool {
	return m.int != nil || m.ext != nil
}

func (m compressionMap) insert(s string, pos int) {
	if m.ext != nil {
		m.ext[s] = pos
	} else {
		m.int[s] = uint16(pos)
	}
}

func (m compressionMap) find(s string) (uint16, bool) {
	if m.ext != nil {
		pos, ok := m.ext[s]
		return uint16(pos), ok
	}

	pos, ok := m.int[s]
	return pos, ok
}

// Domain names are a sequence of counted strings
// split at the dots. They end with a zero-length string.

// PackDomainName packs a domain name s into msg[off:].
// If compression is wanted compress must be true and the compression
// map needs to hold a mapping between domain names and offsets
// pointing into msg.
func PackDomainName(s string, msg []byte, off int, compression map[string]int, compress bool) (off1 int, err error) {
	return packDomainName(s, msg, off, compressionMap{ext: compression}, compress)
}

func packDomainName(s string, msg []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	// XXX: A logical copy of this function exists in IsDomainName and
	// should be kept in sync with this function.

	ls := len(s)
	if ls == 0 { // Ok, for instance when dealing with update RR without any rdata.
		return off, nil
	}

	// If not fully qualified, error out.
	if !IsFqdn(s) {
		return len(msg), ErrFqdn
	}

	// Each dot ends a segment of the name.
	// We trade each dot byte for a length byte.
	// Except for escaped dots (\.), which are normal dots.
	// There is also a trailing zero.

	// Compression
	pointer := ^uint16(0)

	// Emit sequence of counted strings, chopping at dots.
	var (
		begin     int
		compBegin int
		compOff   int
		bs        []byte
		wasDot    bool
	)
loop:
	for i := 0; i < ls; i++ {
		var c byte
		if bs == nil {
			c = s[i]
		} else {
			c = bs[i]
		}

		switch c {
		case '\\':
			if off+1 > len(msg) {
				return len(msg), ErrBuf
			}

			if bs == nil {
				bs = []byte(s)
			}

			// check for \DDD
			if isDDD(bs[i+1:]) {
				bs[i] = dddToByte(bs[i+1:])
				copy(bs[i+1:ls-3], bs[i+4:])
				ls -= 3
				compOff += 3
			} else {
				copy(bs[i:ls-1], bs[i+1:])
				ls--
				compOff++
			}

			wasDot = false
		case '.':
			if i == 0 && len(s) > 1 {
				// leading dots are not legal except for the root zone
				return len(msg), ErrRdata
			}

			if wasDot {
				// two dots back to back is not legal
				return len(msg), ErrRdata
			}
			wasDot = true

			labelLen := i - begin
			if labelLen >= 1<<6 { // top two bits of length must be clear
				return len(msg), ErrRdata
			}

			// off can already (we're in a loop) be bigger than len(msg)
			// this happens when a name isn't fully qualified
			if off+1+labelLen > len(msg) {
				return len(msg), ErrBuf
			}

			// Don't try to compress '.'
			// We should only compress when compress is true, but we should also still pick
			// up names that can be used for *future* compression(s).
			if compression.valid() && !isRootLabel(s, bs, begin, ls) {
				if p, ok := compression.find(s[compBegin:]); ok {
					// The first hit is the longest matching dname
					// keep the pointer offset we get back and store
					// the offset of the current name, because that's
					// where we need to insert the pointer later

					// If compress is true, we're allowed to compress this dname
					if compress {
						pointer = p // Where to point to
						break loop
					}
				} else if off < maxCompressionOffset {
					// Only offsets smaller than maxCompressionOffset can be used.
					compression.insert(s[compBegin:], off)
				}
			}

			// The following is covered by the length check above.
			msg[off] = byte(labelLen)

			if bs == nil {
				copy(msg[off+1:], s[begin:i])
			} else {
				copy(msg[off+1:], bs[begin:i])
			}
			off += 1 + labelLen

			begin = i + 1
			compBegin = begin + compOff
		default:
			wasDot = false
		}
	}

	// Root label is special
	if isRootLabel(s, bs, 0, ls) {
		return off, nil
	}

	// If we did compression and we find something add the pointer here
	if pointer != ^uint16(0) {
		// We have two bytes (14 bits) to put the pointer in
		binary.BigEndian.PutUint16(msg[off:], 0xC000|pointer)
		return off + 2, nil
	}

	if off < len(msg) {
		msg[off] = 0
	}

	return off + 1, nil
}

// isRootLabel returns whether s or bs, from off to end, is the root
// label ".".
//
// If bs is nil, s will be checked, otherwise bs will be checked.
func isRootLabel(s string, bs []byte, off, end int) bool {
	if bs == nil {
		return s[off:end] == "."
	}

	return end-off == 1 && bs[off] == '.'
}

// Unpack a domain name.
// In addition to the simple sequences of counted strings above,
// domain names are allowed to refer to strings elsewhere in the
// packet, to avoid repeating common suffixes when returning
// many entries in a single domain. The pointers are marked
// by a length byte with the top two bits set. Ignoring those
// two bits, that byte and the next give a 14 bit offset from into msg
// where we should pick up the trail.
// Note that if we jump elsewhere in the packet,
// we record the last offset we read from when we found the first pointer,
// which is where the next record or record field will start.
// We enforce that pointers always point backwards into the message.

// UnpackDomainName unpacks a domain name into a string. It returns
// the name, the new offset into msg and any error that occurred.
//
// When an error is encountered, the unpacked name will be discarded
// and len(msg) will be returned as the offset.
func UnpackDomainName(msg []byte, off int) (string, int, error) {
	s := cryptobyte.String(msg[off:])
	name, err := unpackDomainName(&s, msg)
	if err != nil {
		// Keep documented behaviour of returning len(msg) here.
		return "", len(msg), err
	}
	return name, len(msg) - len(s), nil
}

func unpackDomainName(msg *cryptobyte.String, msgBuf []byte) (string, error) {
	s := make([]byte, 0, maxDomainNamePresentationLength)
	budget := maxDomainNameWireOctets
	var ptrs int // number of pointers followed

	// If we never see a pointer, we need to ensure that we advance msg to our
	// final position.
	cs := *msg
	defer func() {
		if ptrs == 0 {
			*msg = cs
		}
	}()

	for {
		var c byte
		if !cs.ReadUint8(&c) {
			return "", ErrBuf
		}
		switch c & 0xC0 {
		case 0x00: // literal string
			var label []byte
			if !cs.ReadBytes(&label, int(c)) {
				return "", ErrBuf
			}
			// If we see a zero-length label (root label), this is the
			// end of the name.
			if len(label) == 0 {
				if len(s) == 0 {
					return ".", nil
				}
				return string(s), nil
			}
			if budget -= len(label) + 1; budget <= 0 { // +1 for the label separator
				return "", ErrLongDomain
			}
			for _, b := range label {
				if isDomainNameLabelSpecial(b) {
					s = append(s, '\\', b)
				} else if b < ' ' || b > '~' {
					s = append(s, escapeByte(b)...)
				} else {
					s = append(s, b)
				}
			}
			s = append(s, '.')
		case 0xC0: // pointer
			var c1 byte
			if !cs.ReadUint8(&c1) {
				return "", ErrBuf
			}
			// If this is the first pointer we've seen, we need to
			// advance msg to our current position.
			if ptrs == 0 {
				*msg = cs
			}
			// Don't follow too many pointers in case there is a loop.
			if ptrs++; ptrs > maxCompressionPointers {
				return "", &Error{err: "too many compression pointers"}
			}
			// The pointer should always point backwards to an earlier
			// part of the message. Technically it could work pointing
			// forwards, but we choose not to support that as RFC1035
			// specifically refers to a "prior occurance".
			off := uint16(c&^0xC0)<<8 | uint16(c1)
			if int(off) >= len(msgBuf)-len(cs) {
				return "", &Error{err: "pointer not to prior occurrence of name"}
			}
			// Jump to the offset in msgBuf. We carry msgBuf around with
			// us solely for this line.
			cs = msgBuf[off:]
		default:
			// 0x80 and 0x40 are reserved
			return "", ErrRdata
		}
	}
}

func packTxt(txt []string, msg []byte, offset int) (int, error) {
	if len(txt) == 0 {
		if offset >= len(msg) {
			return offset, ErrBuf
		}
		msg[offset] = 0
		return offset, nil
	}
	var err error
	for _, s := range txt {
		offset, err = packTxtString(s, msg, offset)
		if err != nil {
			return offset, err
		}
	}
	return offset, nil
}

func packTxtString(s string, msg []byte, offset int) (int, error) {
	lenByteOffset := offset
	if offset >= len(msg) || len(s) > 256*4+1 /* If all \DDD */ {
		return offset, ErrBuf
	}
	offset++
	for i := 0; i < len(s); i++ {
		if len(msg) <= offset {
			return offset, ErrBuf
		}
		if s[i] == '\\' {
			i++
			if i == len(s) {
				break
			}
			// check for \DDD
			if isDDD(s[i:]) {
				msg[offset] = dddToByte(s[i:])
				i += 2
			} else {
				msg[offset] = s[i]
			}
		} else {
			msg[offset] = s[i]
		}
		offset++
	}
	l := offset - lenByteOffset - 1
	if l > 255 {
		return offset, &Error{err: "string exceeded 255 bytes in txt"}
	}
	msg[lenByteOffset] = byte(l)
	return offset, nil
}

func packOctetString(s string, msg []byte, offset int) (int, error) {
	if offset >= len(msg) || len(s) > 256*4+1 {
		return offset, ErrBuf
	}
	for i := 0; i < len(s); i++ {
		if len(msg) <= offset {
			return offset, ErrBuf
		}
		if s[i] == '\\' {
			i++
			if i == len(s) {
				break
			}
			// check for \DDD
			if isDDD(s[i:]) {
				msg[offset] = dddToByte(s[i:])
				i += 2
			} else {
				msg[offset] = s[i]
			}
		} else {
			msg[offset] = s[i]
		}
		offset++
	}
	return offset, nil
}

func unpackTxt(msg *cryptobyte.String) ([]string, error) {
	var ss []string
	for !msg.Empty() {
		s, err := unpackString(msg)
		if err != nil {
			return ss, err
		}
		ss = append(ss, s)
	}
	return ss, nil
}

// Helpers for dealing with escaped bytes
func isDigit(b byte) bool { return b >= '0' && b <= '9' }

func isDDD[T ~[]byte | ~string](s T) bool {
	return len(s) >= 3 && isDigit(s[0]) && isDigit(s[1]) && isDigit(s[2])
}

func dddToByte[T ~[]byte | ~string](s T) byte {
	_ = s[2] // bounds check hint to compiler; see golang.org/issue/14808
	return byte((s[0]-'0')*100 + (s[1]-'0')*10 + (s[2] - '0'))
}

// Helper function for packing and unpacking
func intToBytes(i *big.Int, length int) []byte {
	buf := i.Bytes()
	if len(buf) < length {
		b := make([]byte, length)
		copy(b[length-len(buf):], buf)
		return b
	}
	return buf
}

// PackRR packs a resource record rr into msg[off:].
// See PackDomainName for documentation about the compression.
func PackRR(rr RR, msg []byte, off int, compression map[string]int, compress bool) (off1 int, err error) {
	headerEnd, off1, err := packRR(rr, msg, off, compressionMap{ext: compression}, compress)
	if err == nil {
		// packRR no longer sets the Rdlength field on the rr, but
		// callers might be expecting it so we set it here.
		rr.Header().Rdlength = uint16(off1 - headerEnd)
	}
	return off1, err
}

func packRR(rr RR, msg []byte, off int, compression compressionMap, compress bool) (headerEnd int, off1 int, err error) {
	if rr == nil {
		return len(msg), len(msg), &Error{err: "nil rr"}
	}

	headerEnd, err = rr.Header().packHeader(msg, off, compression, compress)
	if err != nil {
		return headerEnd, len(msg), err
	}

	off1, err = rr.pack(msg, headerEnd, compression, compress)
	if err != nil {
		return headerEnd, len(msg), err
	}

	rdlength := off1 - headerEnd
	if int(uint16(rdlength)) != rdlength { // overflow
		return headerEnd, len(msg), ErrRdata
	}

	// The RDLENGTH field is the last field in the header and we set it here.
	binary.BigEndian.PutUint16(msg[headerEnd-2:], uint16(rdlength))
	return headerEnd, off1, nil
}

// UnpackRR unpacks msg[off:] into an RR.
func UnpackRR(msg []byte, off int) (rr RR, off1 int, err error) {
	if off < 0 || off > len(msg) {
		return nil, off, &Error{err: "bad off"}
	}

	s := cryptobyte.String(msg[off:])
	if s.Empty() {
		// Preserve this somewhat strange existing corner case of not
		// returning an error when given nothing to unpack.
		return new(RR_Header), len(msg), nil
	}

	rr, err = unpackRR(&s, msg)
	return rr, len(msg) - len(s), err
}

// UnpackRRWithHeader unpacks the record type specific payload given an existing
// RR_Header.
func UnpackRRWithHeader(h RR_Header, msg []byte, off int) (rr RR, off1 int, err error) {
	if off < 0 || off > len(msg) {
		return &h, off, &Error{err: "bad off"}
	}

	s := cryptobyte.String(msg[off:])
	rr, err = unpackRRWithHeader(h, &s, msg)
	return rr, len(msg) - len(s), err
}

func unpackRR(msg *cryptobyte.String, msgBuf []byte) (RR, error) {
	h, err := unpackRRHeader(msg, msgBuf)
	if err != nil {
		return nil, err
	}

	return unpackRRWithHeader(h, msg, msgBuf)
}

func unpackRRWithHeader(h RR_Header, msg *cryptobyte.String, msgBuf []byte) (RR, error) {
	var rrData cryptobyte.String
	if !msg.ReadBytes((*[]byte)(&rrData), int(h.Rdlength)) {
		return &h, &Error{err: "bad rdlength"}
	}

	var rr RR
	if newFn, ok := TypeToRR[h.Rrtype]; ok {
		rr = newFn()
		*rr.Header() = h
	} else {
		rr = &RFC3597{Hdr: h}
	}

	if rrData.Empty() {
		return rr, nil
	}

	if err := rr.unpack(&rrData, msgBuf); err != nil {
		return nil, err
	}
	if !rrData.Empty() {
		return rr, &Error{err: "bad rdlength"}
	}

	return rr, nil
}

// Convert a MsgHdr to a string, with dig-like headers:
//
// ;; opcode: QUERY, status: NOERROR, id: 48404
//
// ;; flags: qr aa rd ra;
func (h *MsgHdr) String() string {
	if h == nil {
		return "<nil> MsgHdr"
	}

	s := ";; opcode: " + OpcodeToString[h.Opcode]
	s += ", status: " + RcodeToString[h.Rcode]
	s += ", id: " + strconv.Itoa(int(h.Id)) + "\n"

	s += ";; flags:"
	if h.Response {
		s += " qr"
	}
	if h.Authoritative {
		s += " aa"
	}
	if h.Truncated {
		s += " tc"
	}
	if h.RecursionDesired {
		s += " rd"
	}
	if h.RecursionAvailable {
		s += " ra"
	}
	if h.Zero { // Hmm
		s += " z"
	}
	if h.AuthenticatedData {
		s += " ad"
	}
	if h.CheckingDisabled {
		s += " cd"
	}

	s += ";"
	return s
}

// Pack packs a Msg: it is converted to to wire format.
// If the dns.Compress is true the message will be in compressed wire format.
func (dns *Msg) Pack() (msg []byte, err error) {
	return dns.PackBuffer(nil)
}

// PackBuffer packs a Msg, using the given buffer buf. If buf is too small a new buffer is allocated.
func (dns *Msg) PackBuffer(buf []byte) (msg []byte, err error) {
	// If this message can't be compressed, avoid filling the
	// compression map and creating garbage.
	if dns.Compress && dns.isCompressible() {
		compression := make(map[string]uint16) // Compression pointer mappings.
		return dns.packBufferWithCompressionMap(buf, compressionMap{int: compression}, true)
	}

	return dns.packBufferWithCompressionMap(buf, compressionMap{}, false)
}

// packBufferWithCompressionMap packs a Msg, using the given buffer buf.
func (dns *Msg) packBufferWithCompressionMap(buf []byte, compression compressionMap, compress bool) (msg []byte, err error) {
	if dns.Rcode < 0 || dns.Rcode > 0xFFF {
		return nil, ErrRcode
	}

	// Set extended rcode unconditionally if we have an opt, this will allow
	// resetting the extended rcode bits if they need to.
	if opt := dns.IsEdns0(); opt != nil {
		opt.SetExtendedRcode(uint16(dns.Rcode))
	} else if dns.Rcode > 0xF {
		// If Rcode is an extended one and opt is nil, error out.
		return nil, ErrExtendedRcode
	}

	// Convert convenient Msg into wire-like Header.
	var dh Header
	dh.Id = dns.Id
	dh.Bits = uint16(dns.Opcode)<<11 | uint16(dns.Rcode&0xF)
	if dns.Response {
		dh.Bits |= _QR
	}
	if dns.Authoritative {
		dh.Bits |= _AA
	}
	if dns.Truncated {
		dh.Bits |= _TC
	}
	if dns.RecursionDesired {
		dh.Bits |= _RD
	}
	if dns.RecursionAvailable {
		dh.Bits |= _RA
	}
	if dns.Zero {
		dh.Bits |= _Z
	}
	if dns.AuthenticatedData {
		dh.Bits |= _AD
	}
	if dns.CheckingDisabled {
		dh.Bits |= _CD
	}

	dh.Qdcount = uint16(len(dns.Question))
	dh.Ancount = uint16(len(dns.Answer))
	dh.Nscount = uint16(len(dns.Ns))
	dh.Arcount = uint16(len(dns.Extra))

	// We need the uncompressed length here, because we first pack it and then compress it.
	msg = buf
	uncompressedLen := msgLenWithCompressionMap(dns, nil)
	if packLen := uncompressedLen + 1; len(msg) < packLen {
		msg = make([]byte, packLen)
	}

	// Pack it in: header and then the pieces.
	off := 0
	off, err = dh.pack(msg, off, compression, compress)
	if err != nil {
		return nil, err
	}
	for _, r := range dns.Question {
		off, err = r.pack(msg, off, compression, compress)
		if err != nil {
			return nil, err
		}
	}
	for _, r := range dns.Answer {
		_, off, err = packRR(r, msg, off, compression, compress)
		if err != nil {
			return nil, err
		}
	}
	for _, r := range dns.Ns {
		_, off, err = packRR(r, msg, off, compression, compress)
		if err != nil {
			return nil, err
		}
	}
	for _, r := range dns.Extra {
		_, off, err = packRR(r, msg, off, compression, compress)
		if err != nil {
			return nil, err
		}
	}
	return msg[:off], nil
}

func unpackCounted[T any](unpack func(*cryptobyte.String, []byte) (T, error), cnt uint16, msg *cryptobyte.String, msgBuf []byte) ([]T, error) {
	// Qdcount, Ancount, Nscount, Arcount shouldn't be trusted, as they are
	// attacker controlled. To avoid an attacker being able to force us to
	// allocate a large amount of memory with little effort, we don't use them
	// to pre-allocate this slice.

	var dst []T
	for i := 0; i < int(cnt); i++ {
		// msg is already empty, cnt is a lie.
		//
		// TODO(tmthrgd): Remove this to fix #1492.
		if msg.Empty() {
			return dst, nil
		}

		r, err := unpack(msg, msgBuf)
		if err != nil {
			return dst, err
		}
		dst = append(dst, r)
	}
	return dst, nil
}

func (dns *Msg) unpack(dh Header, msg *cryptobyte.String, msgBuf []byte) error {
	// If we are at the end of the message we should return *just* the
	// header. This can still be useful to the caller. 9.9.9.9 sends these
	// when responding with REFUSED for instance.
	//
	// TODO(tmthrgd): Remove this. If it's only sending the header, the header
	// should be specifying that it contains no records.
	if msg.Empty() {
		// reset sections before returning
		dns.Question, dns.Answer, dns.Ns, dns.Extra = nil, nil, nil, nil
		return nil
	}

	var err error
	dns.Question, err = unpackCounted(unpackQuestion, dh.Qdcount, msg, msgBuf)
	if err == nil {
		dns.Answer, err = unpackCounted(unpackRR, dh.Ancount, msg, msgBuf)
	}
	if err == nil {
		dns.Ns, err = unpackCounted(unpackRR, dh.Nscount, msg, msgBuf)
	}
	if err == nil {
		dns.Extra, err = unpackCounted(unpackRR, dh.Arcount, msg, msgBuf)
	}

	// TODO(tmthrgd): Remove these as part of #1492.
	dh.Qdcount = uint16(len(dns.Question))
	dh.Ancount = uint16(len(dns.Answer))
	dh.Nscount = uint16(len(dns.Ns))
	dh.Arcount = uint16(len(dns.Extra))

	// Set extended Rcode
	if opt := dns.IsEdns0(); opt != nil {
		dns.Rcode |= opt.ExtendedRcode()
	}

	// TODO(miek) make this an error?
	// use PackOpt to let people tell how detailed the error reporting should be?
	// if !msg.Empty() {
	// 	println("dns: extra bytes in dns packet", msg.offset(), "<", len(msg.raw))
	// }
	return err

}

// Unpack unpacks a binary message to a Msg structure.
func (dns *Msg) Unpack(msg []byte) (err error) {
	s := cryptobyte.String(msg)
	dh, err := unpackMsgHdr(&s)
	if err != nil {
		return err
	}

	dns.setHdr(dh)
	return dns.unpack(dh, &s, msg)
}

// Convert a complete message to a string with dig-like output.
func (dns *Msg) String() string {
	if dns == nil {
		return "<nil> MsgHdr"
	}
	s := dns.MsgHdr.String() + " "
	if dns.MsgHdr.Opcode == OpcodeUpdate {
		s += "ZONE: " + strconv.Itoa(len(dns.Question)) + ", "
		s += "PREREQ: " + strconv.Itoa(len(dns.Answer)) + ", "
		s += "UPDATE: " + strconv.Itoa(len(dns.Ns)) + ", "
		s += "ADDITIONAL: " + strconv.Itoa(len(dns.Extra)) + "\n"
	} else {
		s += "QUERY: " + strconv.Itoa(len(dns.Question)) + ", "
		s += "ANSWER: " + strconv.Itoa(len(dns.Answer)) + ", "
		s += "AUTHORITY: " + strconv.Itoa(len(dns.Ns)) + ", "
		s += "ADDITIONAL: " + strconv.Itoa(len(dns.Extra)) + "\n"
	}
	opt := dns.IsEdns0()
	if opt != nil {
		// OPT PSEUDOSECTION
		s += opt.String() + "\n"
	}
	if len(dns.Question) > 0 {
		if dns.MsgHdr.Opcode == OpcodeUpdate {
			s += "\n;; ZONE SECTION:\n"
		} else {
			s += "\n;; QUESTION SECTION:\n"
		}
		for _, r := range dns.Question {
			s += r.String() + "\n"
		}
	}
	if len(dns.Answer) > 0 {
		if dns.MsgHdr.Opcode == OpcodeUpdate {
			s += "\n;; PREREQUISITE SECTION:\n"
		} else {
			s += "\n;; ANSWER SECTION:\n"
		}
		for _, r := range dns.Answer {
			if r != nil {
				s += r.String() + "\n"
			}
		}
	}
	if len(dns.Ns) > 0 {
		if dns.MsgHdr.Opcode == OpcodeUpdate {
			s += "\n;; UPDATE SECTION:\n"
		} else {
			s += "\n;; AUTHORITY SECTION:\n"
		}
		for _, r := range dns.Ns {
			if r != nil {
				s += r.String() + "\n"
			}
		}
	}
	if len(dns.Extra) > 0 && (opt == nil || len(dns.Extra) > 1) {
		s += "\n;; ADDITIONAL SECTION:\n"
		for _, r := range dns.Extra {
			if r != nil && r.Header().Rrtype != TypeOPT {
				s += r.String() + "\n"
			}
		}
	}
	return s
}

// isCompressible returns whether the msg may be compressible.
func (dns *Msg) isCompressible() bool {
	// If we only have one question, there is nothing we can ever compress.
	return len(dns.Question) > 1 || len(dns.Answer) > 0 ||
		len(dns.Ns) > 0 || len(dns.Extra) > 0
}

// Len returns the message length when in (un)compressed wire format.
// If dns.Compress is true compression it is taken into account. Len()
// is provided to be a faster way to get the size of the resulting packet,
// than packing it, measuring the size and discarding the buffer.
func (dns *Msg) Len() int {
	// If this message can't be compressed, avoid filling the
	// compression map and creating garbage.
	if dns.Compress && dns.isCompressible() {
		compression := make(map[string]struct{})
		return msgLenWithCompressionMap(dns, compression)
	}

	return msgLenWithCompressionMap(dns, nil)
}

func msgLenWithCompressionMap(dns *Msg, compression map[string]struct{}) int {
	l := headerSize

	for _, r := range dns.Question {
		l += r.len(l, compression)
	}
	for _, r := range dns.Answer {
		if r != nil {
			l += r.len(l, compression)
		}
	}
	for _, r := range dns.Ns {
		if r != nil {
			l += r.len(l, compression)
		}
	}
	for _, r := range dns.Extra {
		if r != nil {
			l += r.len(l, compression)
		}
	}

	return l
}

func domainNameLen(s string, off int, compression map[string]struct{}, compress bool) int {
	if s == "" || s == "." {
		return 1
	}

	escaped := strings.Contains(s, "\\")

	if compression != nil && (compress || off < maxCompressionOffset) {
		// compressionLenSearch will insert the entry into the compression
		// map if it doesn't contain it.
		if l, ok := compressionLenSearch(compression, s, off); ok && compress {
			if escaped {
				return escapedNameLen(s[:l]) + 2
			}

			return l + 2
		}
	}

	if escaped {
		return escapedNameLen(s) + 1
	}

	return len(s) + 1
}

func escapedNameLen(s string) int {
	nameLen := len(s)
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			continue
		}

		if isDDD(s[i+1:]) {
			nameLen -= 3
			i += 3
		} else {
			nameLen--
			i++
		}
	}

	return nameLen
}

func compressionLenSearch(c map[string]struct{}, s string, msgOff int) (int, bool) {
	for off, end := 0, false; !end; off, end = NextLabel(s, off) {
		if _, ok := c[s[off:]]; ok {
			return off, true
		}

		if msgOff+off < maxCompressionOffset {
			c[s[off:]] = struct{}{}
		}
	}

	return 0, false
}

// Copy returns a new RR which is a deep-copy of r.
func Copy(r RR) RR { return r.copy() }

// Len returns the length (in octets) of the uncompressed RR in wire format.
func Len(r RR) int { return r.len(0, nil) }

// Copy returns a new *Msg which is a deep-copy of dns.
func (dns *Msg) Copy() *Msg { return dns.CopyTo(new(Msg)) }

// CopyTo copies the contents to the provided message using a deep-copy and returns the copy.
func (dns *Msg) CopyTo(r1 *Msg) *Msg {
	r1.MsgHdr = dns.MsgHdr
	r1.Compress = dns.Compress

	if len(dns.Question) > 0 {
		// TODO(miek): Question is an immutable value, ok to do a shallow-copy
		r1.Question = cloneSlice(dns.Question)
	}

	rrArr := make([]RR, len(dns.Answer)+len(dns.Ns)+len(dns.Extra))
	r1.Answer, rrArr = rrArr[:0:len(dns.Answer)], rrArr[len(dns.Answer):]
	r1.Ns, rrArr = rrArr[:0:len(dns.Ns)], rrArr[len(dns.Ns):]
	r1.Extra = rrArr[:0:len(dns.Extra)]

	for _, r := range dns.Answer {
		r1.Answer = append(r1.Answer, r.copy())
	}

	for _, r := range dns.Ns {
		r1.Ns = append(r1.Ns, r.copy())
	}

	for _, r := range dns.Extra {
		r1.Extra = append(r1.Extra, r.copy())
	}

	return r1
}

func (q *Question) pack(msg []byte, off int, compression compressionMap, compress bool) (int, error) {
	off, err := packDomainName(q.Name, msg, off, compression, compress)
	if err != nil {
		return off, err
	}
	off, err = packUint16(q.Qtype, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint16(q.Qclass, msg, off)
	if err != nil {
		return off, err
	}
	return off, nil
}

func unpackQuestion(msg *cryptobyte.String, msgBuf []byte) (Question, error) {
	var (
		q   Question
		err error
	)
	q.Name, err = unpackDomainName(msg, msgBuf)
	if err != nil {
		return q, err
	}
	// TODO(tmthrgd): Should we really accept partial questions?
	if !msg.Empty() && !msg.ReadUint16(&q.Qtype) {
		return q, ErrBuf
	}
	if !msg.Empty() && !msg.ReadUint16(&q.Qclass) {
		return q, ErrBuf
	}
	return q, nil
}

func (dh *Header) pack(msg []byte, off int, compression compressionMap, compress bool) (int, error) {
	off, err := packUint16(dh.Id, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint16(dh.Bits, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint16(dh.Qdcount, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint16(dh.Ancount, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint16(dh.Nscount, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint16(dh.Arcount, msg, off)
	if err != nil {
		return off, err
	}
	return off, nil
}

func unpackMsgHdr(msg *cryptobyte.String) (Header, error) {
	var dh Header
	if !msg.ReadUint16(&dh.Id) ||
		!msg.ReadUint16(&dh.Bits) ||
		!msg.ReadUint16(&dh.Qdcount) ||
		!msg.ReadUint16(&dh.Ancount) ||
		!msg.ReadUint16(&dh.Nscount) ||
		!msg.ReadUint16(&dh.Arcount) {
		return dh, ErrBuf
	}
	return dh, nil
}

// setHdr set the header in the dns using the binary data in dh.
func (dns *Msg) setHdr(dh Header) {
	dns.Id = dh.Id
	dns.Response = dh.Bits&_QR != 0
	dns.Opcode = int(dh.Bits>>11) & 0xF
	dns.Authoritative = dh.Bits&_AA != 0
	dns.Truncated = dh.Bits&_TC != 0
	dns.RecursionDesired = dh.Bits&_RD != 0
	dns.RecursionAvailable = dh.Bits&_RA != 0
	dns.Zero = dh.Bits&_Z != 0 // _Z covers the zero bit, which should be zero; not sure why we set it to the opposite.
	dns.AuthenticatedData = dh.Bits&_AD != 0
	dns.CheckingDisabled = dh.Bits&_CD != 0
	dns.Rcode = int(dh.Bits & 0xF)
}
