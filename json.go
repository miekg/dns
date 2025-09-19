package dns

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

var _ json.Marshaler = &Msg{}
var _ json.Unmarshaler = &Msg{}

var (
	ErrEmptyInput          = errors.New("empty input")
	ErrInvalidJSON         = errors.New("invalid JSON")
	ErrInvalidMessage      = errors.New("invalid message")
	ErrQuestionQType       = errors.New("question qtype")
	ErrQuestionQClass      = errors.New("question qclass")
	ErrAnswerSection       = errors.New("answer")
	ErrNsSection           = errors.New("ns")
	ErrExtraSection        = errors.New("extra")
	ErrUnknownType         = errors.New("unknown type")
	ErrUnknownClass        = errors.New("unknown class")
	ErrInvalidStringSlice  = errors.New("invalid string slice")
	ErrEDNSOptionEntry     = errors.New("edns option entry type")
	ErrEDNSOption          = errors.New("edns option")
	ErrEDNSOptionsNotArray = errors.New("opt options must be array")
	ErrEDNSOptionNoCode    = errors.New("opt option missing code")
	ErrUint8SliceType      = errors.New("uint8 slice type")
	ErrUint8SliceElement   = errors.New("uint8 slice element")
	ErrUint8SliceRange     = errors.New("uint8 slice range")
	ErrNegativeValue       = errors.New("negative value")
	ErrInvalidNumber       = errors.New("invalid number")
	ErrInvalidNumberType   = errors.New("invalid number type")
)

// MessageJSON is the top-level JSON shape for Msg.
type MessageJSON struct {
	ID       uint16         `json:"id"`
	MsgHdr   MsgHdrJSON     `json:"msgHdr"`
	Question []QuestionJSON `json:"question"`
	Answer   []RRJSON       `json:"answer,omitempty"`
	Ns       []RRJSON       `json:"ns,omitempty"`
	Extra    []RRJSON       `json:"extra,omitempty"`
}

type MsgHdrJSON struct {
	QR     bool   `json:"qr,omitempty"`
	Opcode string `json:"opcode"`
	AA     bool   `json:"aa,omitempty"`
	TC     bool   `json:"tc,omitempty"`
	RD     bool   `json:"rd,omitempty"`
	RA     bool   `json:"ra,omitempty"`
	Z      bool   `json:"z,omitempty"`
	AD     bool   `json:"ad,omitempty"`
	CD     bool   `json:"cd,omitempty"`
	Rcode  string `json:"rcode"`
}

type QuestionJSON struct {
	Name   string `json:"name"`
	Qtype  string `json:"qtype"`
	Qclass string `json:"qclass"`
}

// RRJSON contains common RR header fields plus a per-type data map.
type RRJSON struct {
	Name  string         `json:"name"`
	Type  string         `json:"type"`
	Class string         `json:"class"`
	TTL   uint32         `json:"ttl"`
	Data  map[string]any `json:"data"`
}

// MarshalJSON provides JSON marshalling for *Msg using an explicit, human-readable JSON schema.
//
// Schema overview (stable keys; rdata keys per RR type listed below):
//
//	{
//	  "id": 1234,
//	  "msgHdr": {"qr":true, "opcode":"QUERY", "aa":false, "tc":false, "rd":true,
//	              "ra":true, "z":0, "ad":false, "cd":false, "rcode":"NOERROR"},
//	  "question": [{"name":"example.com.", "qtype":"A", "qclass":"IN"}],
//	  "answer":  [ RRJSON, ... ],
//	  "ns":      [ RRJSON, ... ],
//	  "extra":   [ RRJSON, ... ]
//	}
//
// RRJSON (common fields) + per-type data (examples):
//
//	{
//	  "name":"example.com.", "type":"A", "class":"IN", "ttl":300,
//	  "data": { "a":"93.184.216.34" }
//	}
//
// AAAA: {"aaaa":"2001:db8::1"}
// CNAME: {"target":"alias.example."}
// NS: {"ns":"ns1.example."}
// PTR: {"ptr":"host.example."}
// TXT: {"txt":["chunk1","chunk2"]}
// MX: {"preference":10, "mx":"mail.example."}
// SRV: {"priority":0, "weight":5, "port":443, "target":"svc.example."}
// SOA: {"ns":"ns1.", "mbox":"hostmaster.", "serial":1, "refresh":7200, "retry":900, "expire":1209600, "minttl":300}
// CAA: {"flag":0, "tag":"issue", "value":"letsencrypt.org"}
// NAPTR: {"order":100, "preference":50, "flags":"s", "services":"SIP+D2U", "regexp":"", "replacement":"_sip._udp.example."}
// DS: {"key_tag":12345, "algorithm":8, "digest_type":2, "digest":"...hex..."}
// DNSKEY: {"flags":257, "protocol":3, "algorithm":8, "public_key":"base64..."}
// RRSIG: {"type_covered":"A", "algorithm":8, "labels":2, "original_ttl":300,
//
//	"expiration": 1735689600, "inception": 1733097600, "key_tag":12345,
//	"signer_name":"example.", "signature":"base64..."}
//
// TLSA: {"usage":3, "selector":1, "matching_type":1, "cert_data":"hex or base64"}
//
// Notes
//   - Type/class use standard mnemonics (e.g., "A", "AAAA", "IN").
//   - Unknown/less-common RR types are round-tripped via a best-effort map in "data"; if a
//     type is not implemented below, Marshal will include {"raw": "<presentation>"} and
//     Unmarshal will parse it using NewRR on a synthesized presentation string.
//   - Times in RRSIG use UNIX seconds per miekg/dns conventions.
func (m *Msg) MarshalJSON() (b []byte, err error) {
	b = []byte("null")
	if m != nil {
		j := MessageJSON{
			ID:     m.Id,
			MsgHdr: hdrToJSON(m.MsgHdr),
			Answer: rrsToJSON(m.Answer),
			Ns:     rrsToJSON(m.Ns),
			Extra:  rrsToJSON(m.Extra),
		}
		// Questions
		for _, q := range m.Question {
			j.Question = append(j.Question, QuestionJSON{
				Name:   q.Name,
				Qtype:  typeToString(q.Qtype),
				Qclass: classToString(q.Qclass),
			})
		}
		b, err = json.Marshal(j)
	}
	return
}

func (msg *Msg) UnmarshalJSON(data []byte) (err error) {
	err = ErrEmptyInput
	if len(data) > 0 {
		var raw json.RawMessage
		if err = wrapError(ErrInvalidJSON, json.Unmarshal(data, &raw)); err == nil {
			if string(raw) != "null" {
				var j MessageJSON
				if err = wrapError(ErrInvalidMessage, json.Unmarshal(raw, &j)); err == nil {
					msg.MsgHdr = hdrFromJSON(j.MsgHdr)
					msg.Id = j.ID
					// Questions
					for _, qj := range j.Question {
						qt, e := stringToType(qj.Qtype)
						err = errors.Join(err, wrapError(ErrQuestionQType, e))
						qc, e := stringToClass(qj.Qclass)
						err = errors.Join(err, wrapError(ErrQuestionQClass, e))
						msg.Question = append(msg.Question, Question{Name: qj.Name, Qtype: qt, Qclass: qc})
					}
					// Sections
					var e error
					msg.Answer, e = rrsFromJSON(j.Answer)
					err = errors.Join(err, wrapError(ErrAnswerSection, e))
					msg.Ns, e = rrsFromJSON(j.Ns)
					err = errors.Join(err, wrapError(ErrNsSection, e))
					msg.Extra, e = rrsFromJSON(j.Extra)
					err = errors.Join(err, wrapError(ErrExtraSection, e))
				}
			}
		}
	}
	return
}

// --- helpers ---

func hdrToJSON(h MsgHdr) MsgHdrJSON {
	return MsgHdrJSON{
		QR:     h.Response,
		Opcode: OpcodeToString[h.Opcode],
		AA:     h.Authoritative,
		TC:     h.Truncated,
		RD:     h.RecursionDesired,
		RA:     h.RecursionAvailable,
		Z:      h.Zero,
		AD:     h.AuthenticatedData,
		CD:     h.CheckingDisabled,
		Rcode:  RcodeToString[h.Rcode],
	}
}

func hdrFromJSON(j MsgHdrJSON) (mh MsgHdr) {
	mh.Response = j.QR
	mh.Opcode = stringToOpcode(j.Opcode)
	mh.Authoritative = j.AA
	mh.Truncated = j.TC
	mh.RecursionDesired = j.RD
	mh.RecursionAvailable = j.RA
	mh.Zero = j.Z
	mh.AuthenticatedData = j.AD
	mh.CheckingDisabled = j.CD
	mh.Rcode = stringToRcode(j.Rcode)
	return
}

func rrsToJSON(rrs []RR) (out []RRJSON) {
	for _, rr := range rrs {
		out = append(out, rrToJSON(rr))
	}
	return
}

func rrsFromJSON(rrjs []RRJSON) (out []RR, err error) {
	for _, j := range rrjs {
		if rr, e := rrFromJSON(j); e == nil {
			out = append(out, rr)
		} else {
			err = errors.Join(err, e)
		}
	}
	return
}

func rrToJSON(rr RR) RRJSON {
	h := rr.Header()
	j := RRJSON{
		Name:  h.Name,
		Type:  typeToString(h.Rrtype),
		Class: classToString(h.Class),
		TTL:   h.Ttl,
		Data:  map[string]any{},
	}
	switch v := rr.(type) {
	case *A:
		j.Data["a"] = v.A.String()
	case *AAAA:
		j.Data["aaaa"] = v.AAAA.String()
	case *CNAME:
		j.Data["target"] = v.Target
	case *NS:
		j.Data["ns"] = v.Ns
	case *PTR:
		j.Data["ptr"] = v.Ptr
	case *TXT:
		j.Data["txt"] = append([]string(nil), v.Txt...)
	case *MX:
		j.Data["preference"] = v.Preference
		j.Data["mx"] = v.Mx
	case *SRV:
		j.Data["priority"] = v.Priority
		j.Data["weight"] = v.Weight
		j.Data["port"] = v.Port
		j.Data["target"] = v.Target
	case *SOA:
		j.Data["ns"] = v.Ns
		j.Data["mbox"] = v.Mbox
		j.Data["serial"] = v.Serial
		j.Data["refresh"] = v.Refresh
		j.Data["retry"] = v.Retry
		j.Data["expire"] = v.Expire
		j.Data["minttl"] = v.Minttl
	case *CAA:
		j.Data["flag"] = v.Flag
		j.Data["tag"] = v.Tag
		j.Data["value"] = v.Value
	case *NAPTR:
		j.Data["order"] = v.Order
		j.Data["preference"] = v.Preference
		j.Data["flags"] = v.Flags
		j.Data["service"] = v.Service
		j.Data["regexp"] = v.Regexp
		j.Data["replacement"] = v.Replacement
	case *DS:
		j.Data["key_tag"] = v.KeyTag
		j.Data["algorithm"] = v.Algorithm
		j.Data["digest_type"] = v.DigestType
		j.Data["digest"] = strings.ToLower(v.Digest)
	case *DNSKEY:
		j.Data["flags"] = v.Flags
		j.Data["protocol"] = v.Protocol
		j.Data["algorithm"] = v.Algorithm
		j.Data["public_key"] = v.PublicKey
	case *RRSIG:
		j.Data["type_covered"] = typeToString(v.TypeCovered)
		j.Data["algorithm"] = v.Algorithm
		j.Data["labels"] = v.Labels
		j.Data["original_ttl"] = v.OrigTtl
		j.Data["expiration"] = v.Expiration
		j.Data["inception"] = v.Inception
		j.Data["key_tag"] = v.KeyTag
		j.Data["signer_name"] = v.SignerName
		j.Data["signature"] = v.Signature
	case *TLSA:
		j.Data["usage"] = v.Usage
		j.Data["selector"] = v.Selector
		j.Data["matching_type"] = v.MatchingType
		j.Data["cert_data"] = v.Certificate
	case *OPT:
		j.Data["udp_size"] = v.UDPSize()
		j.Data["extended_rcode"] = uint16(v.ExtendedRcode()) // #nosec G115
		j.Data["version"] = v.Version()
		j.Data["do"] = v.Do()
		j.Data["co"] = v.Co()
		j.Data["z"] = v.Z()
		if len(v.Option) > 0 {
			opts := make([]map[string]any, 0, len(v.Option))
			for _, opt := range v.Option {
				opts = append(opts, ednsOptionToJSON(opt))
			}
			j.Data["options"] = opts
		}
	default:
		// Fallback to presentation for unknown types to maintain coverage without wire format.
		j.Data["raw"] = rr.String()
	}
	return j
}

func rrFromJSON(j RRJSON) (rr RR, err error) {
	var typeCode, classCode uint16
	if typeCode, err = stringToType(j.Type); err == nil {
		if classCode, err = stringToClass(j.Class); err == nil {
			// Choose concrete by type
			switch typeCode {
			case TypeA:
				var ip netip.Addr
				if ip, err = netip.ParseAddr(getString(j.Data, "a")); err == nil {
					if ip.Is4() {
						rr = &A{
							Hdr: rrHdr(j, typeCode, classCode),
							A:   ip.AsSlice(),
						}
					}
				}
			case TypeAAAA:
				var ip netip.Addr
				if ip, err = netip.ParseAddr(getString(j.Data, "aaaa")); err == nil {
					if ip.Is6() {
						rr = &AAAA{
							Hdr:  rrHdr(j, typeCode, classCode),
							AAAA: ip.AsSlice(),
						}
					}
				}
			case TypeCNAME:
				rr = &CNAME{
					Hdr:    rrHdr(j, typeCode, classCode),
					Target: getString(j.Data, "target"),
				}
			case TypeNS:
				rr = &NS{
					Hdr: rrHdr(j, typeCode, classCode),
					Ns:  getString(j.Data, "ns"),
				}
			case TypePTR:
				rr = &PTR{
					Hdr: rrHdr(j, typeCode, classCode),
					Ptr: getString(j.Data, "ptr"),
				}
			case TypeTXT:
				var arr []string
				if arr, err = getStringSlice(j.Data, "txt"); err == nil {
					rr = &TXT{
						Hdr: rrHdr(j, typeCode, classCode),
						Txt: arr,
					}
				}
			case TypeMX:
				rr = &MX{
					Hdr:        rrHdr(j, typeCode, classCode),
					Preference: getUint16(j.Data, "preference"),
					Mx:         getString(j.Data, "mx"),
				}
			case TypeSRV:
				rr = &SRV{
					Hdr:      rrHdr(j, typeCode, classCode),
					Priority: getUint16(j.Data, "priority"),
					Weight:   getUint16(j.Data, "weight"),
					Port:     getUint16(j.Data, "port"),
					Target:   getString(j.Data, "target"),
				}
			case TypeSOA:
				rr = &SOA{
					Hdr:     rrHdr(j, typeCode, classCode),
					Ns:      getString(j.Data, "ns"),
					Mbox:    getString(j.Data, "mbox"),
					Serial:  getUint32(j.Data, "serial"),
					Refresh: getUint32(j.Data, "refresh"),
					Retry:   getUint32(j.Data, "retry"),
					Expire:  getUint32(j.Data, "expire"),
					Minttl:  getUint32(j.Data, "minttl"),
				}
			case TypeCAA:
				rr = &CAA{
					Hdr:   rrHdr(j, typeCode, classCode),
					Flag:  getUint8(j.Data, "flag"),
					Tag:   getString(j.Data, "tag"),
					Value: getString(j.Data, "value"),
				}
			case TypeNAPTR:
				rr = &NAPTR{
					Hdr:         rrHdr(j, typeCode, classCode),
					Order:       getUint16(j.Data, "order"),
					Preference:  getUint16(j.Data, "preference"),
					Flags:       getString(j.Data, "flags"),
					Service:     getString(j.Data, "service"),
					Regexp:      getString(j.Data, "regexp"),
					Replacement: getString(j.Data, "replacement"),
				}
			case TypeDS:
				rr = &DS{
					Hdr:        rrHdr(j, typeCode, classCode),
					KeyTag:     getUint16(j.Data, "key_tag"),
					Algorithm:  getUint8(j.Data, "algorithm"),
					DigestType: getUint8(j.Data, "digest_type"),
					Digest:     strings.ToUpper(getString(j.Data, "digest")),
				}
			case TypeDNSKEY:
				rr = &DNSKEY{
					Hdr:       rrHdr(j, typeCode, classCode),
					Flags:     getUint16(j.Data, "flags"),
					Protocol:  getUint8(j.Data, "protocol"),
					Algorithm: getUint8(j.Data, "algorithm"),
					PublicKey: getString(j.Data, "public_key"),
				}
			case TypeRRSIG:
				var cov uint16
				if cov, err = stringToType(getString(j.Data, "type_covered")); err == nil {
					rr = &RRSIG{
						Hdr:         rrHdr(j, typeCode, classCode),
						TypeCovered: cov,
						Algorithm:   getUint8(j.Data, "algorithm"),
						Labels:      getUint8(j.Data, "labels"),
						OrigTtl:     getUint32(j.Data, "original_ttl"),
						Expiration:  getUint32(j.Data, "expiration"),
						Inception:   getUint32(j.Data, "inception"),
						KeyTag:      getUint16(j.Data, "key_tag"),
						SignerName:  getString(j.Data, "signer_name"),
						Signature:   getString(j.Data, "signature"),
					}
				}
			case TypeTLSA:
				rr = &TLSA{
					Hdr:          rrHdr(j, typeCode, classCode),
					Usage:        getUint8(j.Data, "usage"),
					Selector:     getUint8(j.Data, "selector"),
					MatchingType: getUint8(j.Data, "matching_type"),
					Certificate:  getString(j.Data, "cert_data"),
				}
			case TypeOPT:
				opt := &OPT{Hdr: rrHdr(j, typeCode, classCode)}
				udp_size := classCode
				if _, ok := j.Data["udp_size"]; ok {
					udp_size = getUint16(j.Data, "udp_size")
				}
				opt.SetUDPSize(udp_size)
				if _, ok := j.Data["extended_rcode"]; ok {
					opt.SetExtendedRcode(getUint16(j.Data, "extended_rcode"))
				}
				if _, ok := j.Data["version"]; ok {
					opt.SetVersion(getUint8(j.Data, "version"))
				}
				if do, ok := getBool(j.Data, "do"); ok {
					opt.SetDo(do)
				}
				if co, ok := getBool(j.Data, "co"); ok {
					opt.SetCo(co)
				}
				if _, ok := j.Data["z"]; ok {
					opt.SetZ(getUint16(j.Data, "z"))
				}
				if raw, ok := j.Data["options"]; ok {
					err = ErrEDNSOptionsNotArray
					if arr, ok := raw.([]any); ok {
						err = nil
						for idx, entry := range arr {
							var option EDNS0
							if option, err = ednsOptionFromJSON(entry); err == nil {
								opt.Option = append(opt.Option, option)
							} else {
								err = errors.Join(err, &optOptionEntryError{index: idx})
							}
						}
					}
				}
				if err == nil {
					rr = opt
				}
			default:
				// Best-effort fallback using presentation format stored in data.raw
				if rr, err = NewRR(strings.TrimSpace(getString(j.Data, "raw"))); err == nil {
					// NewRR does not preserve TTL/class/name from header in raw string if omitted; ensure header set
					if h := rr.Header(); h != nil {
						h.Name = j.Name
						h.Class = classCode
						h.Rrtype = typeCode
						h.Ttl = j.TTL
					}
				}
			}
		}
	}
	return
}

func ednsOptionToJSON(opt EDNS0) map[string]any {
	m := map[string]any{
		"code": optionCodeToString(opt.Option()),
	}
	switch o := opt.(type) {
	case *EDNS0_NSID:
		m["nsid"] = strings.ToLower(o.Nsid)
	case *EDNS0_SUBNET:
		m["family"] = o.Family
		m["source_netmask"] = o.SourceNetmask
		m["source_scope"] = o.SourceScope
		if o.Address != nil {
			m["address"] = o.Address.String()
		}
	case *EDNS0_COOKIE:
		m["cookie"] = strings.ToLower(o.Cookie)
	case *EDNS0_UL:
		m["lease"] = o.Lease
		m["key_lease"] = o.KeyLease
	case *EDNS0_LLQ:
		m["version"] = o.Version
		m["opcode"] = o.Opcode
		m["error"] = o.Error
		m["id"] = o.Id
		m["lease_life"] = o.LeaseLife
	case *EDNS0_DAU:
		m["alg_codes"] = uint8SliceToIntSlice(o.AlgCode)
	case *EDNS0_DHU:
		m["alg_codes"] = uint8SliceToIntSlice(o.AlgCode)
	case *EDNS0_N3U:
		m["alg_codes"] = uint8SliceToIntSlice(o.AlgCode)
	case *EDNS0_EXPIRE:
		m["expire"] = o.Expire
		if o.Empty {
			m["empty"] = true
		}
	case *EDNS0_LOCAL:
		m["data"] = strings.ToLower(hex.EncodeToString(o.Data))
	case *EDNS0_TCP_KEEPALIVE:
		m["timeout"] = o.Timeout
	case *EDNS0_PADDING:
		m["padding"] = strings.ToLower(hex.EncodeToString(o.Padding))
	case *EDNS0_EDE:
		m["info_code"] = o.InfoCode
		m["extra_text"] = o.ExtraText
	case *EDNS0_ESU:
		m["uri"] = o.Uri
	}
	return m
}

func ednsOptionFromJSON(in any) (rr EDNS0, err error) {
	err = ErrEDNSOptionNoCode
	if m, ok := in.(map[string]any); ok {
		if codeStr := getString(m, "code"); codeStr != "" {
			var code uint16
			if code, err = stringToOptionCode(codeStr); err == nil {
				switch code {
				case EDNS0NSID:
					rr = &EDNS0_NSID{Code: code, Nsid: strings.ToLower(getString(m, "nsid"))}
				case EDNS0SUBNET:
					var address net.IP
					if addr := getString(m, "address"); addr != "" {
						var ip netip.Addr
						if ip, err = netip.ParseAddr(addr); err == nil {
							address = ip.AsSlice()
						}
					}
					if err == nil {
						rr = &EDNS0_SUBNET{
							Code:          code,
							Family:        getUint16(m, "family"),
							SourceNetmask: getUint8(m, "source_netmask"),
							SourceScope:   getUint8(m, "source_scope"),
							Address:       address,
						}
					}
				case EDNS0COOKIE:
					rr = &EDNS0_COOKIE{Code: code, Cookie: strings.ToLower(getString(m, "cookie"))}
				case EDNS0UL:
					rr = &EDNS0_UL{Code: code, Lease: getUint32(m, "lease"), KeyLease: getUint32(m, "key_lease")}
				case EDNS0LLQ:
					var id uint64
					if raw, ok := m["id"]; ok {
						id, err = anyToUint64(raw)
					}
					if err == nil {
						rr = &EDNS0_LLQ{
							Id:        id,
							Code:      code,
							Version:   getUint16(m, "version"),
							Opcode:    getUint16(m, "opcode"),
							Error:     getUint16(m, "error"),
							LeaseLife: getUint32(m, "lease_life"),
						}
					}
				case EDNS0DAU:
					var algs []uint8
					if algs, err = getUint8Slice(m, "alg_codes"); err == nil {
						rr = &EDNS0_DAU{Code: code, AlgCode: algs}
					}
				case EDNS0DHU:
					var algs []uint8
					if algs, err = getUint8Slice(m, "alg_codes"); err == nil {
						rr = &EDNS0_DHU{Code: code, AlgCode: algs}
					}
				case EDNS0N3U:
					var algs []uint8
					if algs, err = getUint8Slice(m, "alg_codes"); err == nil {
						rr = &EDNS0_N3U{Code: code, AlgCode: algs}
					}
				case EDNS0EXPIRE:
					empty, _ := getBool(m, "empty")
					rr = &EDNS0_EXPIRE{Code: code, Expire: getUint32(m, "expire"), Empty: empty}
				case EDNS0TCPKEEPALIVE:
					rr = &EDNS0_TCP_KEEPALIVE{Code: code, Timeout: getUint16(m, "timeout")}
				case EDNS0PADDING:
					var padding []byte
					if padding, err = hex.DecodeString(getString(m, "padding")); err == nil {
						rr = &EDNS0_PADDING{Padding: padding}
					}
				case EDNS0EDE:
					rr = &EDNS0_EDE{InfoCode: getUint16(m, "info_code"), ExtraText: getString(m, "extra_text")}
				case EDNS0ESU:
					rr = &EDNS0_ESU{Code: code, Uri: getString(m, "uri")}
				default:
					var data []byte
					if data, err = hex.DecodeString(getString(m, "data")); err == nil {
						rr = &EDNS0_LOCAL{Code: code, Data: data}
					}
				}
				if err != nil {
					err = &optOptionCodeError{code: codeStr, err: err}
				}
			}
		}
	}
	return
}

func rrHdr(j RRJSON, t uint16, c uint16) RR_Header {
	return RR_Header{Name: j.Name, Rrtype: t, Class: c, Ttl: j.TTL}
}

// --- mapping helpers ---

func typeToString(t uint16) (s string) {
	var ok bool
	if s, ok = TypeToString[t]; !ok {
		s = strconv.FormatUint(uint64(t), 10)
	}
	return
}

func stringToType(s string) (typ uint16, err error) {
	var ok bool
	if typ, ok = StringToType[strings.ToUpper(s)]; !ok {
		var n uint64
		if n, err = strconv.ParseUint(s, 10, 16); err == nil {
			typ = uint16(n)
		} else {
			err = &unknownTypeError{value: s}
		}
	}
	return
}

func classToString(c uint16) (s string) {
	var ok bool
	if s, ok = ClassToString[c]; !ok {
		s = strconv.FormatUint(uint64(c), 10)
	}
	return
}

func stringToClass(s string) (cls uint16, err error) {
	var ok bool
	if cls, ok = StringToClass[strings.ToUpper(s)]; !ok {
		var n uint64
		if n, err = strconv.ParseUint(s, 10, 16); err == nil {
			cls = uint16(n)
		} else {
			err = &unknownClassError{value: s}
		}
	}
	return
}

var optionCodeToName = map[uint16]string{
	EDNS0LLQ:          "LLQ",
	EDNS0UL:           "UL",
	EDNS0NSID:         "NSID",
	EDNS0DAU:          "DAU",
	EDNS0DHU:          "DHU",
	EDNS0N3U:          "N3U",
	EDNS0SUBNET:       "SUBNET",
	EDNS0EXPIRE:       "EXPIRE",
	EDNS0COOKIE:       "COOKIE",
	EDNS0TCPKEEPALIVE: "TCPKEEPALIVE",
	EDNS0PADDING:      "PADDING",
	EDNS0EDE:          "EDE",
	EDNS0ESU:          "ESU",
}

var optionNameToCode = func() map[string]uint16 {
	out := make(map[string]uint16, len(optionCodeToName)+1)
	for code, name := range optionCodeToName {
		out[strings.ToUpper(name)] = code
	}
	out["TCP_KEEPALIVE"] = EDNS0TCPKEEPALIVE
	return out
}()

func optionCodeToString(code uint16) (s string) {
	var ok bool
	if s, ok = optionCodeToName[code]; !ok {
		s = strconv.FormatUint(uint64(code), 10)
	}
	return
}

func stringToOptionCode(s string) (code uint16, err error) {
	var ok bool
	if code, ok = optionNameToCode[strings.ToUpper(s)]; !ok {
		var n uint64
		if n, err = strconv.ParseUint(s, 10, 16); err == nil {
			code = uint16(n)
		} else {
			err = &unknownOptionError{value: s}
		}
	}
	return
}

func stringToOpcode(s string) (opcode int) {
	opcode = OpcodeQuery
	if op, ok := StringToOpcode[strings.ToUpper(s)]; ok {
		opcode = op
	}
	return
}

func stringToRcode(s string) (rcode int) {
	rcode = RcodeSuccess
	if rc, ok := StringToRcode[strings.ToUpper(s)]; ok {
		rcode = rc
	}
	return
}

// --- small JSON helpers ---

func getString(m map[string]any, key string) (s string) {
	if m != nil {
		if v, ok := m[key]; ok {
			s, _ = v.(string)
		}
	}
	return
}

func getUint8(m map[string]any, key string) uint8 {
	return uint8(getInt(m, key)) // #nosec G115
}
func getUint16(m map[string]any, key string) uint16 {
	return uint16(getInt(m, key)) // #nosec G115
}
func getUint32(m map[string]any, key string) uint32 {
	return uint32(getInt(m, key)) // #nosec G115
}

func getInt(m map[string]any, key string) (n int64) {
	if m != nil {
		if v, ok := m[key]; ok {
			switch t := v.(type) {
			case float64:
				n = int64(t)
			case int:
				n = int64(t)
			case int64:
				n = t
			case json.Number:
				n, _ = t.Int64()
			case string:
				n, _ = strconv.ParseInt(t, 10, 64)
			}
		}
	}
	return
}

func getStringSlice(m map[string]any, key string) (out []string, err error) {
	if v, ok := m[key]; ok {
		a, ok := v.([]any)
		if !ok {
			return nil, &stringSliceError{key: key}
		}
		for _, it := range a {
			s, ok := it.(string)
			if !ok {
				return nil, &stringSliceError{key: key}
			}
			out = append(out, s)
		}
	}
	return
}

func getBool(m map[string]any, key string) (bool, bool) {
	if m != nil {
		if v, ok := m[key]; ok {
			switch t := v.(type) {
			case bool:
				return t, true
			case string:
				if b, err := strconv.ParseBool(t); err == nil {
					return b, true
				}
			case float64:
				return t != 0, true
			case json.Number:
				if n, err := t.Int64(); err == nil {
					return n != 0, true
				}
			}
		}
	}
	return false, false
}

func getUint8Slice(m map[string]any, key string) (out []uint8, err error) {
	if m != nil {
		if raw, ok := m[key]; ok {
			arr, ok := raw.([]any)
			if !ok {
				return nil, &keyArrayError{key: key}
			}
			for idx, v := range arr {
				val, e := anyToUint64(v)
				if e != nil {
					return nil, &keyIndexError{key: key, index: idx, err: e}
				}
				if val > math.MaxUint8 {
					return nil, &keyIndexRangeError{key: key, index: idx}
				}
				out = append(out, uint8(val))
			}
		}
	}
	return
}

func anyToUint64(v any) (n uint64, err error) {
	switch t := v.(type) {
	case float64:
		if t < 0 {
			return 0, ErrNegativeValue
		}
		n = uint64(t)
	case json.Number:
		var val int64
		if val, err = t.Int64(); err == nil {
			if val < 0 {
				err = ErrNegativeValue
			} else {
				n = uint64(val)
			}
		}
	case string:
		if t != "" {
			n, err = strconv.ParseUint(t, 10, 64)
		}
	case int:
		if t < 0 {
			return 0, ErrNegativeValue
		}
		n = uint64(t)
	case int64:
		if t < 0 {
			return 0, ErrNegativeValue
		}
		n = uint64(t)
	case uint8:
		n = uint64(t)
	case uint16:
		n = uint64(t)
	case uint32:
		n = uint64(t)
	case uint64:
		n = t
	default:
		err = ErrInvalidNumberType
	}
	return
}

func uint8SliceToIntSlice(in []uint8) []int {
	out := make([]int, 0, len(in))
	for _, v := range in {
		out = append(out, int(v))
	}
	return out
}

type wrappedError struct {
	sentinel error
	err      error
}

func wrapError(sentinel, err error) (out error) {
	if err != nil {
		out = &wrappedError{sentinel: sentinel, err: err}
	}
	return
}

func (w *wrappedError) Error() string {
	return w.sentinel.Error() + ": " + w.err.Error()
}

func (w *wrappedError) Unwrap() error {
	return w.err
}

func (w *wrappedError) Is(target error) bool {
	return target == w.sentinel || errors.Is(w.err, target)
}

type unknownTypeError struct {
	value string
}

func (e *unknownTypeError) Error() string {
	return "unknown type " + strconv.Quote(e.value)
}

func (e *unknownTypeError) Is(target error) bool {
	return target == ErrUnknownType
}

type unknownClassError struct {
	value string
}

func (e *unknownClassError) Error() string {
	return "unknown class " + strconv.Quote(e.value)
}

func (e *unknownClassError) Is(target error) bool {
	return target == ErrUnknownClass
}

type unknownOptionError struct {
	value string
}

func (e *unknownOptionError) Error() string {
	return "unknown option code " + strconv.Quote(e.value)
}

type stringSliceError struct {
	key string
}

func (e *stringSliceError) Error() string {
	return e.key + " must be array of strings"
}

func (e *stringSliceError) Is(target error) bool {
	return target == ErrInvalidStringSlice
}

type optOptionEntryError struct {
	index int
}

func (e *optOptionEntryError) Error() string {
	return "opt options[" + strconv.Itoa(e.index) + "] must be object"
}

func (e *optOptionEntryError) Is(target error) bool {
	return target == ErrEDNSOptionEntry
}

type optOptionCodeError struct {
	code string
	err  error
}

func (e *optOptionCodeError) Error() string {
	if e.err == nil {
		return "opt option " + e.code
	}
	return "opt option " + e.code + ": " + e.err.Error()
}

func (e *optOptionCodeError) Unwrap() error {
	return e.err
}

func (e *optOptionCodeError) Is(target error) bool {
	return target == ErrEDNSOption || errors.Is(e.err, target)
}

type keyArrayError struct {
	key string
}

func (e *keyArrayError) Error() string {
	return e.key + " must be array"
}

func (e *keyArrayError) Is(target error) bool {
	return target == ErrUint8SliceType
}

type keyIndexError struct {
	key   string
	index int
	err   error
}

func (e *keyIndexError) Error() string {
	if e.err == nil {
		return e.key + "[" + strconv.Itoa(e.index) + "]"
	}
	return e.key + "[" + strconv.Itoa(e.index) + "]: " + e.err.Error()
}

func (e *keyIndexError) Unwrap() error {
	return e.err
}

func (e *keyIndexError) Is(target error) bool {
	return target == ErrUint8SliceElement || errors.Is(e.err, target)
}

type keyIndexRangeError struct {
	key   string
	index int
}

func (e *keyIndexRangeError) Error() string {
	return e.key + "[" + strconv.Itoa(e.index) + "]: value out of range"
}

func (e *keyIndexRangeError) Is(target error) bool {
	return target == ErrUint8SliceRange
}
