package dns

import (
	"strings"
)

// PrivateRData is an interface to implement non-RFC dictated resource records. See also dns.PrivateRR, dns.RegisterPrivateRR and dns.UnregisterPrivateRR
type PrivateRData interface {
	String() string
	ReadText([]string) error
	Write([]byte) (int, error)
	Read([]byte) (int, error)
	CopyTo(PrivateRData) error
	RdataLen() int
}

// PrivateRR represents RR that uses PrivateRData user-defined type. It mocks normal RRs and implements dns.RR interface.
type PrivateRR struct {
	Hdr  RR_Header
	Data PrivateRData
}

// Header returns Private RR header.
func (r *PrivateRR) Header() *RR_Header { return &r.Hdr }

// String returns text representation of a Private Resource Record.
func (r *PrivateRR) String() string { return r.Hdr.String() + r.Data.String() }

// Private len and copy parts to satisfy RR interface.
func (r *PrivateRR) len() int { return r.Hdr.len() + r.Data.RdataLen() }
func (r *PrivateRR) copy() RR {
	// make new RR like this:
	rrfunc, ok := typeToRR[r.Hdr.Rrtype]
	if !ok {
		panic("dns: invalid operation with Private RR " + r.Hdr.String())
	}
	rr := rrfunc()
	r.Header().CopyTo(rr)

	rrcust, ok := rr.(*PrivateRR)
	if !ok {
		panic("dns: Private RR generator returned wrong interface value")
	}

	err := r.Data.CopyTo(rrcust.Data)
	if err != nil {
		panic("dns: got value that could not be used to copy Private rdata")
	}

	return rr
}

// RegisterPrivateRR adds support for user-defined resource record type to internals of dns library. Requires
// string and numeric representation of RR type and generator function as argument.
func RegisterPrivateRR(rtypestr string, rtype uint16, generator func() PrivateRData) {
	rtypestr = strings.ToUpper(rtypestr)

	typeToRR[rtype] = func() RR { return &PrivateRR{RR_Header{}, generator()} }
	TypeToString[rtype] = rtypestr
	StringToType[rtypestr] = rtype

	setPrivateRR := func(h RR_Header, c chan lex, o, f string) (RR, *ParseError, string) {
		rrfunc := typeToRR[h.Rrtype]
		rr, ok := rrfunc().(*PrivateRR)
		if !ok {
			panic("dns: invalid handler registered for Private RR " + rtypestr)
		}
		h.CopyTo(rr)

		var l lex
		text := make([]string, 0)
		for end := false; !end; {
			switch l = <-c; l.value {
			case _NEWLINE, _EOF:
				end = true
			case _STRING:
				text = append(text, l.token)
			case _BLANK:
				continue
			}
		}

		err := rr.Data.ReadText(text)
		if err != nil {
			return nil, &ParseError{f, err.Error(), l}, ""
		}

		return rr, nil, ""
	}

	typeToparserFunc[rtype] = parserFunc{setPrivateRR, false}
}

// UnregisterPrivateRR removes defenitions required to support user RR type.
func UnregisterPrivateRR(rtype uint16) {
	rtypestr, ok := TypeToString[rtype]
	if ok {
		delete(typeToRR, rtype)
		delete(TypeToString, rtype)
		delete(typeToparserFunc, rtype)
		delete(StringToType, rtypestr)
	}
	return
}
