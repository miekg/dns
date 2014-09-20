package dns

import (
	"fmt"
	"strings"
)

// PrivateRdata is an interface to implement non-RFC dictated resource records. See also dns.PrivateRR, dns.NewPrivateRR and dns.DelPrivateRR
type PrivateRdata interface {
	String() string
	ParseTextSlice([]string) error
	WriteByteSlice([]byte) (int, error)
	ParseByteSlice([]byte) (int, error)
	PasteRdata(PrivateRdata) error
	RdataLen() int
}

// PrivateRR represents RR that uses PrivateRdata user-defined type. It mocks normal RRs and implements dns.RR interface.
type PrivateRR struct {
	Hdr  RR_Header
	Data PrivateRdata
}

// Panics if RR is not an instance of PrivateRR
func mkPrivateRR(rrtype uint16) *PrivateRR {
	rrfunc, ok := typeToRR[rrtype]
	if !ok {
		panic(fmt.Sprintf("dns: invalid operation with Private RR type %d", rrtype))
	}

	anyrr := rrfunc()
	switch rr := anyrr.(type) {
	case *PrivateRR:
		return rr
	}
	panic(fmt.Sprintf("dns: RR is not a PrivateRR, typeToRR[%d] generator returned %T", rrtype, anyrr))
}

func (r *PrivateRR) Header() *RR_Header { return &r.Hdr }
func (r *PrivateRR) String() string     { return r.Hdr.String() + r.Data.String() }

// Private len and copy parts to satisfy RR interface.
func (r *PrivateRR) len() int { return r.Hdr.len() + r.Data.RdataLen() }
func (r *PrivateRR) copy() RR {
	// make new RR like this:
	rr := mkPrivateRR(r.Hdr.Rrtype)
	newh := r.Hdr.copyHeader()
	rr.Hdr = *newh

	err := r.Data.PasteRdata(rr.Data)
	if err != nil {
		panic("dns: got value that could not be used to copy Private rdata")
	}

	return rr
}

// NewPrivateRR adds support for user-defined resource record type to internals of dns library. Requires
// string and numeric representation of RR type and generator function as argument.
func NewPrivateRR(rtypestr string, rtype uint16, generator func() PrivateRdata) {
	rtypestr = strings.ToUpper(rtypestr)

	typeToRR[rtype] = func() RR { return &PrivateRR{RR_Header{}, generator()} }
	TypeToString[rtype] = rtypestr
	StringToType[rtypestr] = rtype

	setPrivateRR := func(h RR_Header, c chan lex, o, f string) (RR, *ParseError, string) {
		rr := mkPrivateRR(h.Rrtype)
		rr.Hdr = h

		var l lex
		text := make([]string, 0, 2) // could be 0..N elements, median is probably 1
	FETCH:
		for {
			switch l = <-c; l.value {
			case _NEWLINE, _EOF:
				break FETCH
			case _STRING:
				text = append(text, l.token)
			}
		}

		err := rr.Data.ParseTextSlice(text)
		if err != nil {
			return nil, &ParseError{f, err.Error(), l}, ""
		}

		return rr, nil, ""
	}

	typeToparserFunc[rtype] = parserFunc{setPrivateRR, false}
}

// DelPrivateRR removes defenitions required to support user RR type.
func DelPrivateRR(rtype uint16) {
	rtypestr, ok := TypeToString[rtype]
	if ok {
		delete(typeToRR, rtype)
		delete(TypeToString, rtype)
		delete(typeToparserFunc, rtype)
		delete(StringToType, rtypestr)
	}
	return
}
