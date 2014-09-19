package dns

type CustomRData interface {
	String() string
	ReadText([]string) error
	Write([]byte) (int, error)
	Read([]byte) (int, error)
	CopyTo(CustomRData) error
}

// CopyTo needs to be here to avoid write/read pass that would require make([]byte, xxxxxx)

type CustomRR struct {
	Hdr  RR_Header
	Data CustomRData
}

func (r *CustomRR) Header() *RR_Header { return &r.Hdr }
func (r *CustomRR) String() string     { return r.Hdr.String() + r.Data.String() }
func (r *CustomRR) copy() RR {
	// make new RR like this:
	rrfunc, ok := typeToRR[r.Hdr.Rrtype]
	if !ok {
		panic("dns: invalid operation with custom RR " + r.Hdr.String())
	}
	rr := rrfunc()
	r.Header().CopyTo(rr)

	rrcust, ok := rr.(*CustomRR)
	if !ok {
		panic("dns: custom RR generator returned wrong interface value")
	}

	err := r.Data.CopyTo(rrcust.Data)
	if err != nil {
		panic("dns: got value that could not be used to copy custom rdata")
	}

	return rr
}

func (r *CustomRR) len() int { panic("TODO: WHERE THIS IS USED?"); return 0 }

func RegisterCustomRR(rtypestr string, rtype uint16, generator func() CustomRData) {
	typeToRR[rtype] = func() RR { return &CustomRR{RR_Header{}, generator()} }
	TypeToString[rtype] = rtypestr
	StringToType[rtypestr] = rtype

	setCustomRR := func(h RR_Header, c chan lex, o, f string) (RR, *ParseError, string) {
		rrfunc := typeToRR[h.Rrtype]
		rr, ok := rrfunc().(*CustomRR)
		if !ok {
			panic("dns: invalid handler registered for custom RR " + rtypestr)
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

	typeToparserFunc[rtype] = parserFunc{setCustomRR, false}
}

func UnregisterCustomRR(rtype uint16) {
	rtypestr, ok := TypeToString[rtype]
	if ok {
		delete(typeToRR, rtype)
		delete(TypeToString, rtype)
		delete(typeToparserFunc, rtype)
		delete(StringToType, rtypestr)
	}
	return
}
