package dns

import (
	"encoding/base64"
	"net"
	"strconv"
	"strings"
)

// Parse the rdata of each rrtype.
// All data from the channel c is either _STRING or _BLANK.
// After the rdata there may come 1 _BLANK and then a _NEWLINE
// or immediately a _NEWLINE. If this is not the case we flag
// an *ParseError: garbage after rdata.
func setRR(h RR_Header, c chan lex, o, f string) (RR, *ParseError) {
	var r RR
	e := new(ParseError)
	switch h.Rrtype {
	case TypeA:
		r, e = setA(h, c, f)
		goto Slurp
	case TypeAAAA:
		r, e = setAAAA(h, c, f)
		goto Slurp
	case TypeHINFO:
		r, e = setHINFO(h, c, f)
		goto Slurp
	case TypeNS:
		r, e = setNS(h, c, o, f)
		goto Slurp
	case TypePTR:
		r, e = setPTR(h, c, o, f)
		goto Slurp
	case TypeMF:
		r, e = setMF(h, c, o, f)
		goto Slurp
	case TypeMD:
		r, e = setMD(h, c, o, f)
		goto Slurp
	case TypeMG:
		r, e = setMG(h, c, o, f)
		goto Slurp
	case TypeRT:
		r, e = setRT(h, c, o, f)
		goto Slurp
	case TypeAFSDB:
		r, e = setAFSDB(h, c, o, f)
		goto Slurp
	case TypeMX:
		r, e = setMX(h, c, o, f)
		goto Slurp
	case TypeCNAME:
		r, e = setCNAME(h, c, o, f)
		goto Slurp
	case TypeDNAME:
		r, e = setDNAME(h, c, o, f)
		goto Slurp
	case TypeSOA:
		r, e = setSOA(h, c, o, f)
		goto Slurp
	case TypeSSHFP:
		r, e = setSSHFP(h, c, f)
		goto Slurp
	case TypeSRV:
		r, e = setSRV(h, c, o, f)
		goto Slurp
	case TypeNAPTR:
		r, e = setNAPTR(h, c, o, f)
		goto Slurp
	case TypeTALINK:
		r, e = setTALINK(h, c, o, f)
		goto Slurp
	case TypeRP:
		r, e = setRP(h, c, o, f)
		goto Slurp
	case TypeMR:
		r, e = setMR(h, c, o, f)
		goto Slurp
	case TypeMB:
		r, e = setMB(h, c, o, f)
		goto Slurp
	case TypeKX:
		r, e = setKX(h, c, o, f)
		goto Slurp
	// These types have a variable ending: either chunks of txt or chunks/base64 or hex.
	// They need to search for the end of the RR themselves, hence they look for the ending
	// newline. Thus there is no need to slurp the remainder, because there is none.
	case TypeDNSKEY:
		return setDNSKEY(h, c, f)
	case TypeRRSIG:
		return setRRSIG(h, c, o, f)
	case TypeNSEC:
		return setNSEC(h, c, o, f)
	case TypeNSEC3:
		return setNSEC3(h, c, o, f)
	case TypeNSEC3PARAM:
		return setNSEC3PARAM(h, c, f)
	case TypeWKS:
		return setWKS(h, c, f)
	case TypeDS:
		return setDS(h, c, f)
	case TypeDLV:
		return setDLV(h, c, f)
	case TypeTA:
		return setTA(h, c, f)
	case TypeTLSA:
		return setTLSA(h, c, f)
	case TypeTXT:
		return setTXT(h, c, f)
	case TypeHIP:
		return setHIP(h, c, o, f)
	case TypeSPF:
		return setSPF(h, c, f)
	case TypeDHCID:
		return setDHCID(h, c, f)
	case TypeIPSECKEY:
		return setIPSECKEY(h, c, o, f)
	case TypeLOC:
		r, e = setLOC(h, c, f)
	default:
		// RFC3957 RR (Unknown RR handling)
		return setRFC3597(h, c, f)
	}
Slurp:
	if e != nil {
		return nil, e
	}
	if se := slurpRemainder(c, f); se != nil {
		return nil, se
	}
	return r, e
}

func setA(h RR_Header, c chan lex, f string) (RR, *ParseError) {
	rr := new(RR_A)
	rr.Hdr = h

	l := <-c
	rr.A = net.ParseIP(l.token)
	if rr.A == nil {
		return nil, &ParseError{f, "bad A A", l}
	}
	return rr, nil
}

func setAAAA(h RR_Header, c chan lex, f string) (RR, *ParseError) {
	rr := new(RR_AAAA)
	rr.Hdr = h

	l := <-c
	rr.AAAA = net.ParseIP(l.token)
	if rr.AAAA == nil {
		return nil, &ParseError{f, "bad AAAA AAAA", l}
	}
	return rr, nil
}

func setNS(h RR_Header, c chan lex, o, f string) (RR, *ParseError) {
	rr := new(RR_NS)
	rr.Hdr = h

	l := <-c
	rr.Ns = l.token
	_, ld, ok := IsDomainName(l.token)
	if !ok {
		return nil, &ParseError{f, "bad NS Ns", l}
	}
	if rr.Ns[ld-1] != '.' {
		rr.Ns = appendOrigin(rr.Ns, o)
	}
	return rr, nil
}

func setPTR(h RR_Header, c chan lex, o, f string) (RR, *ParseError) {
	rr := new(RR_PTR)
	rr.Hdr = h

	l := <-c
	rr.Ptr = l.token
	_, ld, ok := IsDomainName(l.token)
	if !ok {
		return nil, &ParseError{f, "bad PTR Ptr", l}
	}
	if rr.Ptr[ld-1] != '.' {
		rr.Ptr = appendOrigin(rr.Ptr, o)
	}
	return rr, nil
}

func setRP(h RR_Header, c chan lex, o, f string) (RR, *ParseError) {
	rr := new(RR_RP)
	rr.Hdr = h

	l := <-c
	rr.Mbox = l.token
	_, ld, ok := IsDomainName(l.token)
	if !ok {
		return nil, &ParseError{f, "bad RP Mbox", l}
	}
	if rr.Mbox[ld-1] != '.' {
		rr.Mbox = appendOrigin(rr.Mbox, o)
	}
	<-c // _BLANK
	l = <-c
	rr.Txt = l.token
	_, ld, ok = IsDomainName(l.token)
	if !ok {
		return nil, &ParseError{f, "bad RP Txt", l}
	}
	if rr.Txt[ld-1] != '.' {
		rr.Txt = appendOrigin(rr.Txt, o)
	}

	return rr, nil
}

func setMR(h RR_Header, c chan lex, o, f string) (RR, *ParseError) {
	rr := new(RR_MR)
	rr.Hdr = h

	l := <-c
	rr.Mr = l.token
	_, ld, ok := IsDomainName(l.token)
	if !ok {
		return nil, &ParseError{f, "bad MR Mr", l}
	}
	if rr.Mr[ld-1] != '.' {
		rr.Mr = appendOrigin(rr.Mr, o)
	}
	return rr, nil
}

func setMB(h RR_Header, c chan lex, o, f string) (RR, *ParseError) {
	rr := new(RR_MB)
	rr.Hdr = h

	l := <-c
	rr.Mb = l.token
	_, ld, ok := IsDomainName(l.token)
	if !ok {
		return nil, &ParseError{f, "bad MB Mb", l}
	}
	if rr.Mb[ld-1] != '.' {
		rr.Mb = appendOrigin(rr.Mb, o)
	}
	return rr, nil
}

func setMG(h RR_Header, c chan lex, o, f string) (RR, *ParseError) {
	rr := new(RR_MG)
	rr.Hdr = h

	l := <-c
	rr.Mg = l.token
	_, ld, ok := IsDomainName(l.token)
	if !ok {
		return nil, &ParseError{f, "bad MG Mg", l}
	}
	if rr.Mg[ld-1] != '.' {
		rr.Mg = appendOrigin(rr.Mg, o)
	}
	return rr, nil
}

func setHINFO(h RR_Header, c chan lex, f string) (RR, *ParseError) {
	rr := new(RR_HINFO)
	rr.Hdr = h

	l := <-c
	rr.Cpu = l.token
	<-c     // _BLANK
	l = <-c // _STRING
	rr.Os = l.token

	return rr, nil
}

func setMINFO(h RR_Header, c chan lex, o, f string) (RR, *ParseError) {
	rr := new(RR_MINFO)
	rr.Hdr = h

	l := <-c
	rr.Rmail = l.token
	_, ld, ok := IsDomainName(l.token)
	if !ok {
		return nil, &ParseError{f, "bad MINFO Rmail", l}
	}
	if rr.Rmail[ld-1] != '.' {
		rr.Rmail = appendOrigin(rr.Rmail, o)
	}
	l = <-c
	rr.Email = l.token
	_, ld, ok = IsDomainName(l.token)
	if !ok {
		return nil, &ParseError{f, "bad MINFO Email", l}
	}
	if rr.Email[ld-1] != '.' {
		rr.Email = appendOrigin(rr.Email, o)
	}
	return rr, nil
}

func setMF(h RR_Header, c chan lex, o, f string) (RR, *ParseError) {
	rr := new(RR_MF)
	rr.Hdr = h

	l := <-c
	rr.Mf = l.token
	_, ld, ok := IsDomainName(l.token)
	if !ok {
		return nil, &ParseError{f, "bad MF Mf", l}
	}
	if rr.Mf[ld-1] != '.' {
		rr.Mf = appendOrigin(rr.Mf, o)
	}
	return rr, nil
}

func setMD(h RR_Header, c chan lex, o, f string) (RR, *ParseError) {
	rr := new(RR_MD)
	rr.Hdr = h

	l := <-c
	rr.Md = l.token
	_, ld, ok := IsDomainName(l.token)
	if !ok {
		return nil, &ParseError{f, "bad MD Md", l}
	}
	if rr.Md[ld-1] != '.' {
		rr.Md = appendOrigin(rr.Md, o)
	}
	return rr, nil
}

func setMX(h RR_Header, c chan lex, o, f string) (RR, *ParseError) {
	rr := new(RR_MX)
	rr.Hdr = h

	l := <-c
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{f, "bad MX Pref", l}
	} else {
		rr.Pref = uint16(i)
	}
	<-c     // _BLANK
	l = <-c // _STRING
	rr.Mx = l.token
	_, ld, ok := IsDomainName(l.token)
	if !ok {
		return nil, &ParseError{f, "bad MX Mx", l}
	}
	if rr.Mx[ld-1] != '.' {
		rr.Mx = appendOrigin(rr.Mx, o)
	}
	return rr, nil
}

func setRT(h RR_Header, c chan lex, o, f string) (RR, *ParseError) {
	rr := new(RR_RT)
	rr.Hdr = h

	l := <-c
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{f, "bad RT Preference", l}
	} else {
		rr.Preference = uint16(i)
	}
	<-c     // _BLANK
	l = <-c // _STRING
	rr.Host = l.token
	_, ld, ok := IsDomainName(l.token)
	if !ok {
		return nil, &ParseError{f, "bad RT Host", l}
	}
	if rr.Host[ld-1] != '.' {
		rr.Host = appendOrigin(rr.Host, o)
	}
	return rr, nil
}

func setAFSDB(h RR_Header, c chan lex, o, f string) (RR, *ParseError) {
	rr := new(RR_AFSDB)
	rr.Hdr = h

	l := <-c
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{f, "bad AFSDB Subtype", l}
	} else {
		rr.Subtype = uint16(i)
	}
	<-c     // _BLANK
	l = <-c // _STRING
	rr.Hostname = l.token
	_, ld, ok := IsDomainName(l.token)
	if !ok {
		return nil, &ParseError{f, "bad AFSDB Hostname", l}
	}
	if rr.Hostname[ld-1] != '.' {
		rr.Hostname = appendOrigin(rr.Hostname, o)
	}
	return rr, nil
}

func setKX(h RR_Header, c chan lex, o, f string) (RR, *ParseError) {
	rr := new(RR_KX)
	rr.Hdr = h

	l := <-c
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{f, "bad KX Pref", l}
	} else {
		rr.Pref = uint16(i)
	}
	<-c     // _BLANK
	l = <-c // _STRING
	rr.Exchanger = l.token
	_, ld, ok := IsDomainName(l.token)
	if !ok {
		return nil, &ParseError{f, "bad KX Exchanger", l}
	}
	if rr.Exchanger[ld-1] != '.' {
		rr.Exchanger = appendOrigin(rr.Exchanger, o)
	}
	return rr, nil
}

func setCNAME(h RR_Header, c chan lex, o, f string) (RR, *ParseError) {
	rr := new(RR_CNAME)
	rr.Hdr = h

	l := <-c
	rr.Target = l.token
	_, ld, ok := IsDomainName(l.token)
	if !ok {
		return nil, &ParseError{f, "bad CNAME Target", l}
	}
	if rr.Target[ld-1] != '.' {
		rr.Target = appendOrigin(rr.Target, o)
	}
	return rr, nil
}

func setDNAME(h RR_Header, c chan lex, o, f string) (RR, *ParseError) {
	rr := new(RR_DNAME)
	rr.Hdr = h

	l := <-c
	rr.Target = l.token
	_, ld, ok := IsDomainName(l.token)
	if !ok {
		return nil, &ParseError{f, "bad CNAME Target", l}
	}
	if rr.Target[ld-1] != '.' {
		rr.Target = appendOrigin(rr.Target, o)
	}
	return rr, nil
}

func setSOA(h RR_Header, c chan lex, o, f string) (RR, *ParseError) {
	rr := new(RR_SOA)
	rr.Hdr = h

	l := <-c
	rr.Ns = l.token
	<-c // _BLANK
	_, ld, ok := IsDomainName(l.token)
	if !ok {
		return nil, &ParseError{f, "bad SOA Ns", l}
	}
	if rr.Ns[ld-1] != '.' {
		rr.Ns = appendOrigin(rr.Ns, o)
	}

	l = <-c
	rr.Mbox = l.token
	_, ld, ok = IsDomainName(l.token)
	if !ok {
		return nil, &ParseError{f, "bad SOA Mbox", l}
	}
	if rr.Mbox[ld-1] != '.' {
		rr.Mbox = appendOrigin(rr.Mbox, o)
	}
	<-c // _BLANK

	var v uint32
	for i := 0; i < 5; i++ {
		l = <-c
		if j, e := strconv.Atoi(l.token); e != nil {
			if i == 0 {
				// Serial should be a number
				return nil, &ParseError{f, "bad SOA zone parameter", l}
			}
			if v, ok = stringToTtl(l.token); !ok {
				return nil, &ParseError{f, "bad SOA zone parameter", l}

			}
		} else {
			v = uint32(j)
		}
		switch i {
		case 0:
			rr.Serial = v
			<-c // _BLANK
		case 1:
			rr.Refresh = v
			<-c // _BLANK
		case 2:
			rr.Retry = v
			<-c // _BLANK
		case 3:
			rr.Expire = v
			<-c // _BLANK
		case 4:
			rr.Minttl = v
		}
	}
	return rr, nil
}

func setSRV(h RR_Header, c chan lex, o, f string) (RR, *ParseError) {
	rr := new(RR_SRV)
	rr.Hdr = h

	l := <-c
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{f, "bad SRV Priority", l}
	} else {
		rr.Priority = uint16(i)
	}
	<-c     // _BLANK
	l = <-c // _STRING
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{f, "bad SRV Weight", l}
	} else {
		rr.Weight = uint16(i)
	}
	<-c     // _BLANK
	l = <-c // _STRING
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{f, "bad SRV Port", l}
	} else {
		rr.Port = uint16(i)
	}
	<-c     // _BLANK
	l = <-c // _STRING
	rr.Target = l.token
	_, ld, ok := IsDomainName(l.token)
	if !ok {
		return nil, &ParseError{f, "bad SRV Target", l}
	}
	if rr.Target[ld-1] != '.' {
		rr.Target = appendOrigin(rr.Target, o)
	}
	return rr, nil
}

func setNAPTR(h RR_Header, c chan lex, o, f string) (RR, *ParseError) {
	rr := new(RR_NAPTR)
	rr.Hdr = h

	l := <-c
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{f, "bad NAPTR Order", l}
	} else {
		rr.Order = uint16(i)
	}
	<-c     // _BLANK
	l = <-c // _STRING
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{f, "bad NAPTR Preference", l}
	} else {
		rr.Pref = uint16(i)
	}
	// Flags
	<-c     // _BLANK
	l = <-c // _QUOTE
	if l.value != _QUOTE {
		return nil, &ParseError{f, "bad NAPTR Flags", l}
	}
	l = <-c // Either String or Quote
	if l.value == _STRING {
		rr.Flags = l.token
		l = <-c // _QUOTE
		if l.value != _QUOTE {
			return nil, &ParseError{f, "bad NAPTR Flags", l}
		}
	} else if l.value == _QUOTE {
		rr.Flags = ""
	} else {
		return nil, &ParseError{f, "bad NAPTR Flags", l}
	}

	// Service
	<-c     // _BLANK
	l = <-c // _QUOTE
	if l.value != _QUOTE {
		return nil, &ParseError{f, "bad NAPTR Service", l}
	}
	l = <-c // Either String or Quote
	if l.value == _STRING {
		rr.Service = l.token
		l = <-c // _QUOTE
		if l.value != _QUOTE {
			return nil, &ParseError{f, "bad NAPTR Service", l}
		}
	} else if l.value == _QUOTE {
		rr.Service = ""
	} else {
		return nil, &ParseError{f, "bad NAPTR Service", l}
	}

	// Regexp
	<-c     // _BLANK
	l = <-c // _QUOTE
	if l.value != _QUOTE {
		return nil, &ParseError{f, "bad NAPTR Regexp", l}
	}
	l = <-c // Either String or Quote
	if l.value == _STRING {
		rr.Regexp = l.token
		l = <-c // _QUOTE
		if l.value != _QUOTE {
			return nil, &ParseError{f, "bad NAPTR Regexp", l}
		}
	} else if l.value == _QUOTE {
		rr.Regexp = ""
	} else {
		return nil, &ParseError{f, "bad NAPTR Regexp", l}
	}
	// After quote no space??
	<-c     // _BLANK
	l = <-c // _STRING
	rr.Replacement = l.token
	_, ld, ok := IsDomainName(l.token)
	if !ok {
		return nil, &ParseError{f, "bad NAPTR Replacement", l}
	}
	if rr.Replacement[ld-1] != '.' {
		rr.Replacement = appendOrigin(rr.Replacement, o)
	}
	return rr, nil
}

func setTALINK(h RR_Header, c chan lex, o, f string) (RR, *ParseError) {
	rr := new(RR_TALINK)
	rr.Hdr = h

	l := <-c
	rr.PreviousName = l.token
	_, ld, ok := IsDomainName(l.token)
	if !ok {
		return nil, &ParseError{f, "bad TALINK PreviousName", l}
	}
	if rr.PreviousName[ld-1] != '.' {
		rr.PreviousName = appendOrigin(rr.PreviousName, o)
	}
	<-c // _BLANK
	l = <-c
	rr.NextName = l.token
	_, ld, ok = IsDomainName(l.token)
	if !ok {
		return nil, &ParseError{f, "bad TALINK NextName", l}
	}
	if rr.NextName[ld-1] != '.' {
		rr.NextName = appendOrigin(rr.NextName, o)
	}
	return rr, nil
}

func setLOC(h RR_Header, c chan lex, f string) (RR, *ParseError) {
	rr := new(RR_LOC)
	rr.Hdr = h
	// Non zero defaults for LOC record, see RFC 1876, Section 3.
	rr.HorizPre = 165 // 10000
	rr.VertPre = 162  // 10
	rr.Size = 18      // 1
	ok := false
	// North
	l := <-c
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{f, "bad LOC Latitude", l}
	} else {
		rr.Latitude = 1000 * 60 * 60 * uint32(i)
	}
	<-c // _BLANK
	// Either number, 'N' or 'S'
	l = <-c
	if rr.Latitude, ok = locCheckNorth(l.token, rr.Latitude); ok {
		goto East
	}
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{f, "bad LOC Latitude minutes", l}
	} else {
		rr.Latitude += 1000 * 60 * uint32(i)
	}
	<-c // _BLANK
	l = <-c
	if i, e := strconv.ParseFloat(l.token, 32); e != nil {
		return nil, &ParseError{f, "bad LOC Latitude seconds", l}
	} else {
		rr.Latitude += uint32(1000 * i)
	}
	<-c // _BLANK
	// Either number, 'N' or 'S'
	l = <-c
	if rr.Latitude, ok = locCheckNorth(l.token, rr.Latitude); ok {
		goto East
	}
	// If still alive, flag an error
	return nil, &ParseError{f, "bad LOC Latitude North/South", l}

East:
	// East
	<-c // _BLANK
	l = <-c
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{f, "bad LOC Longitude", l}
	} else {
		rr.Longitude = 1000 * 60 * 60 * uint32(i)
	}
	<-c // _BLANK
	// Either number, 'E' or 'W'
	l = <-c
	if rr.Longitude, ok = locCheckEast(l.token, rr.Longitude); ok {
		goto Altitude
	}
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{f, "bad LOC Longitude minutes", l}
	} else {
		rr.Longitude += 1000 * 60 * uint32(i)
	}
	<-c // _BLANK
	l = <-c
	if i, e := strconv.ParseFloat(l.token, 32); e != nil {
		return nil, &ParseError{f, "bad LOC Longitude seconds", l}
	} else {
		rr.Longitude += uint32(1000 * i)
	}
	<-c // _BLANK
	// Either number, 'E' or 'W'
	l = <-c
	if rr.Longitude, ok = locCheckEast(l.token, rr.Longitude); ok {
		goto Altitude
	}
	// If still alive, flag an error
	return nil, &ParseError{f, "bad LOC Longitude East/West", l}

Altitude:
	<-c // _BLANK
	l = <-c
	if l.token[len(l.token)-1] == 'M' || l.token[len(l.token)-1] == 'm' {
		l.token = l.token[0 : len(l.token)-1]
	}
	if i, e := strconv.ParseFloat(l.token, 32); e != nil {
		return nil, &ParseError{f, "bad LOC Altitude", l}
	} else {
		rr.Altitude = uint32(i*100.0 + 10000000.0 + 0.5)
	}

	// And now optionally the other values
	l = <-c
	count := 0
	for l.value != _NEWLINE && l.value != _EOF {
		switch l.value {
		case _STRING:
			switch count {
			case 0: // Size
				if e, m, ok := stringToCm(l.token); !ok {
					return nil, &ParseError{f, "bad LOC Size", l}
				} else {
					rr.Size = (e & 0x0f) | (m << 4 & 0xf0)
				}
			case 1: // HorizPre
				if e, m, ok := stringToCm(l.token); !ok {
					return nil, &ParseError{f, "bad LOC HorizPre", l}
				} else {
					rr.HorizPre = (e & 0x0f) | (m << 4 & 0xf0)
				}
			case 2: // VertPre
				if e, m, ok := stringToCm(l.token); !ok {
					return nil, &ParseError{f, "bad LOC VertPre", l}
				} else {
					rr.VertPre = (e & 0x0f) | (m << 4 & 0xf0)
				}
			}
			count++
		case _BLANK:
			// Ok
		default:
			return nil, &ParseError{f, "bad LOC Size, HorizPre or VertPre", l}
		}
		l = <-c
	}
	return rr, nil
}

func setHIP(h RR_Header, c chan lex, o, f string) (RR, *ParseError) {
	rr := new(RR_HIP)
	rr.Hdr = h

	// HitLength is not represented
	l := <-c
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{f, "bad HIP PublicKeyAlgorithm", l}
	} else {
		rr.PublicKeyAlgorithm = uint8(i)
	}
	<-c              // _BLANK
	l = <-c          // _STRING
	rr.Hit = l.token // This can not contain spaces, see RFC 5205 Section 6.
	rr.HitLength = uint8(len(rr.Hit)) / 2

	<-c                    // _BLANK
	l = <-c                // _STRING
	rr.PublicKey = l.token // This cannot contain spaces
	rr.PublicKeyLength = uint16(base64.StdEncoding.DecodedLen(len(rr.PublicKey)))

	// RendezvousServers (if any)
	l = <-c
	xs := make([]string, 0)
	for l.value != _NEWLINE && l.value != _EOF {
		switch l.value {
		case _STRING:
			_, ld, ok := IsDomainName(l.token)
			if !ok {
				return nil, &ParseError{f, "bad HIP RendezvousServers", l}
			}
			if l.token[ld-1] != '.' {
				l.token = appendOrigin(l.token, o)
			}
			xs = append(xs, l.token)
		case _BLANK:
			// Ok
		default:
			return nil, &ParseError{f, "bad HIP RendezvousServers", l}
		}
		l = <-c
	}
	rr.RendezvousServers = xs
	return rr, nil
}

func setCERT(h RR_Header, c chan lex, o, f string) (RR, *ParseError) {
	rr := new(RR_CERT)
	rr.Hdr = h

	l := <-c
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{f, "bad CERT Type", l}
	} else {
		rr.Type = uint16(i)
	}
	<-c     // _BLANK
	l = <-c // _STRING
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{f, "bad NAPTR KeyTag", l}
	} else {
		rr.KeyTag = uint16(i)
	}
	<-c     // _BLANK
	l = <-c // _STRING
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{f, "bad NAPTR Algorithm", l}
	} else {
		rr.Algorithm = uint8(i)
	}
	// Get the remaining data until we see a NEWLINE
	l = <-c
	s := ""
	for l.value != _NEWLINE && l.value != _EOF {
		switch l.value {
		case _STRING:
			s += l.token
		case _BLANK:
			// Ok
		default:
			return nil, &ParseError{f, "bad NAPTR Certificate", l}
		}
		l = <-c
	}
	rr.Certificate = s

	return rr, nil
}

func setRRSIG(h RR_Header, c chan lex, o, f string) (RR, *ParseError) {
	rr := new(RR_RRSIG)
	rr.Hdr = h
	l := <-c
	if t, ok := Str_rr[strings.ToUpper(l.token)]; !ok {
		return nil, &ParseError{f, "bad RRSIG Typecovered", l}
	} else {
		rr.TypeCovered = t
	}
	<-c // _BLANK
	l = <-c
	if i, err := strconv.Atoi(l.token); err != nil {
		return nil, &ParseError{f, "bad RRSIG Algorithm", l}
	} else {
		rr.Algorithm = uint8(i)
	}
	<-c // _BLANK
	l = <-c
	if i, err := strconv.Atoi(l.token); err != nil {
		return nil, &ParseError{f, "bad RRSIG Labels", l}
	} else {
		rr.Labels = uint8(i)
	}
	<-c // _BLANK
	l = <-c
	if i, err := strconv.Atoi(l.token); err != nil {
		return nil, &ParseError{f, "bad RRSIG OrigTtl", l}
	} else {
		rr.OrigTtl = uint32(i)
	}
	<-c // _BLANK
	l = <-c
	if i, err := StringToTime(l.token); err != nil {
		return nil, &ParseError{f, "bad RRSIG Expiration", l}
	} else {
		rr.Expiration = i
	}
	<-c // _BLANK
	l = <-c
	if i, err := StringToTime(l.token); err != nil {
		return nil, &ParseError{f, "bad RRSIG Inception", l}
	} else {
		rr.Inception = i
	}
	<-c // _BLANK
	l = <-c
	if i, err := strconv.Atoi(l.token); err != nil {
		return nil, &ParseError{f, "bad RRSIG KeyTag", l}
	} else {
		rr.KeyTag = uint16(i)
	}
	<-c // _BLANK
	l = <-c
	rr.SignerName = l.token
	_, ld, ok := IsDomainName(l.token)
	if !ok {
		return nil, &ParseError{f, "bad RRSIG SignerName", l}
	}
	if rr.SignerName[ld-1] != '.' {
		rr.SignerName = appendOrigin(rr.SignerName, o)
	}
	// Get the remaining data until we see a NEWLINE
	l = <-c
	s := ""
	for l.value != _NEWLINE && l.value != _EOF {
		switch l.value {
		case _STRING:
			s += l.token
		case _BLANK:
			// Ok
		default:
			return nil, &ParseError{f, "bad RRSIG Signature", l}
		}
		l = <-c
	}
	rr.Signature = s
	return rr, nil
}

func setNSEC(h RR_Header, c chan lex, o, f string) (RR, *ParseError) {
	rr := new(RR_NSEC)
	rr.Hdr = h

	l := <-c
	rr.NextDomain = l.token
	_, ld, ok := IsDomainName(l.token)
	if !ok {
		return nil, &ParseError{f, "bad NSEC NextDomain", l}
	}
	if rr.NextDomain[ld-1] != '.' {
		rr.NextDomain = appendOrigin(rr.NextDomain, o)
	}

	rr.TypeBitMap = make([]uint16, 0)
	var k uint16
	l = <-c
	for l.value != _NEWLINE && l.value != _EOF {
		switch l.value {
		case _BLANK:
			// Ok
		case _STRING:
			if k, ok = Str_rr[strings.ToUpper(l.token)]; !ok {
				if k, ok = typeToInt(l.token); !ok {
					return nil, &ParseError{f, "bad NSEC TypeBitMap", l}
				}
			}
			rr.TypeBitMap = append(rr.TypeBitMap, k)
		default:
			return nil, &ParseError{f, "bad NSEC TypeBitMap", l}
		}
		l = <-c
	}
	return rr, nil
}

func setNSEC3(h RR_Header, c chan lex, o, f string) (RR, *ParseError) {
	rr := new(RR_NSEC3)
	rr.Hdr = h

	l := <-c
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{f, "bad NSEC3 Hash", l}
	} else {
		rr.Hash = uint8(i)
	}
	<-c // _BLANK
	l = <-c
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{f, "bad NSEC3 Flags", l}
	} else {
		rr.Flags = uint8(i)
	}
	<-c // _BLANK
	l = <-c
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{f, "bad NSEC3 Iterations", l}
	} else {
		rr.Iterations = uint16(i)
	}
	<-c
	l = <-c
	if len(l.token) == 0 {
		return nil, &ParseError{f, "bad NSEC3 Salt", l}
	}
	rr.SaltLength = uint8(len(l.token)) / 2
	rr.Salt = l.token

	<-c
	l = <-c
	rr.HashLength = 20 // Fix for NSEC3 (sha1 160 bits)
	rr.NextDomain = l.token

	rr.TypeBitMap = make([]uint16, 0)
	var (
		k  uint16
		ok bool
	)
	l = <-c
	for l.value != _NEWLINE && l.value != _EOF {
		switch l.value {
		case _BLANK:
			// Ok
		case _STRING:
			if k, ok = Str_rr[strings.ToUpper(l.token)]; !ok {
				if k, ok = typeToInt(l.token); !ok {
					return nil, &ParseError{f, "bad NSEC3 TypeBitMap", l}
				}
			}
			rr.TypeBitMap = append(rr.TypeBitMap, k)
		default:
			return nil, &ParseError{f, "bad NSEC3 TypeBitMap", l}
		}
		l = <-c
	}
	return rr, nil
}

func setNSEC3PARAM(h RR_Header, c chan lex, f string) (RR, *ParseError) {
	rr := new(RR_NSEC3PARAM)
	rr.Hdr = h

	l := <-c
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{f, "bad NSEC3PARAM Hash", l}
	} else {
		rr.Hash = uint8(i)
	}
	<-c // _BLANK
	l = <-c
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{f, "bad NSEC3PARAM Flags", l}
	} else {
		rr.Flags = uint8(i)
	}
	<-c // _BLANK
	l = <-c
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{f, "bad NSEC3PARAM Iterations", l}
	} else {
		rr.Iterations = uint16(i)
	}
	<-c
	l = <-c
	rr.SaltLength = uint8(len(l.token))
	rr.Salt = l.token
	return rr, nil
}

func setWKS(h RR_Header, c chan lex, f string) (RR, *ParseError) {
	rr := new(RR_WKS)
	rr.Hdr = h

	l := <-c
	rr.Address = net.ParseIP(l.token)
	if rr.Address == nil {
		return nil, &ParseError{f, "bad WKS Adress", l}
	}

	<-c // _BLANK
	l = <-c
	proto := "tcp"
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{f, "bad WKS Protocol", l}
	} else {
		rr.Protocol = uint8(i)
		switch rr.Protocol {
		case 17:
			proto = "udp"
		case 6:
			proto = "tcp"
		default:
			return nil, &ParseError{f, "bad WKS Protocol", l}
		}
	}

	<-c
	l = <-c
	rr.BitMap = make([]uint16, 0)
	var (
		k   int
		err error
	)
	for l.value != _NEWLINE && l.value != _EOF {
		switch l.value {
		case _BLANK:
			// Ok
		case _STRING:
			if k, err = net.LookupPort(proto, l.token); err != nil {
				if i, e := strconv.Atoi(l.token); e != nil { // If a number use that
					rr.BitMap = append(rr.BitMap, uint16(i))
				} else {
					return nil, &ParseError{f, "bad WKS BitMap", l}
				}
			}
			rr.BitMap = append(rr.BitMap, uint16(k))
		default:
			return nil, &ParseError{f, "bad WKS BitMap", l}
		}
		l = <-c
	}
	return rr, nil
}

func setSSHFP(h RR_Header, c chan lex, f string) (RR, *ParseError) {
	rr := new(RR_SSHFP)
	rr.Hdr = h

	l := <-c
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{f, "bad SSHFP Algorithm", l}
	} else {
		rr.Algorithm = uint8(i)
	}
	<-c // _BLANK
	l = <-c
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{f, "bad SSHFP Type", l}
	} else {
		rr.Type = uint8(i)
	}
	<-c // _BLANK
	l = <-c
	rr.FingerPrint = l.token
	return rr, nil
}

func setDNSKEY(h RR_Header, c chan lex, f string) (RR, *ParseError) {
	rr := new(RR_DNSKEY)
	rr.Hdr = h

	l := <-c
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{f, "bad DNSKEY Flags", l}
	} else {
		rr.Flags = uint16(i)
	}
	<-c     // _BLANK
	l = <-c // _STRING
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{f, "bad DNSKEY Protocol", l}
	} else {
		rr.Protocol = uint8(i)
	}
	<-c     // _BLANK
	l = <-c // _STRING
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{f, "bad DNSKEY Algorithm", l}
	} else {
		rr.Algorithm = uint8(i)
	}
	l = <-c
	var s string
	for l.value != _NEWLINE && l.value != _EOF {
		switch l.value {
		case _STRING:
			s += l.token
		case _BLANK:
			// Ok
		default:
			return nil, &ParseError{f, "bad DNSKEY PublicKey", l}
		}
		l = <-c
	}
	rr.PublicKey = s
	return rr, nil
}

func setDS(h RR_Header, c chan lex, f string) (RR, *ParseError) {
	rr := new(RR_DS)
	rr.Hdr = h
	l := <-c
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{f, "bad DS KeyTag", l}
	} else {
		rr.KeyTag = uint16(i)
	}
	<-c // _BLANK
	l = <-c
	if i, e := strconv.Atoi(l.token); e != nil {
		if i, ok := Str_alg[strings.ToUpper(l.token)]; !ok {
			return nil, &ParseError{f, "bad DS Algorithm", l}
		} else {
			rr.Algorithm = i
		}
	} else {
		rr.Algorithm = uint8(i)
	}
	<-c // _BLANK
	l = <-c
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{f, "bad DS DigestType", l}
	} else {
		rr.DigestType = uint8(i)
	}
	// There can be spaces here...
	l = <-c
	s := ""
	for l.value != _NEWLINE && l.value != _EOF {
		switch l.value {
		case _STRING:
			s += l.token
		case _BLANK:
			// Ok
		default:
			return nil, &ParseError{f, "bad DS Digest", l}
		}
		l = <-c
	}
	rr.Digest = s
	return rr, nil
}

func setDLV(h RR_Header, c chan lex, f string) (RR, *ParseError) {
	rr := new(RR_DLV)
	rr.Hdr = h
	l := <-c
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{f, "bad DLV KeyTag", l}
	} else {
		rr.KeyTag = uint16(i)
	}
	<-c // _BLANK
	l = <-c
	if i, e := strconv.Atoi(l.token); e != nil {
		if i, ok := Str_alg[strings.ToUpper(l.token)]; !ok {
			return nil, &ParseError{f, "bad DLV Algorithm", l}
		} else {
			rr.Algorithm = i
		}
	} else {
		rr.Algorithm = uint8(i)
	}
	<-c // _BLANK
	l = <-c
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{f, "bad DLV DigestType", l}
	} else {
		rr.DigestType = uint8(i)
	}
	// There can be spaces here...
	l = <-c
	s := ""
	for l.value != _NEWLINE && l.value != _EOF {
		switch l.value {
		case _STRING:
			s += l.token
		case _BLANK:
			// Ok
		default:
			return nil, &ParseError{f, "bad DLV Digest", l}
		}
		l = <-c
	}
	rr.Digest = s
	return rr, nil
}

func setTA(h RR_Header, c chan lex, f string) (RR, *ParseError) {
	rr := new(RR_TA)
	rr.Hdr = h
	l := <-c
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{f, "bad TA KeyTag", l}
	} else {
		rr.KeyTag = uint16(i)
	}
	<-c // _BLANK
	l = <-c
	if i, e := strconv.Atoi(l.token); e != nil {
		if i, ok := Str_alg[strings.ToUpper(l.token)]; !ok {
			return nil, &ParseError{f, "bad TA Algorithm", l}
		} else {
			rr.Algorithm = i
		}
	} else {
		rr.Algorithm = uint8(i)
	}
	<-c // _BLANK
	l = <-c
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{f, "bad TA DigestType", l}
	} else {
		rr.DigestType = uint8(i)
	}
	// There can be spaces here...
	l = <-c
	s := ""
	for l.value != _NEWLINE && l.value != _EOF {
		switch l.value {
		case _STRING:
			s += l.token
		case _BLANK:
			// Ok
		default:
			return nil, &ParseError{f, "bad TA Digest", l}
		}
		l = <-c
	}
	rr.Digest = s
	return rr, nil
}

func setTLSA(h RR_Header, c chan lex, f string) (RR, *ParseError) {
	rr := new(RR_TLSA)
	rr.Hdr = h
	l := <-c
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{f, "bad TLSA Usage", l}
	} else {
		rr.Usage = uint8(i)
	}
	<-c // _BLANK
	l = <-c
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{f, "bad TLSA Selector", l}
	} else {
		rr.Selector = uint8(i)
	}
	<-c // _BLANK
	l = <-c
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{f, "bad TLSA MatchingType", l}
	} else {
		rr.MatchingType = uint8(i)
	}
	// There can be spaces here...
	l = <-c
	s := ""
	for l.value != _NEWLINE && l.value != _EOF {
		switch l.value {
		case _STRING:
			s += l.token
		case _BLANK:
			// Ok
		default:
			return nil, &ParseError{f, "bad TLSA Certificate", l}
		}
		l = <-c
	}
	rr.Certificate = s
	return rr, nil
}

func setRFC3597(h RR_Header, c chan lex, f string) (RR, *ParseError) {
	rr := new(RR_RFC3597)
	rr.Hdr = h
	l := <-c
	if l.token != "\\#" {
		return nil, &ParseError{f, "unkown RR type", l}
	}
	<-c // _BLANK
	l = <-c
	rdlength, e := strconv.Atoi(l.token)
	if e != nil {
		return nil, &ParseError{f, "bad RFC3597 Rdata", l}
	}
	// There can be spaces here...
	l = <-c
	s := ""
	for l.value != _NEWLINE && l.value != _EOF {
		switch l.value {
		case _STRING:
			s += l.token
		case _BLANK:
			// Ok
		default:
			return nil, &ParseError{f, "bad RFC3597 Rdata", l}
		}
		l = <-c
	}
	if rdlength*2 != len(s) {
		return nil, &ParseError{f, "bad RFC3597 Rdata", l}
	}
	rr.Rdata = s
	return rr, nil
}

func setSPF(h RR_Header, c chan lex, f string) (RR, *ParseError) {
	rr := new(RR_SPF)
	rr.Hdr = h

	// Get the remaining data until we see a NEWLINE
	quote := false
	l := <-c
	var s []string
	switch l.value == _QUOTE {
	case true: // A number of quoted string
		s = make([]string, 0)
		for l.value != _NEWLINE && l.value != _EOF {
			switch l.value {
			case _STRING:
				s = append(s, l.token)
			case _BLANK:
				if quote {
					// _BLANK can only be seen in between txt parts.
					return nil, &ParseError{f, "bad SPF Txt", l}
				}
			case _QUOTE:
				quote = !quote
			default:
				return nil, &ParseError{f, "bad SPF Txt", l}
			}
			l = <-c
		}
		if quote {
			return nil, &ParseError{f, "bad SPF Txt", l}
		}
	case false: // Unquoted text record
		s = make([]string, 1)
		for l.value != _NEWLINE && l.value != _EOF {
			s[0] += l.token
			l = <-c
		}
	}
	rr.Txt = s
	return rr, nil
}

func setTXT(h RR_Header, c chan lex, f string) (RR, *ParseError) {
	rr := new(RR_TXT)
	rr.Hdr = h

	// Get the remaining data until we see a NEWLINE
	quote := false
	l := <-c
	var s []string
	switch l.value == _QUOTE {
	case true: // A number of quoted string
		s = make([]string, 0)
		for l.value != _NEWLINE && l.value != _EOF {
			switch l.value {
			case _STRING:
				s = append(s, l.token)
			case _BLANK:
				if quote {
					// _BLANK can only be seen in between txt parts.
					return nil, &ParseError{f, "bad TXT Txt", l}
				}
			case _QUOTE:
				quote = !quote
			default:
				return nil, &ParseError{f, "bad TXT Txt", l}
			}
			l = <-c
		}
		if quote {
			return nil, &ParseError{f, "bad TXT Txt", l}
		}
	case false: // Unquoted text record
		s = make([]string, 1)
		for l.value != _NEWLINE && l.value != _EOF {
			s[0] += l.token
			l = <-c
		}
	}
	rr.Txt = s
	return rr, nil
}

func setURI(h RR_Header, c chan lex, f string) (RR, *ParseError) {
	rr := new(RR_URI)
	rr.Hdr = h

	l := <-c
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{f, "bad URI Priority", l}
	} else {
		rr.Priority = uint16(i)
	}
	<-c // _BLANK
	l = <-c
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{f, "bad URI Weight", l}
	} else {
		rr.Weight = uint16(i)
	}
	// _BLANK?

	// Get the remaining data until we see a NEWLINE
	quote := false
	l = <-c
	var s string
	switch l.value == _QUOTE {
	case true:
		for l.value != _NEWLINE && l.value != _EOF {
			switch l.value {
			case _STRING:
				s += l.token
			case _BLANK:
				if quote {
					// _BLANK can only be seen in between txt parts.
					return nil, &ParseError{f, "bad URI Target", l}
				}
			case _QUOTE:
				quote = !quote
			default:
				return nil, &ParseError{f, "bad URI Target", l}
			}
			l = <-c
		}
		if quote {
			return nil, &ParseError{f, "bad URI Target", l}
		}
	case false: // Unquoted
		return nil, &ParseError{f, "bad URI Target", l}
	}
	rr.Target = s
	return rr, nil
}

func setIPSECKEY(h RR_Header, c chan lex, o, f string) (RR, *ParseError) {
	rr := new(RR_IPSECKEY)
	rr.Hdr = h

	l := <-c
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{f, "bad IPSECKEY Precedence", l}
	} else {
		rr.Precedence = uint8(i)
	}
	<-c // _BLANK
	l = <-c
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{f, "bad IPSECKEY GatewayType", l}
	} else {
		rr.GatewayType = uint8(i)
	}
	<-c // _BLANK
	l = <-c
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{f, "bad IPSECKEY Algorithm", l}
	} else {
		rr.Algorithm = uint8(i)
	}
	<-c
	l = <-c
	rr.Gateway = l.token
	l = <-c
	var s string
	for l.value != _NEWLINE && l.value != _EOF {
		switch l.value {
		case _STRING:
			s += l.token
		case _BLANK:
			// Ok
		default:
			return nil, &ParseError{f, "bad IPSECKEY PublicKey", l}
		}
		l = <-c
	}
	rr.PublicKey = s
	return rr, nil
}

func setDHCID(h RR_Header, c chan lex, f string) (RR, *ParseError) {
	// awesome record to parse!
	rr := new(RR_DHCID)
	rr.Hdr = h

	l := <-c // _STRING
	var s string
	for l.value != _NEWLINE && l.value != _EOF {
		switch l.value {
		case _STRING:
			s += l.token
		case _BLANK:
			// Ok
		default:
			return nil, &ParseError{f, "bad DHCID Digest", l}
		}
		l = <-c
	}
	rr.Digest = s
	return rr, nil
}
