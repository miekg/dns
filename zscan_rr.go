package dns

import (
	"net"
	"strconv"
	"strings"
)

// TODO: SPF, TKEY, RR_URI, DHCID, TLSA

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
	case TypeNS:
		r, e = setNS(h, c, o, f)
		goto Slurp
	case TypePTR:
		r, e = setPTR(h, c, o, f)
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
	// These types have a variable ending either chunks of txt or chunks/base64 or hex.
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
	case TypeDS:
		return setDS(h, c, f)
	case TypeTXT:
		return setTXT(h, c, f)
	case TypeSPF:
		return setSPF(h, c, f)
        case TypeIPSECKEY:
                return setIPSECKEY(h, c, o, f)
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

func slurpRemainder(c chan lex, f string) *ParseError {
	l := <-c
	switch l.value {
	case _BLANK:
		l = <-c
		if l.value != _NEWLINE && l.value != _EOF {
			return &ParseError{f, "garbage after rdata", l}
		}
		// Ok
	case _NEWLINE:
		// Ok
	case _EOF:
		// Ok
	default:
		return &ParseError{f, "garbage after rdata", l}
	}
	return nil
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

func setCNAME(h RR_Header, c chan lex, o, f string) (RR, *ParseError) {
	rr := new(RR_CNAME)
	rr.Hdr = h

	l := <-c
	rr.Cname = l.token
	_, ld, ok := IsDomainName(l.token)
	if !ok {
		return nil, &ParseError{f, "bad CNAME Cname", l}
	}
	if rr.Cname[ld-1] != '.' {
		rr.Cname = appendOrigin(rr.Cname, o)
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
			if v, ok = stringToTtl(l, f); !ok {
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
		rr.Preference = uint16(i)
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
	if i, err := dateToTime(l.token); err != nil {
		return nil, &ParseError{f, "bad RRSIG Expiration", l}
	} else {
		rr.Expiration = i
	}
	<-c // _BLANK
	l = <-c
	if i, err := dateToTime(l.token); err != nil {
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
	l = <-c
	for l.value != _NEWLINE && l.value != _EOF {
		switch l.value {
		case _BLANK:
			// Ok
		case _STRING:
			if k, ok := Str_rr[strings.ToUpper(l.token)]; !ok {
				return nil, &ParseError{f, "bad NSEC TypeBitMap", l}
			} else {
				rr.TypeBitMap = append(rr.TypeBitMap, k)
			}
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
	rr.SaltLength = uint8(len(l.token))
	rr.Salt = l.token

	<-c
	l = <-c
	rr.HashLength = uint8(len(l.token))
	rr.NextDomain = l.token

	rr.TypeBitMap = make([]uint16, 0)
	l = <-c
	for l.value != _NEWLINE && l.value != _EOF {
		switch l.value {
		case _BLANK:
			// Ok
		case _STRING:
			if k, ok := Str_rr[strings.ToUpper(l.token)]; !ok {
				return nil, &ParseError{f, "bad NSEC3 TypeBitMap", l}
			} else {
				rr.TypeBitMap = append(rr.TypeBitMap, k)
			}
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

// DLV and TA are the same
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
		return nil, &ParseError{f, "bad DS Algorithm", l}
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
