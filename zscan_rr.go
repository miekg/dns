package dns

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Parse the rdata of each rrtype.
// All data from the channel c is either _STRING or _BLANK.
// After the rdata there may come 1 _BLANK and then a _NEWLINE
// or immediately a _NEWLINE. If this is not the case we flag
// an *ParseError: garbage after rdata.

func setRR(h RR_Header, c chan lex) (RR, *ParseError) {
	var r RR
	e := new(ParseError)
	switch h.Rrtype {
	// goto Slurpremainder
	case TypeA:
		r, e = setA(h, c)
		if e != nil {
			return nil, e
		}
		if se := slurpRemainder(c); se != nil {
			return nil, se
		}
	case TypeAAAA:
		r, e = setAAAA(h, c)
		if e != nil {
			return nil, e
		}
		if se := slurpRemainder(c); se != nil {
			return nil, se
		}
	case TypeNS:
		r, e = setNS(h, c)
		if e != nil {
			return nil, e
		}
		if se := slurpRemainder(c); se != nil {
			return nil, se
		}
	case TypeMX:
		r, e = setMX(h, c)
		if e != nil {
			return nil, e
		}
		if se := slurpRemainder(c); se != nil {
			return nil, se
		}
	case TypeCNAME:
		r, e = setCNAME(h, c)
		if e != nil {
			return nil, e
		}
		if se := slurpRemainder(c); se != nil {
			return nil, se
		}
	case TypeSOA:
		r, e = setSOA(h, c)
		if e != nil {
			return nil, e
		}
		if se := slurpRemainder(c); se != nil {
			return nil, se
		}
	case TypeSSHFP:
		r, e = setSSHFP(h, c)
		if e != nil {
			return nil, e
		}
		if se := slurpRemainder(c); se != nil {
			return nil, se
		}
		// These types have a variable ending either chunks of txt or chunks/base64 or hex.
		// They need to search for the end of the RR themselves, hence they look for the ending
		// newline. Thus there is no need to slurp the remainder, because there is none.
	case TypeDNSKEY:
		r, e = setDNSKEY(h, c)
	case TypeRRSIG:
		r, e = setRRSIG(h, c)
	case TypeNSEC:
		r, e = setNSEC(h, c)
	case TypeNSEC3:
		r, e = setNSEC3(h, c)
	case TypeDS:
		r, e = setDS(h, c)
	case TypeTXT:
		r, e = setTXT(h, c)
	default:
		// Don't the have the token the holds the RRtype, but we substitute that in the
		// calling function when lex is empty.
		return nil, &ParseError{"Unknown RR type", lex{}}
	}
	return r, e
}

func slurpRemainder(c chan lex) *ParseError {
	l := <-c
	if _DEBUG {
		fmt.Printf("%v\n", l)
	}
	switch l.value {
	case _BLANK:
		l = <-c
		if _DEBUG {
			fmt.Printf("%v\n", l)
		}
		if l.value != _NEWLINE && l.value != _EOF {
			return &ParseError{"garbage after rdata", l}
		}
		// Ok
	case _NEWLINE:
		// Ok
	case _EOF:
		// Ok
	default:
		return &ParseError{"garbage after directly rdata", l}
	}
	return nil
}

func setA(h RR_Header, c chan lex) (RR, *ParseError) {
	rr := new(RR_A)
	rr.Hdr = h

	l := <-c
	rr.A = net.ParseIP(l.token)
	if rr.A == nil {
		return nil, &ParseError{"bad A", l}
	}
	return rr, nil
}

func setAAAA(h RR_Header, c chan lex) (RR, *ParseError) {
	rr := new(RR_AAAA)
	rr.Hdr = h

	l := <-c
	rr.AAAA = net.ParseIP(l.token)
	if rr.AAAA == nil {
		return nil, &ParseError{"bad AAAA", l}
	}
	return rr, nil
}

func setNS(h RR_Header, c chan lex) (RR, *ParseError) {
	rr := new(RR_NS)
	rr.Hdr = h

	l := <-c
	rr.Ns = l.token
	if !IsDomainName(l.token) {
		return nil, &ParseError{"bad NS Ns", l}
	}
	return rr, nil
}

func setMX(h RR_Header, c chan lex) (RR, *ParseError) {
	rr := new(RR_MX)
	rr.Hdr = h

	l := <-c
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{"bad MX Pref", l}
	} else {
		rr.Pref = uint16(i)
	}
	<-c     // _BLANK
	l = <-c // _STRING
	rr.Mx = l.token
	if !IsDomainName(l.token) {
		return nil, &ParseError{"bad MX Mx", l}
	}
	return rr, nil
}

func setCNAME(h RR_Header, c chan lex) (RR, *ParseError) {
	rr := new(RR_CNAME)
	rr.Hdr = h

	l := <-c
	rr.Cname = l.token
	if !IsDomainName(l.token) {
		return nil, &ParseError{"bad CNAME", l}
	}
	return rr, nil
}

func setSOA(h RR_Header, c chan lex) (RR, *ParseError) {
	rr := new(RR_SOA)
	rr.Hdr = h

	l := <-c
	rr.Ns = l.token
	<-c // _BLANK
	if !IsDomainName(l.token) {
		return nil, &ParseError{"bad SOA mname", l}
	}

	l = <-c
	rr.Mbox = l.token
	if !IsDomainName(l.token) {
		return nil, &ParseError{"bad SOA rname", l}
	}
	<-c // _BLANK

	var j int
	var e error
	for i := 0; i < 5; i++ {
		l = <-c
		if j, e = strconv.Atoi(l.token); e != nil {
			return nil, &ParseError{"bad SOA zone parameter", l}
		}
		switch i {
		case 0:
			rr.Serial = uint32(j)
			<-c // _BLANK
		case 1:
			rr.Refresh = uint32(j)
			<-c // _BLANK
		case 2:
			rr.Retry = uint32(j)
			<-c // _BLANK
		case 3:
			rr.Expire = uint32(j)
			<-c // _BLANK
		case 4:
			rr.Minttl = uint32(j)
		}
	}
	return rr, nil
}

func setRRSIG(h RR_Header, c chan lex) (RR, *ParseError) {
	rr := new(RR_RRSIG)
	rr.Hdr = h
	l := <-c
	if t, ok := Str_rr[strings.ToUpper(l.token)]; !ok {
		return nil, &ParseError{"bad RRSIG", l}
	} else {
		rr.TypeCovered = t
	}
	<-c // _BLANK
	l = <-c
	if i, err := strconv.Atoi(l.token); err != nil {
		return nil, &ParseError{"bad RRSIG", l}
	} else {
		rr.Algorithm = uint8(i)
	}
	<-c // _BLANK
	l = <-c
	if i, err := strconv.Atoi(l.token); err != nil {
		return nil, &ParseError{"bad RRSIG", l}
	} else {
		rr.Labels = uint8(i)
	}
	<-c // _BLANK
	l = <-c
	if i, err := strconv.Atoi(l.token); err != nil {
		return nil, &ParseError{"bad RRSIG", l}
	} else {
		rr.OrigTtl = uint32(i)
	}
	<-c // _BLANK
	l = <-c
	if i, err := dateToTime(l.token); err != nil {
		return nil, &ParseError{"bad RRSIG", l}
	} else {
		rr.Expiration = i
	}
	<-c // _BLANK
	l = <-c
	if i, err := dateToTime(l.token); err != nil {
		return nil, &ParseError{"bad RRSIG", l}
	} else {
		rr.Inception = i
	}
	<-c // _BLANK
	l = <-c
	if i, err := strconv.Atoi(l.token); err != nil {
		return nil, &ParseError{"bad RRSIG", l}
	} else {
		rr.KeyTag = uint16(i)
	}
	<-c // _BLANK
	l = <-c
	if !IsDomainName(l.token) {
		return nil, &ParseError{"bad RRSIG", l}
	} else {
		rr.SignerName = l.token
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
			return nil, &ParseError{"bad RRSIG", l}
		}
		l = <-c
	}
	rr.Signature = s
	return rr, nil
}

func setNSEC(h RR_Header, c chan lex) (RR, *ParseError) {
	rr := new(RR_NSEC)
	rr.Hdr = h

	l := <-c
	if !IsDomainName(l.token) {
		return nil, &ParseError{"bad NSEC nextdomain", l}
	} else {
		rr.NextDomain = l.token
	}

	rr.TypeBitMap = make([]uint16, 0)
	l = <-c
	for l.value != _NEWLINE && l.value != _EOF {
		switch l.value {
		case _BLANK:
			// Ok
		case _STRING:
			if k, ok := Str_rr[strings.ToUpper(l.token)]; !ok {
				return nil, &ParseError{"bad NSEC non RR in type bitmap", l}
			} else {
				rr.TypeBitMap = append(rr.TypeBitMap, k)
			}
		default:
			return nil, &ParseError{"bad NSEC garbage in type bitmap", l}
		}
		l = <-c
	}
	return rr, nil
}

func setNSEC3(h RR_Header, c chan lex) (RR, *ParseError) {
	rr := new(RR_NSEC3)
	rr.Hdr = h

	l := <-c
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{"bad NSEC3", l}
	} else {
		rr.Hash = uint8(i)
	}
	<-c // _BLANK
	l = <-c
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{"bad NSEC3", l}
	} else {
		rr.Flags = uint8(i)
	}
	<-c // _BLANK
	l = <-c
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{"bad NSEC3", l}
	} else {
		rr.Iterations = uint16(i)
	}
	<-c
	l = <-c
	rr.SaltLength = uint8(len(l.token))
	rr.Salt = l.token // CHECK?

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
				return nil, &ParseError{"bad NSEC3", l}
			} else {
				rr.TypeBitMap = append(rr.TypeBitMap, k)
			}
		default:
			return nil, &ParseError{"bad NSEC3", l}
		}
		l = <-c
	}
	return rr, nil
}

/*
func setNSEC3PARAM(h RR_Header, c chan lex) (RR, *ParseError) {
        rr := new(RR_NSEC3PARAM)
        rr.Hdr = h
        l := <-c
        if i, e = strconv.Atoi(rdf[0]); e != nil {
                return nil, &ParseError{Error: "bad NSEC3PARAM", name: rdf[0], line: l}
        } else {
        rr.Hash = uint8(i)
}
        if i, e = strconv.Atoi(rdf[1]); e != nil {
                reutrn nil, &ParseError{Error: "bad NSEC3PARAM", name: rdf[1], line: l}
        } else {
        rr.Flags = uint8(i)
}
        if i, e = strconv.Atoi(rdf[2]); e != nil {
                return nil, &ParseError{Error: "bad NSEC3PARAM", name: rdf[2], line: l}
        } else {
        rr.Iterations = uint16(i)
}
        rr.Salt = rdf[3]
        rr.SaltLength = uint8(len(rr.Salt))
        zp.RR <- rr
    }
*/

func setSSHFP(h RR_Header, c chan lex) (RR, *ParseError) {
	rr := new(RR_SSHFP)
	rr.Hdr = h

	l := <-c
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{"bad SSHFP", l}
	} else {
		rr.Algorithm = uint8(i)
	}
	<-c // _BLANK
	l = <-c
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{"bad SSHFP", l}
	} else {
		rr.Type = uint8(i)
	}
	<-c // _BLANK
	l = <-c
	rr.FingerPrint = l.token
	return rr, nil
}

func setDNSKEY(h RR_Header, c chan lex) (RR, *ParseError) {
	rr := new(RR_DNSKEY)
	rr.Hdr = h

	l := <-c
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{"bad DNSKEY", l}
	} else {
		rr.Flags = uint16(i)
	}
	<-c     // _BLANK
	l = <-c // _STRING
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{"bad DNSKEY", l}
	} else {
		rr.Protocol = uint8(i)
	}
	<-c     // _BLANK
	l = <-c // _STRING
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{"bad DNSKEY", l}
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
			return nil, &ParseError{"bad DNSKEY", l}
		}
		l = <-c
	}
	rr.PublicKey = s
	return rr, nil
}

// DLV and TA are the same
func setDS(h RR_Header, c chan lex) (RR, *ParseError) {
	rr := new(RR_DS)
	rr.Hdr = h
	l := <-c
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{"bad DS", l}
	} else {
		rr.KeyTag = uint16(i)
	}
	<-c // _BLANK
	l = <-c
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{"bad DS", l}
	} else {
		rr.Algorithm = uint8(i)
	}
	<-c // _BLANK
	l = <-c
	if i, e := strconv.Atoi(l.token); e != nil {
		return nil, &ParseError{"bad DS", l}
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
			return nil, &ParseError{"bad DS", l}
		}
		l = <-c
	}
	rr.Digest = s
	return rr, nil
}

func setTXT(h RR_Header, c chan lex) (RR, *ParseError) {
	rr := new(RR_TXT)
	rr.Hdr = h

	// Get the remaining data until we see a NEWLINE
	l := <-c
	var s string
	for l.value != _NEWLINE && l.value != _EOF {
		switch l.value {
		case _STRING:
			s += l.token
		case _BLANK:
			s += l.token
		default:
			return nil, &ParseError{"bad TXT", l}
		}
		l = <-c
	}
	rr.Txt = s
	return rr, nil
}
