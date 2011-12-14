package dns

import (
        "net"
)

// All data from c is either _STRING or _BLANK
// After the rdata there may come 1 _BLANK and then a _NEWLINE
// or immediately a _NEWLINE. If this is not the case we flag
// an error: garbage after rdata.

func slurpRemainder(c chan Lex) error {
        l := <-c
        switch l.value {
        case _BLANK:
                l = <-c
                if l.value != _NEWLINE {
                        return &ParseError{"garbage after rdata", l}
                }
                // Ok
        case _NEWLINE:
                // Ok
        default:
                return &ParseError{"garbage after rdata", l}
        }
        return nil
}

func setRR(h RR_Header, c chan Lex) (RR, error) {
        var (
                r RR
                e error
        )
        switch h.Rrtype {
        case TypeA:
                r, e = setA(h, c)
                if se := slurpRemainder(c); se != nil {
                        return nil, se
                }
        case TypeRRSIG:
                r, e = setRRSIG(h, c)
                // Remain slurped in function
        default:
                println("RR not supported")
        }
        return r, e
}

func setA(h RR_Header, c chan Lex) (RR, error) {
        rr := new(RR_A)
        rr.Hdr = h

        l := <-c
        rr.A = net.ParseIP(l.token)
        if rr.A == nil {
                return nil, &ParseError{"bad a", l}
        }
        return rr, nil
}

func setAAAA(h RR_Header, c chan Lex) (RR, error) {
        rr := new(RR_AAAA)
        rr.Hdr = h

        l := <-c
        rr.AAAA = net.ParseIP(l.token)
        if rr.AAAA == nil {
                return nil, &ParseError{"bad AAAA", l}
        }
        return rr, nil
}

func setNS(h RR_Header, c chan Lex) (RR, error) {
        rr := new(RR_NS)
        rr.Hdr = h

        l := <-c
        rr.Ns = l.token
        if ! IsDomainName(l.token) {
                return nil, &ParseError{"bad NS", l}
        }
        return rr, nil
}

func setMX(h RR_Header, c chan Lex) (RR, error) {
        rr := new(RR_MX)
        rr.Hdr = h

        l := <-c
        i, e := strconv.Atoui(l.token)
        if e != nil {
                return nil, &ParseError{"bad MX", l}
        }
        rr.Pref = uint16(i)
        <-c // _BLANK
        l = <-c // _STRING
        rr.Mx = l.token
        if ! IsDomainName(l.token) {
                return nil, &ParseError{"bad CNAME", l}
        }
        return rr, nil
}

func setCNAME(h RR_Header, c chan Lex) (RR, error) {
        rr := new(RR_CNAME)
        rr.Hdr = h

        l := <-c
        rr.Cname = l.token
        if ! IsDomainName(l.token) {
                return nil, &ParseError{"bad CNAME", l}
        }
        return rr, nil
}

func setSOA(h RR_Header, c chan Lex) (RR, error) {
        rr := new(RR_SOA)
        rr.Hdr = h

        l := <-c
        var (
                i uint
                err os.Error
        )
        rr.Ns = l.token
        <-c // _BLANK
        if ! IsDomainName(l.token) {
                return nil, &ParseError{"bad SOA", l}
        }

        l = <-c
        rr.Mbox = l.token
        if ! IsDomainName(l.token) {
                return nil, &ParseError{Error: "bad SOA", name: rdf[1], line: l}
        }
        <-c // _BLANK

        for i := 0; i < 5; i++ {
                l = <-c
                if j, e = strconv.Atoui(s); e != nil {
                        return nil, &ParseError{"bad SOA", l}
                }
                switch i {
                case 0: rr.Serial = uint32(j)
                case 1: rr.Refresh = uint32(j)
                case 2: rr.Retry = uint32(j)
                case 3: rr.Expire = uint32(j)
                case 4: rr.Minttl = uint32(j)
                }
                <-c // _BLANK
        }
        return rr, nil
}

func setRRSIG(h RR_Header, c chan Lex) (RR, error) {
        rr := new(RR_RRSIG)
        rr.Hdr = h
        l := <-c
        if t, ok := str_rr[strings.ToUpper(l.token]; !ok {
                return nil, &ParseError{"bad RRSIG", l}
        } else {
                rr.TypeCovered = t
        }
        <-c // _BLANK
        l = <-c
        if i, err := strconv.Atoui(l.token); err != nil {
                return nil, &ParseError{"bad RRSIG", l}
        } else {
                rr.Algorithm = uint8(i)
        }
        <-c // _BLANK
        l = <-c
        if i, err := strconv.Atoui(l.token); err != nil {
                return nil, &ParseError{"bad RRSIG", l}
        } else {
                rr.Labels = uint8(i)
        }
        <-c // _BLANK
        l = <-c
        if i, err := strconv.Atoui(l.token); err != nil {
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
        if i, err := strconv.Atoui(l.token); err != nil {
                return nil, &ParseError{"bad RRSIG", l}
        } else {
                rr.KeyTag = uint16(i)
        }
        <-c // _BLANK
        l = <-c
        if ! IsDomainName(l.token) {
                return nil, &ParseError{"bad RRSIG", l}
        } else {
                rr.SignerName = l.token
        }
        // Get the remaining data until we see a NEWLINE
        l = <-c
        var s string
        for l.value != _NEWLINE {
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

func setNSEC(h RR_Header, c chan Lex) (RR, error) {
        rr := new(RR_NSEC)
        rr.Hdr = h

        l := <-c
        if ! IsDomainName(l.token) {
                return nil, &ParseError{"bad NSEC", l}
        } else {
                rr.NextDomain = l.token
        }

        rr.TypeBitMap = make([]uint16, 0)
        l = <-c
        for l.value != _NEWLINE {
        case _BLANK:
                // Ok
        case _STRING:
                if k, ok := str_rr[strings.ToUpper(l.token)]; !ok {
                        return nil, &ParseError{"bad NSEC", l}
                } else {
                        append(rr.TypeBitMap, k)
                }
        default:
                return nil, &ParseError{"bad NSEC", l}
        }
        return rr, nil
    }

func setNSEC3(h RR_Header, c chan Lex) (RR, error) {
        rr := new(RR_NSEC3)
        rr.Hdr = h

        rdf := fields(data[mark:p], 0)

        if i, e = strconv.Atoui(rdf[0]); e != nil {
                zp.Err <- &ParseError{Error: "bad NSEC3", name: rdf[0], line: l}
                return
        }
        rr.Hash = uint8(i)
        if i, e = strconv.Atoui(rdf[1]); e != nil {
                zp.Err <- &ParseError{Error: "bad NSEC3", name: rdf[1], line: l}
                return
        }
        rr.Flags = uint8(i)
        if i, e = strconv.Atoui(rdf[2]); e != nil {
                zp.Err <- &ParseError{Error: "bad NSEC3", name: rdf[2], line: l}
                return
        }
        rr.Iterations = uint16(i)
        rr.SaltLength = uint8(len(rdf[3]))
        rr.Salt = rdf[3]

        rr.HashLength = uint8(len(rdf[4]))
        rr.NextDomain = rdf[4]
        rr.TypeBitMap = make([]uint16, len(rdf)-5)
        // Fill the Type Bit Map
        for i := 5; i < len(rdf); i++ {
            // Check if its there in the map TODO
            rr.TypeBitMap[i-5] = str_rr[strings.ToUpper(rdf[i])]
        }
        zp.RR <- rr
    }

func setNSEC3PARAM(h RR_Header, c chan Lex) (RR, error) {
        rr := new(RR_NSEC3PARAM)
        rr.Hdr = h
        rdf := fields(data[mark:p], 4)
        if i, e = strconv.Atoi(rdf[0]); e != nil {
                zp.Err <- &ParseError{Error: "bad NSEC3PARAM", name: rdf[0], line: l}
                return
        }
        rr.Hash = uint8(i)
        if i, e = strconv.Atoi(rdf[1]); e != nil {
                zp.Err <- &ParseError{Error: "bad NSEC3PARAM", name: rdf[1], line: l}
                return
        }
        rr.Flags = uint8(i)
        if i, e = strconv.Atoi(rdf[2]); e != nil {
                zp.Err <- &ParseError{Error: "bad NSEC3PARAM", name: rdf[2], line: l}
                return
        }
        rr.Iterations = uint16(i)
        rr.Salt = rdf[3]
        rr.SaltLength = uint8(len(rr.Salt))
        zp.RR <- rr
    }

func setTXT(h RR_Header, c chan Lex) (RR, error) {
        rr := new(RR_TXT)
        rr.Hdr = h
        rr.Txt = rdf[0]
        zp.RR <- rr
    }

    /*
func setDS(h RR_Header, c chan Lex) (RR, error) {
        rr := new(RR_DS)
        rr.Hdr = h
    action setDS {
        var (
                i uint
                e os.Error
        )
        rdf := fields(data[mark:p], 4)
        rr := new(RR_DS)
        rr.Hdr = hdr
        rr.Hdr.Rrtype = TypeDS
        if i, e = strconv.Atoui(rdf[0]); e != nil {
                zp.Err <- &ParseError{Error: "bad DS", name: rdf[0], line: l}
                return
        }
        rr.KeyTag = uint16(i)
        if i, e = strconv.Atoui(rdf[1]); e != nil {
                zp.Err <- &ParseError{Error: "bad DS", name: rdf[1], line: l}
                return
        }
        rr.Algorithm = uint8(i)
        if i, e = strconv.Atoui(rdf[2]); e != nil {
                zp.Err <- &ParseError{Error: "bad DS", name: rdf[2], line: l}
                return
        }
        rr.DigestType = uint8(i)
        rr.Digest = rdf[3]
        zp.RR <- rr
    }

func setCNAME(h RR_Header, c chan Lex) (RR, error) {
        rr := new(RR_CNAME)
        rr.Hdr = h
    action setDLV {
        var (
                i uint
                e os.Error
        )
        rdf := fields(data[mark:p], 4)
        rr := new(RR_DLV)
        rr.Hdr = hdr
        rr.Hdr.Rrtype = TypeDLV
        if i, e = strconv.Atoui(rdf[0]); e != nil {
                zp.Err <- &ParseError{Error: "bad DS", name: rdf[0], line: l}
                return
        }
        rr.KeyTag = uint16(i)
        if i, e = strconv.Atoui(rdf[1]); e != nil {
                zp.Err <- &ParseError{Error: "bad DS", name: rdf[1], line: l}
                return
        }
        rr.Algorithm = uint8(i)
        if i, e = strconv.Atoui(rdf[2]); e != nil {
                zp.Err <- &ParseError{Error: "bad DS", name: rdf[2], line: l}
                return
        }
        rr.DigestType = uint8(i)
        rr.Digest = rdf[3]
        zp.RR <- rr
    }

func setCNAME(h RR_Header, c chan Lex) (RR, error) {
        rr := new(RR_CNAME)
        rr.Hdr = h
    action setTA {
        var (
                i uint
                e os.Error
        )
        rdf := fields(data[mark:p], 4)
        rr := new(RR_TA)
        rr.Hdr = hdr
        rr.Hdr.Rrtype = TypeTA
        if i, e = strconv.Atoui(rdf[0]); e != nil {
                zp.Err <- &ParseError{Error: "bad DS", name: rdf[0], line: l}
                return
        }
        rr.KeyTag = uint16(i)
        if i, e = strconv.Atoui(rdf[1]); e != nil {
                zp.Err <- &ParseError{Error: "bad DS", name: rdf[1], line: l}
                return
        }
        rr.Algorithm = uint8(i)
        if i, e = strconv.Atoui(rdf[2]); e != nil {
                zp.Err <- &ParseError{Error: "bad DS", name: rdf[2], line: l}
                return
        }
        rr.DigestType = uint8(i)
        rr.Digest = rdf[3]
        zp.RR <- rr
    }

func setCNAME(h RR_Header, c chan Lex) (RR, error) {
        rr := new(RR_CNAME)
        rr.Hdr = h
    action setDNSKEY {
        var (
                i uint
                e os.Error
        )
        rdf := fields(data[mark:p], 4)
        rr := new(RR_DNSKEY)
        rr.Hdr = hdr
        rr.Hdr.Rrtype = TypeDNSKEY

        if i, e = strconv.Atoui(rdf[0]); e != nil {
                zp.Err <- &ParseError{Error: "bad DNSKEY", name: rdf[0], line: l}
                return
        }
        rr.Flags = uint16(i)
        if i, e = strconv.Atoui(rdf[1]); e != nil {
                zp.Err <- &ParseError{Error: "bad DNSKEY", name: rdf[1], line: l}
                return
        }
        rr.Protocol = uint8(i)
        if i, e = strconv.Atoui(rdf[2]); e != nil {
                zp.Err <- &ParseError{Error: "bad DNSKEY", name: rdf[2], line: l}
                return
        }
        rr.Algorithm = uint8(i)
        rr.PublicKey = rdf[3]
        zp.RR <- rr
    }


func setSSHFP(h RR_Header, c chan Lex) (RR, error) {
        rr := new(RR_CNAME)
        rr.Hdr = h
        var (
                i int
                e os.Error
        )
        rdf := fields(data[mark:p], 3)
        rr := new(RR_SSHFP)
        rr.Hdr = hdr
        rr.Hdr.Rrtype = TypeSSHFP
        if i, e = strconv.Atoi(rdf[0]); e != nil {
                zp.Err <- &ParseError{Error: "bad SSHFP", name: rdf[0], line: l}
                return
        }
        rr.Algorithm = uint8(i)
        if i, e = strconv.Atoi(rdf[1]); e != nil {
                zp.Err <- &ParseError{Error: "bad SSHFP", name: rdf[1], line: l}
                return
        }
        rr.Type = uint8(i)
        rr.FingerPrint = rdf[2]
        zp.RR <- rr
}
