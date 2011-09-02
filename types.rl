%%{
    machine z;

    action setA {
        rdf := fields(data[mark:p], 1)
        rr := new(RR_A)
        rr.Hdr = hdr
        rr.Hdr.Rrtype = TypeA
        rr.A = net.ParseIP(rdf[0])
        if rr.A == nil {
                zp.Err <- &ParseError{Error: "bad A", name: rdf[0], line: l}
                return
        }
        zp.RR <- rr
    }

    action setAAAA {
        rdf := fields(data[mark:p], 1)
        rr := new(RR_AAAA)
        rr.Hdr = hdr
        rr.Hdr.Rrtype = TypeAAAA
        rr.AAAA = net.ParseIP(rdf[0])
        if rr.AAAA == nil {
                zp.Err <- &ParseError{Error: "bad AAAA", name: rdf[0], line: l}
                return
        }
        zp.RR <- rr
    }

    action setNS {
        rdf := fields(data[mark:p], 1)
        rr := new(RR_NS)
        rr.Hdr = hdr
        rr.Hdr.Rrtype = TypeNS
        rr.Ns = rdf[0]
        if ! IsDomainName(rdf[0]) {
                zp.Err <- &ParseError{Error: "bad NS", name: rdf[0], line: l}
                return
        }
        zp.RR <- rr
    }

    action setMX {
        rdf := fields(data[mark:p], 2)
        rr := new(RR_MX)
        rr.Hdr = hdr
        rr.Hdr.Rrtype = TypeMX
        i, err := strconv.Atoui(rdf[0])
        rr.Pref = uint16(i)
        rr.Mx = rdf[1]
        if err != nil {
                zp.Err <- &ParseError{Error: "bad MX", name: rdf[0], line: l}
                return
        }
        zp.RR <- rr
    }

    action setCNAME {
        rdf := fields(data[mark:p], 1)
        rr := new(RR_CNAME)
        rr.Hdr = hdr
        rr.Hdr.Rrtype = TypeCNAME
        rr.Cname = rdf[0]
        if ! IsDomainName(rdf[0]) {
                zp.Err <- &ParseError{Error: "bad CNAME", name: rdf[0], line: l}
                return
        }
        zp.RR <- rr
    }

    action setSOA {
        var (
                i uint
                err os.Error
        )
        rdf := fields(data[mark:p], 7)
        rr := new(RR_SOA)
        rr.Hdr = hdr
        rr.Hdr.Rrtype = TypeSOA
        rr.Ns = rdf[0]
        rr.Mbox = rdf[1]
        if ! IsDomainName(rdf[0]) {
                zp.Err <- &ParseError{Error: "bad SOA", name: rdf[0], line: l}
                return
        }
        if ! IsDomainName(rdf[1]) {
                zp.Err <- &ParseError{Error: "bad SOA", name: rdf[1], line: l}
                return
        }
        for j, s := range rdf[2:7] {
                if i, err = strconv.Atoui(s); err != nil {
                        zp.Err <- &ParseError{Error: "bad SOA", name: s, line: l}
                        return
                }
                switch j {
                case 0: rr.Serial = uint32(i)
                case 1: rr.Refresh = uint32(i)
                case 2: rr.Retry = uint32(i)
                case 3: rr.Expire = uint32(i)
                case 4: rr.Minttl = uint32(i)
                }
        }
        z.PushRR(rr)
        zp.RR <- rr
    }

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

    action setRRSIG {
        var (
                i uint
                j uint32
                err os.Error
        )
        rdf := fields(data[mark:p], 9)
        rr := new(RR_RRSIG)
        rr.Hdr = hdr
        rr.Hdr.Rrtype = TypeRRSIG

        if _, ok := str_rr[strings.ToUpper(rdf[0])]; !ok {
                zp.Err <- &ParseError{Error: "bad RRSIG", name: rdf[0], line: l}
                return
        }
        rr.TypeCovered = str_rr[strings.ToUpper(rdf[0])]

        if i, err = strconv.Atoui(rdf[1]); err != nil {
                zp.Err <- &ParseError{Error: "bad RRSIG", name: rdf[1], line: l}
                return
        }
        rr.Algorithm = uint8(i)
        if i, err = strconv.Atoui(rdf[2]); err != nil {
                zp.Err <- &ParseError{Error: "bad RRSIG", name: rdf[2], line: l}
                return
        }
        rr.Labels = uint8(i)
        if i, err = strconv.Atoui(rdf[3]); err != nil {
                zp.Err <- &ParseError{Error: "bad RRSIG", name: rdf[3], line: l}
                return
        }
        rr.OrigTtl = uint32(i)

        if j, err = dateToTime(rdf[4]); err != nil {
                zp.Err <- &ParseError{Error: "bad RRSIG", name: rdf[4], line: l}
                return
        }
        rr.Expiration = j
        if j, err = dateToTime(rdf[5]); err != nil {
                zp.Err <- &ParseError{Error: "bad RRSIG", name: rdf[5], line: l}
                return
        }
        rr.Inception = j

        if i, err = strconv.Atoui(rdf[6]); err != nil {
                zp.Err <- &ParseError{Error: "bad RRSIG", name: rdf[3], line: l}
                return
        }
        rr.KeyTag = uint16(i)
       
        rr.SignerName = rdf[7]
        if ! IsDomainName(rdf[7]) {
                zp.Err <- &ParseError{Error: "bad RRSIG", name: rdf[7], line: l}
                return
        }
        // Check base64 TODO
        rr.Signature = rdf[8]
        zp.RR <- rr
    }

    action setNSEC {
        rdf := fields(data[mark:p], 0)
        rr := new(RR_NSEC)
        rr.Hdr = hdr
        rr.Hdr.Rrtype = TypeNSEC
        rr.NextDomain = rdf[0]
        rr.TypeBitMap = make([]uint16, len(rdf)-1)
        // Fill the Type Bit Map
        for i := 1; i < len(rdf); i++ {
                // Check if its there in the map TODO
                rr.TypeBitMap[i-1] = str_rr[strings.ToUpper(rdf[i])]
        }
        zp.RR <- rr
    }

    action setNSEC3 {
        var (
                i uint
                e os.Error
        )
        rdf := fields(data[mark:p], 0)
        rr := new(RR_NSEC3)
        rr.Hdr = hdr
        rr.Hdr.Rrtype = TypeNSEC3

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

    action setNSEC3PARAM {
        var (
                i int
                e os.Error
        )
        rdf := fields(data[mark:p], 4)
        rr := new(RR_NSEC3PARAM)
        rr.Hdr = hdr
        rr.Hdr.Rrtype = TypeNSEC3PARAM
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

    action setTXT {
        rdf := fields(data[mark:p], 1)
        rr := new(RR_TXT)
        rr.Hdr = hdr
        rr.Hdr.Rrtype = TypeTXT
        rr.Txt = rdf[0]
        zp.RR <- rr
    }

    action setSRV {
    }

    action setCERT {
    }

    action setPTR {
    }

    action setDNAME {
    }

    action setNAPTR {
    }

    action setSSHFP {
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
}%%
