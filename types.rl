%%{
    machine z;
    action setA {
        rdf := fields(data[mark:p], 1)
        rr := new(RR_A)
        rr.Hdr = hdr
        rr.Hdr.Rrtype = TypeA
        rr.A = net.ParseIP(rdf[0])
        if rr.A == nil {
                return z, &ParseError{Error: "bad A", name: rdf[0], line: l}
        }
        z.PushRR(rr)
    }

    action setAAAA {
        rdf := fields(data[mark:p], 1)
        rr := new(RR_AAAA)
        rr.Hdr = hdr
        rr.Hdr.Rrtype = TypeAAAA
        rr.AAAA = net.ParseIP(rdf[0])
        if rr.AAAA == nil {
                return z, &ParseError{Error: "bad AAAA", name: rdf[0], line: l}
        }
        z.PushRR(rr)
    }

    action setNS {
        rdf := fields(data[mark:p], 1)
        rr := new(RR_NS)
        rr.Hdr = hdr
        rr.Hdr.Rrtype = TypeNS
        rr.Ns = rdf[0]
        if ! IsDomainName(rdf[0]) {
                return z, &ParseError{Error: "bad NS", name: rdf[0], line: l}
        }
        z.PushRR(rr)
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
                return z, &ParseError{Error: "bad MX", name: rdf[0], line: l}
        }
        z.PushRR(rr)
    }

    action setCNAME {
        rdf := fields(data[mark:p], 1)
        rr := new(RR_CNAME)
        rr.Hdr = hdr
        rr.Hdr.Rrtype = TypeCNAME
        rr.Cname = rdf[0]
        if ! IsDomainName(rdf[0]) {
                return z, &ParseError{Error: "bad CNAME", name: rdf[0], line: l}
        }
        z.PushRR(rr)
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
                return z, &ParseError{Error: "bad SOA", name: rdf[0], line: l}
        }
        if ! IsDomainName(rdf[1]) {
                return z, &ParseError{Error: "bad SOA", name: rdf[1], line: l}
        }
        for j, s := range rdf[2:7] {
                if i, err = strconv.Atoui(s); err != nil {
                        return z, &ParseError{Error: "bad SOA", name: s, line: l}
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
    }

    action setDS {
        rdf := fields(data[mark:p], 4)
        rr := new(RR_DS)
        rr.Hdr = hdr
        rr.Hdr.Rrtype = TypeDS
        rr.KeyTag = uint16(atoi(rdf[0]))
        rr.Algorithm = uint8(atoi(rdf[1]))
        rr.DigestType = uint8(atoi(rdf[2]))
        rr.Digest = rdf[3]
        z.PushRR(rr)
    }

    action setDLV {
        rdf := fields(data[mark:p], 4)
        rr := new(RR_DLV)
        rr.Hdr = hdr
        rr.Hdr.Rrtype = TypeDLV
        rr.KeyTag = uint16(atoi(rdf[0]))
        rr.Algorithm = uint8(atoi(rdf[1]))
        rr.DigestType = uint8(atoi(rdf[2]))
        rr.Digest = rdf[3]
        z.PushRR(rr)
    }

    action setTA {
        rdf := fields(data[mark:p], 4)
        rr := new(RR_TA)
        rr.Hdr = hdr
        rr.Hdr.Rrtype = TypeTA
        rr.KeyTag = uint16(atoi(rdf[0]))
        rr.Algorithm = uint8(atoi(rdf[1]))
        rr.DigestType = uint8(atoi(rdf[2]))
        rr.Digest = rdf[3]
        z.PushRR(rr)
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
                return z, &ParseError{Error: "bad DNSKEY", name: rdf[0], line: l}
        }
        rr.Flags = uint16(i)
        if i, e = strconv.Atoui(rdf[1]); e != nil {
                return z, &ParseError{Error: "bad DNSKEY", name: rdf[1], line: l}
        }
        rr.Protocol = uint8(i)
        if i, e = strconv.Atoui(rdf[2]); e != nil {
                return z, &ParseError{Error: "bad DNSKEY", name: rdf[2], line: l}
        }
        rr.Algorithm = uint8(i)
        rr.PublicKey = rdf[3]
        z.PushRR(rr)
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

        if _, ok := str_rr[rdf[0]]; !ok {
                return z, &ParseError{Error: "bad RRSIG", name: rdf[0], line: l}
        }
        rr.TypeCovered = str_rr[rdf[0]]

        if i, err = strconv.Atoui(rdf[1]); err != nil {
                return z, &ParseError{Error: "bad RRSIG", name: rdf[1], line: l}
        }
        rr.Algorithm = uint8(i)
        if i, err = strconv.Atoui(rdf[2]); err != nil {
                return z, &ParseError{Error: "bad RRSIG", name: rdf[2], line: l}
        }
        rr.Labels = uint8(i)
        if i, err = strconv.Atoui(rdf[3]); err != nil {
                return z, &ParseError{Error: "bad RRSIG", name: rdf[3], line: l}
        }
        rr.OrigTtl = uint32(i)

        if j, err = dateToTime(rdf[4]); err != nil {
                return z, &ParseError{Error: "bad RRSIG", name: rdf[4], line: l}
        }
        rr.Expiration = j
        if j, err = dateToTime(rdf[5]); err != nil {
                return z, &ParseError{Error: "bad RRSIG", name: rdf[5], line: l}
        }
        rr.Inception = j

        if i, err = strconv.Atoui(rdf[6]); err != nil {
                return z, &ParseError{Error: "bad RRSIG", name: rdf[3], line: l}
        }
        rr.KeyTag = uint16(i)
       
        rr.SignerName = rdf[7]
        if ! IsDomainName(rdf[7]) {
                return z, &ParseError{Error: "bad RRSIG", name: rdf[7], line: l}
        }
        // Check base64 TODO
        rr.Signature = rdf[8]
        z.PushRR(rr)
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
                rr.TypeBitMap[i-1] = str_rr[rdf[i]]
        }
        z.PushRR(rr)
    }

    action setNSEC3 {
        rdf := fields(data[mark:p], 0)
        rr := new(RR_NSEC3)
        rr.Hdr = hdr
        rr.Hdr.Rrtype = TypeNSEC3
        rr.Hash = uint8(atoi(rdf[0]))
        rr.Flags = uint8(atoi(rdf[1]))
        rr.Iterations = uint16(atoi(rdf[2]))
        rr.SaltLength = uint8(atoi(rdf[3]))
        rr.Salt = rdf[4]
        rr.HashLength = uint8(atoi(rdf[4]))
        rr.NextDomain = rdf[5]
        rr.TypeBitMap = make([]uint16, len(rdf)-6)
        // Fill the Type Bit Map
        for i := 6; i < len(rdf); i++ {
            // Check if its there in the map TODO
            rr.TypeBitMap[i-6] = str_rr[rdf[i]]
        }
        z.PushRR(rr)
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
                return z, &ParseError{Error: "bad NSEC3PARAM", name: rdf[0], line: l}
        }
        rr.Hash = uint8(i)
        if i, e = strconv.Atoi(rdf[1]); e != nil {
                return z, &ParseError{Error: "bad NSEC3PARAM", name: rdf[1], line: l}
        }
        rr.Flags = uint8(i)
        if i, e = strconv.Atoi(rdf[2]); e != nil {
                return z, &ParseError{Error: "bad NSEC3PARAM", name: rdf[2], line: l}
        }
        rr.Iterations = uint16(i)
        rr.Salt = rdf[3]
        rr.SaltLength = uint8(len(rr.Salt))
        z.PushRR(rr)
    }

    action setPRT {
    }

    action setTXT {
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
                return z, &ParseError{Error: "bad SSHFP", name: rdf[0], line: l}
        }
        rr.Algorithm = uint8(i)
        if i, e = strconv.Atoi(rdf[1]); e != nil {
                return z, &ParseError{Error: "bad SSHFP", name: rdf[1], line: l}
        }
        rr.Type = uint8(i)
        rr.FingerPrint = rdf[2]
    }
}%%
