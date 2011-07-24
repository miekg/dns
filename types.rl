%%{
    machine z;
    action setA {
        rdf := fields(data[mark:p], 1)
        rr := new(RR_A)
        rr.Hdr = hdr
        rr.Hdr.Rrtype = TypeA
        rr.A = net.ParseIP(rdf[0])
        if rr.A == nil {
                return z, &ParseError{Error: "bad A: " + rdf[0], line: l}
        }
        z.Push(rr)
    }

    action setAAAA {
        rdf := fields(data[mark:p], 1)
        rr := new(RR_AAAA)
        rr.Hdr = hdr
        rr.Hdr.Rrtype = TypeAAAA
        rr.AAAA = net.ParseIP(rdf[0])
        if rr.AAAA == nil {
                return z, &ParseError{Error: "bad AAAA: " + rdf[0], line: l}
        }
        z.Push(rr)
    }

    action setNS {
        rdf := fields(data[mark:p], 1)
        rr := new(RR_NS)
        rr.Hdr = hdr
        rr.Hdr.Rrtype = TypeNS
        rr.Ns = rdf[0]
        if ! IsDomainName(rdf[0]) {
                return z, &ParseError{Error: "bad NS: " + rdf[0], line: l}
        }
        z.Push(rr)
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
                return z, &ParseError{Error: "bad MX: " + rdf[0], line: l}
        }
        z.Push(rr)
    }

    action setCNAME {
        rdf := fields(data[mark:p], 1)
        rr := new(RR_CNAME)
        rr.Hdr = hdr
        rr.Hdr.Rrtype = TypeCNAME
        rr.Cname = rdf[0]
        if ! IsDomainName(rdf[0]) {
                return z, &ParseError{Error: "bad CNAME: " + rdf[0], line: l}
        }
        z.Push(rr)
    }

    action setSOA {
        var (
                i int
                err os.Error
        )
        rdf := fields(data[mark:p], 7)
        rr := new(RR_SOA)
        rr.Hdr = hdr
        rr.Hdr.Rrtype = TypeSOA
        rr.Ns = rdf[0]
        rr.Mbox = rdf[1]
        if ! IsDomainName(rdf[0]) || ! IsDomainName(rdf[1]) {
                return z, &ParseError{Error: "bad SOA: " + rdf[0] + "," + rdf[1], line: l}
        }
        for j, _ := range rdf[2:7] {
            if i, err = strconv.Atoi(rdf[j]); err != nil {
                    return z, &ParseError{Error: "bad SOA: " + rdf[j], line: l}
            }
            switch j {
                    case 2: rr.Serial = uint32(i)
                    case 3: rr.Refresh = uint32(i)
                    case 4: rr.Retry = uint32(i)
                    case 5: rr.Expire = uint32(i)
                    case 6: rr.Minttl = uint32(i)
            }
        }
        z.Push(rr)
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
        z.Push(rr)
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
        z.Push(rr)
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
        z.Push(rr)
    }

    action setDNSKEY {
        rdf := fields(data[mark:p], 4)
        rr := new(RR_DNSKEY)
        rr.Hdr = hdr
        rr.Hdr.Rrtype = TypeDNSKEY
        rr.Flags = uint16(atoi(rdf[0]))
        rr.Protocol = uint8(atoi(rdf[1]))
        rr.Algorithm = uint8(atoi(rdf[2]))
        rr.PublicKey = rdf[3]
        z.Push(rr)
    }

    action setRRSIG {
        rdf := fields(data[mark:p], 9)
        rr := new(RR_RRSIG)
        rr.Hdr = hdr
        rr.Hdr.Rrtype = TypeRRSIG
        rr.TypeCovered = uint16(atoi(rdf[0]))
        rr.Algorithm = uint8(atoi(rdf[1]))
        rr.Labels = uint8(atoi(rdf[2]))
        rr.OrigTtl = uint32(atoi(rdf[3]))
        rr.Expiration = uint32(atoi(rdf[4]))
        rr.Inception = uint32(atoi(rdf[5]))
        rr.KeyTag = uint16(atoi(rdf[6]))
        rr.SignerName = rdf[7]
        rr.Signature = rdf[9]
        z.Push(rr)
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
        z.Push(rr)
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
        z.Push(rr)
    }

    action setNSEC3PARAM {
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
}%%
