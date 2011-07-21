%%{
        machine z;

        action rdata_a {
            rr = new(RR_A)
            x := rr.(*RR_A)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeA
            x.A = net.ParseIP(tok.T[0])
        }
        action rdata_aaaa {
            rr = new(RR_AAAA)
            x := rr.(*RR_AAAA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeAAAA
            x.AAAA = net.ParseIP(tok.T[0])
        }
        action rdata_ns {
            rr = new(RR_NS)
            x := rr.(*RR_NS)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeNS
            x.Ns = tok.T[0]
        }
        action rdata_cname {
            rr = new(RR_CNAME)
            x := rr.(*RR_CNAME)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeCNAME
            x.Cname = tok.T[0]
        }
        action rdata_soa {
            rr = new(RR_SOA)
            x := rr.(*RR_SOA)
            x.Hdr = *hdr
            x.Hdr.Rrtype = TypeSOA
            x.Ns = tok.T[0]
            x.Mbox = tok.T[1]
            x.Serial = uint32(tok.N[0])
            x.Refresh = uint32(tok.N[1])
            x.Retry = uint32(tok.N[2])
            x.Expire = uint32(tok.N[3])
            x.Minttl = uint32(tok.N[4])
        }
        action rdata_mx {
            rr = new(RR_MX)
            x := rr.(*RR_MX)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeMX
            x.Pref = uint16(tok.N[0])
            x.Mx = tok.T[0]
        }
        action rdata_ds {
            rr = new(RR_DS)
            x := rr.(*RR_DS)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeDS
            x.KeyTag = uint16(tok.N[0])
            x.Algorithm = uint8(tok.N[1])
            x.DigestType = uint8(tok.N[2])
            x.Digest = tok.T[0]
        }
        action rdata_dnskey {
            rr = new(RR_DNSKEY)
            x := rr.(*RR_DNSKEY)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeDNSKEY
            x.Flags = uint16(tok.N[0])
            x.Protocol = uint8(tok.N[1])
            x.Algorithm = uint8(tok.N[2])
            x.PublicKey = tok.T[0]
        }
        action rdata_rrsig {
            rr = new(RR_RRSIG)
            x := rr.(*RR_RRSIG)
            x.Hdr = *hdr;
            x.Hdr.Rrtype = TypeRRSIG
            x.TypeCovered = uint16(tok.N[0])
            x.Algorithm = uint8(tok.N[1])
            x.Labels = uint8(tok.N[2])
            x.OrigTtl = uint32(tok.N[3])
            x.Expiration = uint32(tok.N[4])
            x.Inception = uint32(tok.N[5])
            x.KeyTag = uint16(tok.N[6])
            x.SignerName = tok.T[0]
            x.Signature = tok.T[1]
        }
}%%
