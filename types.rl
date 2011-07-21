func rdata_a(hdr RR_Header, tok *token) RR {
    rr := new(RR_A)
    rr.Hdr = hdr
    rr.Hdr.Rrtype = TypeA
    rr.A = net.ParseIP(tok.T[0])
}
func rdata_ns(hdr RR_Header, tok *token) RR {
    rr := new(RR_NS)
    rr.Hdr = hdr
    rr.Hdr.Rrtype = TypeNS
    rr.Ns = tok.T[0]
}
func rdata_cname(hdr RR_Header, tok *token) RR {
    rr := new(RR_CNAME)
    rr.Hdr = hdr
    rr.Hdr.Rrtype = TypeCNAME
    rr.Cname = tok.T[0]
}
func rdata_soa(hdr RR_Header, tok *token) RR {
    rr := new(RR_SOA)
    rr.Hdr = hdr
    rr.Hdr.Rrtype = TypeSOA
    rr.Ns = tok.T[0]
    rr.Mbox = tok.T[1]
    rr.Serial = uint32(tok.N[0])
    rr.Refresh = uint32(tok.N[1])
    rr.Retry = uint32(tok.N[2])
    rr.Expire = uint32(tok.N[3])
    rr.Minttl = uint32(tok.N[4])
}
func rdata_mx(hdr RR_Header, tok *token) RR {
    rr := new(RR_MX)
    rr.Hdr = hdr;
    rr.Hdr.Rrtype = TypeMX
    rr.Pref = uint16(tok.N[0])
    rr.Mx = tok.T[0]
}
func rdata_ds(hdr RR_Header, tok *token) RR {
    rr := new(RR_DS)
    rr.Hdr = hdr;
    rr.Hdr.Rrtype = TypeDS
    rr.KeyTag = uint16(tok.N[0])
    rr.Algorithm = uint8(tok.N[1])
    rr.DigestType = uint8(tok.N[2])
    rr.Digest = tok.T[0]
}
func rdata_dnskey(hdr RR_Header, tok *token) RR {
    rr := new(RR_DNSKEY)
    rr.Hdr = hdr;
    rr.Hdr.Rrtype = TypeDNSKEY
    rr.Flags = uint16(tok.N[0])
    rr.Protocol = uint8(tok.N[1])
    rr.Algorithm = uint8(tok.N[2])
    rr.PublicKey = tok.T[0]
}
func rdata_rrsig(hdr RR_Header, tok *token) RR {
    rr := new(RR_RRSIG)
    rr.Hdr = hdr;
    rr.Hdr.Rrtype = TypeRRSIG
    rr.TypeCovered = uint16(tok.N[0])
    rr.Algorithm = uint8(tok.N[1])
    rr.Labels = uint8(tok.N[2])
    rr.OrigTtl = uint32(tok.N[3])
    rr.Expiration = uint32(tok.N[4])
    rr.Inception = uint32(tok.N[5])
    rr.KeyTag = uint16(tok.N[6])
    rr.SignerName = tok.T[0]
    rr.Signature = tok.T[1]
}
