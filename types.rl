%%{
        machine z;

        action rdata_a {
            rr.(*RR_A).Hdr = *hdr
            rr.(*RR_A).A = net.ParseIP(data[mark:p])
        }
        action rdata_aaaa {
            rr.(*RR_AAAA).Hdr = *hdr
            rr.(*RR_AAAA).AAAA = net.ParseIP(data[mark:p])
        }
        action rdata_ns {
            rr.(*RR_NS).Hdr = *hdr
            rr.(*RR_NS).Ns = tok.T[0]
        }
        action rdata_cname {
            rr.(*RR_CNAME).Hdr = *hdr
            rr.(*RR_CNAME).Cname = tok.T[0]
        }
        action rdata_soa {
            rr.(*RR_SOA).Hdr = *hdr
            rr.(*RR_SOA).Ns = tok.T[0]
            rr.(*RR_SOA).Mbox = tok.T[1]
            rr.(*RR_SOA).Serial = uint32(tok.N[0])
            rr.(*RR_SOA).Refresh = uint32(tok.N[1])
            rr.(*RR_SOA).Retry = uint32(tok.N[2])
            rr.(*RR_SOA).Expire = uint32(tok.N[3])
            rr.(*RR_SOA).Minttl = uint32(tok.N[4])
        }
        action rdata_mx {
            rr.(*RR_MX).Hdr = *hdr;
            rr.(*RR_MX).Pref = uint16(tok.N[0])
            rr.(*RR_MX).Mx = tok.T[0]
        }
        action rdata_ds {
            rr.(*RR_DS).Hdr = *hdr;
            rr.(*RR_DS).KeyTag = uint16(tok.N[0])
            rr.(*RR_DS).Algorithm = uint8(tok.N[1])
            rr.(*RR_DS).DigestType = uint8(tok.N[2])
            rr.(*RR_DS).Digest = tok.T[0]
        }
        action rdata_dnskey {
            rr.(*RR_DNSKEY).Hdr = *hdr;
            rr.(*RR_DNSKEY).Flags = uint16(tok.N[0])
            rr.(*RR_DNSKEY).Protocol = uint8(tok.N[1])
            rr.(*RR_DNSKEY).Algorithm = uint8(tok.N[2])
            rr.(*RR_DNSKEY).PublicKey = tok.T[0]
        }
        action rdata_rrsig {
            rr.(*RR_RRSIG).Hdr = *hdr;
            rr.(*RR_RRSIG).TypeCovered = uint16(tok.N[0])
            rr.(*RR_RRSIG).Algorithm = uint8(tok.N[1])
            rr.(*RR_RRSIG).Labels = uint8(tok.N[2])
            rr.(*RR_RRSIG).OrigTtl = uint32(tok.N[3])
            rr.(*RR_RRSIG).Expiration = uint32(tok.N[4])
            rr.(*RR_RRSIG).Inception = uint32(tok.N[5])
            rr.(*RR_RRSIG).KeyTag = uint16(tok.N[6])
            rr.(*RR_RRSIG).SignerName = tok.T[0]
            rr.(*RR_RRSIG).Signature = tok.T[1]
        }
}%%
