%%{
        machine z;

        action rdata_a {
            r.(*RR_A).Hdr = *hdr
            r.(*RR_A).A = net.ParseIP(data[mark:p])
        }
        action rdata_ns {
            r.(*RR_NS).Hdr = *hdr
            r.(*RR_NS).Ns = tok.T[0]
        }
        action rdata_cname {
            r.(*RR_CNAME).Hdr = *hdr
            r.(*RR_CNAME).Cname = tok.T[0]
        }
        action rdata_soa {
            r.(*RR_SOA).Hdr = *hdr
            r.(*RR_SOA).Ns = tok.T[0]
            r.(*RR_SOA).Mbox = tok.T[1]
            r.(*RR_SOA).Serial = uint32(tok.N[0])
            r.(*RR_SOA).Refresh = uint32(tok.N[1])
            r.(*RR_SOA).Retry = uint32(tok.N[2])
            r.(*RR_SOA).Expire = uint32(tok.N[3])
            r.(*RR_SOA).Minttl = uint32(tok.N[4])
        }
        action rdata_mx {
            r.(*RR_MX).Hdr = *hdr;
            r.(*RR_MX).Pref = uint16(tok.N[0])
            r.(*RR_MX).Mx = tok.T[0]
        }
        action rdata_ds {
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(tok.N[0])
            r.(*RR_DS).Algorithm = uint8(tok.N[1])
            r.(*RR_DS).DigestType = uint8(tok.N[2])
            r.(*RR_DS).Digest = tok.T[0]
        }
        action rdata_dnskey {
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(tok.N[0])
            r.(*RR_DNSKEY).Protocol = uint8(tok.N[1])
            r.(*RR_DNSKEY).Algorithm = uint8(tok.N[2])
            r.(*RR_DNSKEY).PublicKey = tok.T[0]
        }
        action rdata_rrsig {
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(tok.N[0])
            r.(*RR_RRSIG).Algorithm = uint8(tok.N[1])
            r.(*RR_RRSIG).Labels = uint8(tok.N[2])
            r.(*RR_RRSIG).OrigTtl = uint32(tok.N[3])
            r.(*RR_RRSIG).Expiration = uint32(tok.N[4])
            r.(*RR_RRSIG).Inception = uint32(tok.N[5])
            r.(*RR_RRSIG).KeyTag = uint16(tok.N[6])
            r.(*RR_RRSIG).SignerName = tok.T[0]
            r.(*RR_RRSIG).Signature = tok.T[1]
        }
}%%
