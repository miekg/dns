%%{
        machine z;

        action rdata_a {
            r.(*RR_A).Hdr = *hdr
            r.(*RR_A).A = net.ParseIP(data[mark:p])
        }
        action rdata_ns {
            r.(*RR_NS).Hdr = *hdr
            r.(*RR_NS).Ns = txt[0]
        }
        action rdata_cname {
            r.(*RR_CNAME).Hdr = *hdr
            r.(*RR_CNAME).Cname = txt[0]
        }
        action rdata_soa {
            r.(*RR_SOA).Hdr = *hdr
            r.(*RR_SOA).Ns = txt[0]
            r.(*RR_SOA).Mbox = txt[1]
            r.(*RR_SOA).Serial = uint32(num[0])
            r.(*RR_SOA).Refresh = uint32(num[1])
            r.(*RR_SOA).Retry = uint32(num[2])
            r.(*RR_SOA).Expire = uint32(num[3])
            r.(*RR_SOA).Minttl = uint32(num[4])
        }
        action rdata_mx {
            r.(*RR_MX).Hdr = *hdr;
            r.(*RR_MX).Pref = uint16(num[0])
            r.(*RR_MX).Mx = txt[0]
        }
        action rdata_ds {
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
        action rdata_dnskey {
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
        action rdata_rrsig {
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
}%%
