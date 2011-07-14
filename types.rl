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
}%%
