%%{

    machine z;

    action setA {
        rdf := fields(data[mark:p], 1)
        rr := new(RR_A)
        rr.Hdr = *hdr
        rr.Hdr.Rrtype = TypeA
        rr.A = net.ParseIP(rdf[0])
        z.Push(rr)
    }

    action setAAAA {
        rdf := fields(data[mark:p], 1)
        rr := new(RR_AAAA)
        rr.Hdr = *hdr
        rr.Hdr.Rrtype = TypeAAAA
        rr.AAAA = net.ParseIP(rdf[0])
        z.Push(rr)
    }

    action setNS {
        rdf := fields(data[mark:p], 1)
        rr := new(RR_NS)
        rr.Hdr = *hdr
        rr.Hdr.Rrtype = TypeNS
        rr.Ns = rdf[0]
        z.Push(rr)
    }

    action setMX {
        rdf := fields(data[mark:p], 2)
        rr := new(RR_MX)
        rr.Hdr = *hdr
        rr.Hdr.Rrtype = TypeMX
        rr.Pref = uint16(atoi(rdf[0]))
        rr.Mx = rdf[1]
        z.Push(rr)
    }


    action setCNAME {
        rdf := fields(data[mark:p], 1)
        rr := new(RR_CNAME)
        rr.Hdr = *hdr
        rr.Hdr.Rrtype = TypeCNAME
        rr.Cname = rdf[0]
        z.Push(rr)
    }

    action setSOA {
        println("SOA")
        rdf := fields(data[mark:p], 7)
        rr := new(RR_SOA)
        rr.Hdr = *hdr
        rr.Hdr.Rrtype = TypeSOA
        rr.Ns = rdf[0]
        rr.Mbox = rdf[1]
        rr.Serial = uint32(atoi(rdf[2]))
        rr.Refresh = uint32(atoi(rdf[3]))
        rr.Retry = uint32(atoi(rdf[4]))
        rr.Expire = uint32(atoi(rdf[5]))
        rr.Minttl = uint32(atoi(rdf[6]))
        z.Push(rr)
}

}%%
