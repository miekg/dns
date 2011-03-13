package dns

func New(i int) RR {
        var rr RR
        mk, known := rr_mk[i]
        if !known {
                rr = new(RR_RFC3597)
        } else {
                rr = mk()
        }

        rr.Header().Ttl = DefaultTtl
        rr.Header().Class = ClassINET
        rr.Header().Rrtype = uint16(i)
        switch t := rr.(type) {
        case *RR_TSIG:
                t.Hdr = RR_Header{Ttl: 0, Class: ClassANY, Rrtype: uint16(i)}
                t.Fudge = 300
        case *RR_OPT:
                t.Hdr = RR_Header{Name: "", Ttl: 0, Class: 0, Rrtype: uint16(i)}
                t.SetVersion(0)
                t.SetUDPSize(DefaultMsgSize)
        }
        return rr
}
