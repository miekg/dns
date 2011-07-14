package dns

// Parse RRs
// With the thankful help of gdnsd and the Go examples for Ragel 

import (
    "os"
    "fmt"
    "net"
    "strconv"
)

%%{
        machine z;
        write data;
}%%

func zparse(data string) (r RR, err os.Error) {
        cs, p, pe := 0, 0, len(data)
        mark := 0
        eof := len(data)
        hdr := new(RR_Header)

        %%{
                action mark   { mark = p }
                action rdata_out    { fmt.Printf("rdata {%s}\n", data[mark:p]) }
                action qname_out { 
                    fmt.Printf("qname {%s}\n", data[mark:p])
                    hdr.Name = data[mark:p] 
                }
                action qclass_out { 
                    fmt.Printf("qclass {%s}\n", data[mark:p])
                    hdr.Class = Str_class[data[mark:p]]
                    println(hdr.Class)
                }
                action qtype_out { 
                    fmt.Printf("qtype {%s}\n", data[mark:p])
                }

                action defTtl { fmt.Printf("defttl {%s}\n", data[mark:p]) }
                action setTtl { 
                    fmt.Printf("ttl {%s}\n", data[mark:p])
                    ttl, _ :=  strconv.Atoi(data[mark:p])
                    hdr.Ttl = uint32(ttl)
                }

                action rdata_a {
                    r = new(RR_A)
                    r.(*RR_A).Hdr = *hdr
                    r.(*RR_A).Hdr.Rrtype = TypeA
                    r.(*RR_A).A = net.ParseIP(data[mark:p])
                    println("Setting")
                }


                qtype = ('IN'i|'CS'i|'CH'i|'HS'i|'ANY'i|'NONE'i) %qclass_out;
                ttl = digit+ >mark;
                blank = [ \t]+ %mark;
                qname = [a-zA-Z0-9.\\]+ %qname_out;

                # RDATA definitions
                rdata_a = any+ $1 %0 %rdata_a;
                rdata_dnskey = [a-z0-9.\\]+;

                lhs = qname? blank %defTtl (
                      (ttl %setTtl blank (qtype blank)?)
                    | (qtype blank (ttl %setTtl blank)?)
                )?;

                # RR definitions
                rhs = (
                      ('A'i %qtype_out         blank   rdata_a)
                    | ('DNSKEY'i %qtype_out    blank   rdata_dnskey)
                );

                rr = lhs rhs;
            
                main := rr+;

                write init;
                write exec;
        }%%

        if cs < z_first_final {
                // No clue what I'm doing what so ever
                if p == pe {
                        return nil, os.ErrorString("unexpected eof")
                } else {
                        return nil, os.ErrorString(fmt.Sprintf("error at position %d", p))
                }
        }
        return r ,nil
}
