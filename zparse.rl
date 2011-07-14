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
        cs, p, pe, eof := 0, 0, len(data), len(data)
        j := 0; j = j // Needed for compile.
        k := 0; k = k // "
        mark := 0
        hdr := new(RR_Header)
        txt := make([]string, 10)
        num := make([]int, 10)

        %%{
                action mark      { mark = p }
                action qname     { hdr.Name = data[mark:p] }
                action number    { n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
                action text      { txt[k] = data[mark:p]; k++ }
                action textblank { txt[k] = data[mark:p]; k++ }
                action qclass    { hdr.Class = Str_class[data[mark:p]] }
                action defTtl    { /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
                action setTtl    { ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }

                action qtype    { 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }

                qclass      = ('IN'i|'CS'i|'CH'i|'HS'i|'ANY'i|'NONE'i) %qclass;
                ttl         = digit+ >mark;
                blank       = [ \t]+ %mark;
                qname       = [a-zA-Z0-9.\\]+ %qname;
                textblank   = [a-zA-Z0-9.\\ ]+ $1 %0 %textblank;
                text        = [a-zA-Z0-9.\\]+ $1 %0 %text;
                number      = [0-9]+ $1 %0 %number;

                lhs = qname? blank %defTtl (
                      (ttl %setTtl blank (qclass blank)?)
                    | (qclass blank (ttl %setTtl blank)?)
                )?;

                # RDATA definitions
                include "types.rl";

                # RR definitions
                rhs = (
                      ('A'i         %qtype blank text) %rdata_a
                    | ('NS'i        %qtype blank text) %rdata_ns
                    | ('CNAME'i     %qtype blank text) %rdata_cname
                    | ('SOA'i       %qtype blank text blank text blank number blank number blank number blank number blank number) %rdata_soa
                    | ('MX'i        %qtype blank number blank text) %rdata_mx
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
