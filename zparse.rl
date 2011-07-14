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

func Zparse(data string) (r RR, err os.Error) {
        cs, p, pe, eof := 0, 0, len(data), len(data)
        j := 0; j = j // Needed for compile.
        k := 0; k = k // "
        mark := 0
        hdr := new(RR_Header)
        txt := make([]string, 7)
        num := make([]int, 7)

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
                b           = [ \t]+ %mark;
                qname       = [a-zA-Z0-9.\\]+ %qname;
                tb          = [a-zA-Z0-9.\\ ]+ $1 %0 %textblank;
                t           = [a-zA-Z0-9.\\]+ $1 %0 %text;
                n           = [0-9]+ $1 %0 %number;

                lhs = qname? b %defTtl (
                      (ttl %setTtl b (qclass b)?)
                    | (qclass b (ttl %setTtl b)?)
                )?;

                # RDATA definitions
                include "types.rl";

                # RR definitions
                rhs = (
                      ('A'i         %qtype b t) %rdata_a
                    | ('NS'i        %qtype b t) %rdata_ns
                    | ('CNAME'i     %qtype b t) %rdata_cname
                    | ('SOA'i       %qtype b tb t b n b n b n b n b n) %rdata_soa
                    | ('MX'i        %qtype b n b t) %rdata_mx
                    | ('DS'i        %qtype b n b n b n b tb) %rdata_ds
                    | ('DNSKEY'i    %qtype b n b n b n b tb) %rdata_dnskey
                    | ('RRSIG'i     %qtype b n b n b n b n b n b n b n b t b tb) %rdata_rrsig
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
