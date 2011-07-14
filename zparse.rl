package dns

import (
    "os"
    "fmt"
)

%%{
        machine z;
        write data;
}%%

func zparse(data string) (res int, err os.Error) {
        cs, p, pe, eof := 0, 0, len(data), len(data)

        %%{
                action out    { fmt.Printf("%s\n", data) }
                action defTtl { fmt.Printf("%s\n", data) }
                action setTtl { fmt.Printf("%s\n", data) }

                qtype = ('IN'i|'CS'i|'CH'i|'HS'i|'ANY'i|'NONE'i);
                ttl = digit+;
                blank = [ \t]+;
                qname = any+;

                # RDATA definition
                rdata_a = any+;
                rdata_dnskey = any+;

                lhs = qname? blank %defTtl (
                      (ttl %setTtl blank (qtype blank)?)
                    | (qtype blank (ttl %setTtl blank)?)
                )?;

                # RR definitions
                rhs = (
                      ('A'i         blank   rdata_a) %out
                    | ('DNSKEY'i    blank   rdata_dnskey) %out
                );

                rr = lhs rhs;
            
                main := rr+;

                write init;
                write exec;
        }%%

        if cs < z_first_final {
                // No clue what I'm doing what so ever
                if p == pe {
                        return 0, os.ErrorString("unexpected eof")
                } else {
                        return 0, os.ErrorString(fmt.Sprintf("error at position %d", p))
                }
        }
        return 0 ,nil
}
