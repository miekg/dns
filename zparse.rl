package dns

// Parse RRs
// With the thankful help of gdnsd and the Go examples for Ragel 

import (
    "os"
    "io"
    "net"
    "strconv"
)

const _RDATAMAX = 7
const _IOBUF = 65365

// Save up tokens, after we've seen the entire rdata
// we can use this.
type token struct {
    T []string      // text
    N []int         // number
    ti int          // text counter
    ni int          // number counter
}

func newToken() *token {
    to := new(token)
    to.T = make([]string, _RDATAMAX)
    to.N = make([]int, _RDATAMAX)
    to.ni, to.ti = 0, 0
    return to
}

// Only push functions are provided. Reading is done, by directly
// accessing the members (T and N). See types.rl.
func (to *token) pushInt(s string) {
    i, err := strconv.Atoi(s)
    if err != nil {
        panic("Failure to parse to int: " + s)
    }
    to.N[to.ni] = i
    to.ni++
    if to.ni > _RDATAMAX {
        panic("Too much rdata (int)")
    }
}

func (to *token) pushString(s string) {
    to.T[to.ti] = s
    to.ti++
    if to.ti > _RDATAMAX {
        panic("Too much rdata (string)")
    }
}

func (to *token) reset() {
    to.ni, to.ti = 0, 0
}

%%{
        machine z;
        write data;
}%%

// SetString
// All the NewReader stuff is expensive...
// only works for short io.Readers as we put the whole thing
// in a string -- needs to be extended for large files (sliding window).
func Zparse(q io.Reader) (rr RR, err os.Error) {
        buf := make([]byte, _IOBUF) 
        n, err := q.Read(buf)
        if err != nil {
            return nil, err
        }
        buf = buf[:n]

        data := string(buf)
        cs, p, pe, eof := 0, 0, len(data), len(data)
        mark := 0
        hdr := new(RR_Header)
        tok := newToken()

        %%{
                # can't do comments yet
                action mark      { mark = p }
                action qname     { hdr.Name = data[mark:p] }
                action qclass    { hdr.Class = Str_class[data[mark:p]] }
                action defTtl    { /* ... */ }
                action setTtl    { ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
                action number    { tok.pushInt(data[mark:p]) }
                action text      { tok.pushString(data[mark:p]) }
                action textblank { tok.pushString(data[mark:p]) }

                action qtype    { 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    rr = mk()
                    hdr.Rrtype = i
                }

                qclass      = ('IN'i|'CS'i|'CH'i|'HS'i|'ANY'i|'NONE'i) %qclass;
                ttl         = digit+ >mark;
                bl          = [ \t]+ %mark;
                qname       = [a-zA-Z0-9.\\]+ %qname;
                # If I use this in the definitions at the end, things break...
                tb          = [a-zA-Z0-9.\\ ]+ $1 %0 %textblank;
#                t           = [a-zA-Z0-9.\\]+ $1 %0 %text;
                t           = [a-zA-Z0-9.\\/+=]+ $1 %0 %text;
                n           = [0-9]+ $1 %0 %number;
                comment     = /^;/;

                lhs = qname? bl %defTtl (
                      (ttl %setTtl bl (qclass bl)?)
                    | (qclass bl (ttl %setTtl bl)?)
                )?;

                # RDATA definitions
                include "types.rl";

                # RR definitions
                rhs = (
                       ('A'i         %qtype bl t) %rdata_a
                     | ('NS'i        %qtype bl t) %rdata_ns
                     | ('CNAME'i     %qtype bl t) %rdata_cname
                     | ('SOA'i       %qtype bl t bl t bl n bl n bl n bl n bl n) %rdata_soa
                     | ('MX'i        %qtype bl n bl t) %rdata_mx
                     | ('DS'i        %qtype bl n bl n bl n bl t) %rdata_ds
                     | ('DNSKEY'i    %qtype bl n bl n bl n bl t) %rdata_dnskey
                     | ('RRSIG'i     %qtype bl n bl n bl n bl n bl n bl n bl n bl t bl t) %rdata_rrsig
                );

                rr = lhs rhs;
                main := rr+;

                write init;
                write exec;
        }%%

        if cs < z_first_final {
                // No clue what I'm doing what so ever
                if p == pe {
                        //return nil, os.ErrorString("unexpected eof")
                        return nil, nil
                } else {
                        //return nil, os.ErrorString(fmt.Sprintf("error at position %d", p))
                        return nil, nil
                }
        }
        return rr, nil
}
