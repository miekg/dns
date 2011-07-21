package dns

// Parse RRs
// With the thankful help of gdnsd and the Go examples for Ragel.
// 

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
func Zparse(q io.Reader) (z *Zone, err os.Error) {
        buf := make([]byte, _IOBUF) 
        n, err := q.Read(buf)
        if err != nil {
            return nil, err
        }
        buf = buf[:n]
        z = new(Zone)

        data := string(buf)
        cs, p, pe := 0, 0, len(data)
        ts, te, act := 0, 0, 0
//        top := 0
//        stack := make([]int, 100)
        eof := len(data)
        // keep Go happy
        ts = ts; te = te; act = act

        brace := false
        lines := 0
        mark := 0
        hdr := new(RR_Header)
        tok := newToken()
        var rr RR

        %%{
                action mark       { mark = p }
                action qname      { hdr.Name = data[mark:p] }
                action qclass     { hdr.Class = Str_class[data[mark:p]] }
                action defTtl     { /* ... */ }
                action setTtl     { ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
                action number     { tok.pushInt(data[mark:p]) }
                action text       { tok.pushString(data[mark:p]) }
                action set        { z.Push(rr); tok.reset(); println("Setting") }
                action openBrace  { if brace { println("Brace already open")} ; brace = true }
                action closeBrace { if !brace { println("Brace already closed")}; brace = false }
                action brace      { brace }
                action linecount  { lines++ }

                # Newlines
                nl = [\n]+ $linecount;

                # Comments, entire line. Shorter comments are handled in the 
                # 'bl' definition below.
                comment = ';' [^\n]*;

                bl = (
                    [ \t]+
                    | '(' $openBrace
                    | ')' $closeBrace
                    | (comment? nl)+ when brace
                )+ %mark;

                qclass      = ('IN'i|'CS'i|'CH'i|'HS'i|'ANY'i|'NONE'i) %qclass;
                chars       = [^; \t"\n\\)(];
                ttl         = digit+ >mark;
                qname       = chars+ %qname;
                tb          = (chars | ' ')+ $1 %0 %text;
                t           = chars+ $1 %0 %text;
                n           = [0-9]+ $1 %0 %number;

                lhs = qname? bl %defTtl (
                      (ttl %setTtl bl (qclass bl)?)
                    | (qclass bl (ttl %setTtl bl)?)
                )?;

                # RDATA definitions.
                include "types.rl";

                # RR definitions.
                rhs = (
                       ('AAAA'i      bl t) %rdata_aaaa
                     | ('A'i         bl t) %rdata_a
                     | ('NS'i        bl t) %rdata_ns
                     | ('CNAME'i     bl t) %rdata_cname 
                     | ('MX'i        bl n bl t) %rdata_mx
                     );
#                     'SOA'i;       bl; t; bl; t; bl; n; bl; n; bl; n; bl; n; bl; n => rdata_soa; { fret; };
#                *|;

                rr = lhs rhs %set;
                main := (rr? bl? ((comment? nl) when !brace))*;

                write init;
                write exec;
        }%%
        
        if eof > -1 {
                if cs < z_first_final {
                        // No clue what I'm doing what so ever
                        if p == pe {
                                println("unexpected eof")
                                return z, nil
                        } else {
                                println("error at position ", p, "\"",data[mark:p],"\"")
                                return z, nil
                        }
                }
        }
        return z, nil
}
