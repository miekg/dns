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

func rdata_aaaa(hdr RR_Header, tok *token) RR {
        rr := new(RR_AAAA)
        rr.Hdr = hdr
        rr.Hdr.Rrtype = TypeAAAA
        rr.AAAA = net.ParseIP(tok.T[0])
        return rr
}

func rdata_a(hdr RR_Header, tok *token) RR {
        rr := new(RR_A)
        rr.Hdr = hdr
        rr.Hdr.Rrtype = TypeA
        rr.A = net.ParseIP(tok.T[0])
        return rr
}

func rdata_ns(hdr RR_Header, tok *token) RR {
        rr := new(RR_NS)
        rr.Hdr = hdr
        rr.Hdr.Rrtype = TypeNS
        rr.Ns = tok.T[0]
        return rr
}

func rdata_cname(hdr RR_Header, tok *token) RR {
        rr := new(RR_CNAME)
        rr.Hdr = hdr
        rr.Hdr.Rrtype = TypeCNAME
        rr.Cname = tok.T[0]
        return rr
}

func rdata_soa(hdr RR_Header, tok *token) RR {
        rr := new(RR_SOA)
        rr.Hdr = hdr
        rr.Hdr.Rrtype = TypeSOA
        rr.Ns = tok.T[0]
        rr.Mbox = tok.T[1]
        rr.Serial = uint32(tok.N[0])
        rr.Refresh = uint32(tok.N[1])
        rr.Retry = uint32(tok.N[2])
        rr.Expire = uint32(tok.N[3])
        rr.Minttl = uint32(tok.N[4])
        return rr
}

func rdata_mx(hdr RR_Header, tok *token) RR {
        rr := new(RR_MX)
        rr.Hdr = hdr;
        rr.Hdr.Rrtype = TypeMX
        rr.Pref = uint16(tok.N[0])
        rr.Mx = tok.T[0]
        return rr
}

func rdata_ds(hdr RR_Header, tok *token) RR {
        rr := new(RR_DS)
        rr.Hdr = hdr;
        rr.Hdr.Rrtype = TypeDS
        rr.KeyTag = uint16(tok.N[0])
        rr.Algorithm = uint8(tok.N[1])
        rr.DigestType = uint8(tok.N[2])
        rr.Digest = tok.T[0]
        return rr
}

func rdata_dnskey(hdr RR_Header, tok *token) RR {
        rr := new(RR_DNSKEY)
        rr.Hdr = hdr;
        rr.Hdr.Rrtype = TypeDNSKEY
        rr.Flags = uint16(tok.N[0])
        rr.Protocol = uint8(tok.N[1])
        rr.Algorithm = uint8(tok.N[2])
        rr.PublicKey = tok.T[0]
        return rr
}

func rdata_rrsig(hdr RR_Header, tok *token) RR {
        rr := new(RR_RRSIG)
        rr.Hdr = hdr;
        rr.Hdr.Rrtype = TypeRRSIG
        rr.TypeCovered = uint16(tok.N[0])
        rr.Algorithm = uint8(tok.N[1])
        rr.Labels = uint8(tok.N[2])
        rr.OrigTtl = uint32(tok.N[3])
        rr.Expiration = uint32(tok.N[4])
        rr.Inception = uint32(tok.N[5])
        rr.KeyTag = uint16(tok.N[6])
        rr.SignerName = tok.T[0]
        rr.Signature = tok.T[1]
        return rr
}

func set(r RR, z *Zone, tok *token) {
        println("setting",r.String())
        z.Push(r)
        tok.reset()
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
        // keep Go happy - need to fix this ofcourse
        ts = ts; te = te; act = act

        brace := false
        lines := 0
        mark := 0
        hdr := new(RR_Header)
        tok := newToken()

        %%{
                action mark       { mark = p }
                action qname      { hdr.Name = data[mark:p] }
                action qclass     { hdr.Class = Str_class[data[mark:p]] }
                action defTtl     { /* ... */ }
                action setTtl     { ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
                action number     { tok.pushInt(data[mark:p]) }
                action text       { tok.pushString(data[mark:p]) }
                action openBrace  { if brace { println("Brace already open")} ; brace = true }
                action closeBrace { if !brace { println("Brace already closed")}; brace = false }
                action brace      { brace }
                action linecount  { lines++ }

                # Newlines
                nl = [\n]+ $linecount;

                # Comments, entire line. Shorter comments are handled in the 
                # 'bl' definition below. TODO
                comment = ';' [^\n]*;

                bl = (
                    [ \t]+
                    | '(' $openBrace
                    | ')' $closeBrace
                    | (comment? nl)+ when brace
                )+ %mark;

#                chars       = [^; \t"\n\\)(];
                ws          = [ \t]+;
                qclass      = ('IN'i|'CS'i|'CH'i|'HS'i|'ANY'i|'NONE'i) %qclass;
                qname       = [a-zA-Z0-9_\-.\+=/]+ %qname;
                t           = [a-zA-Z0-9_\-.:\+=/]+ $1 %0 >mark %text;
                # now if I use this, I get an assertion failure in Ragel ... :-)
                tb          = [a-zA-Z0-9_\-.: ]+ $1 %0 %text;
                n           = [0-9]+ $1 %0 %number;
                ttl         = digit+ >mark;

                # Not even sure this works okay
                lhs = qname? bl %defTtl (
                      (ttl %setTtl bl (qclass bl)?)
                    | (qclass bl (ttl %setTtl bl)?)
                )?;

                main := |*
                    lhs 'A'i        bl t nl      => { r := rdata_a(*hdr, tok); set(r, z, tok); };
                    lhs 'NS'i       bl t nl      => { r := rdata_ns(*hdr, tok); set(r, z, tok); };
                    lhs 'CNAME'i    bl t nl      => { r := rdata_cname(*hdr, tok); set(r, z, tok); };
                    lhs 'AAAA'i     bl t nl      => { r := rdata_aaaa(*hdr, tok); set(r, z, tok); };
                    lhs 'MX'i       bl n bl t nl => { r := rdata_mx(*hdr, tok); set(r, z, tok); };
                    lhs 'SOA'i      bl t bl t bl n bl n bl n bl n bl n nl           => { r := rdata_soa(*hdr, tok); set(r, z, tok); };
                    lhs 'DS'i       bl n bl n bl n bl t nl                          => { r := rdata_ds(*hdr, tok); set(r, z, tok); };
                    lhs 'DNSKEY'i   bl n bl n bl n bl t nl                          => { r := rdata_dnskey(*hdr, tok); set(r, z, tok); };
                    lhs 'RRSIG'i    bl n bl n bl n bl n bl n bl n bl n bl t bl t nl => { r := rdata_rrsig(*hdr, tok); set(r, z, tok); };
                *|;

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
