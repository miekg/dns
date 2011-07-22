package dns

// Parse RRs
// With the thankful help of gdnsd and the Go examples for Ragel.
// 

import (
    "os"
    "io"
    "net"
    "strings"
    "strconv"
)

//const _IOBUF = 65365
const _IOBUF = 3e7

// Return the rdata fields as a slice. All starting whitespace deleted
func fields(s string, i int) (rdf []string) {
    rdf = strings.Fields(strings.TrimSpace(s))
    for i, _ := range rdf {
        rdf[i] = strings.TrimSpace(rdf[i])
    }
    // every rdf above i should be stiched together without
    // the spaces
    return
}

func atoi(s string) uint {
    i, err :=  strconv.Atoui(s)
    if err != nil {
        panic("not a number: " + s + " " + err.String())
    }
    return i
}

/*
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
*/

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
        eof := len(data)

//        brace := false
        lines := 0
        mark := 0
        hdr := new(RR_Header)

        %%{
                action mark       { mark = p }
                action setQname   { hdr.Name = data[mark:p] }
                action setQclass  { hdr.Class = Str_class[data[mark:p]] }
                action defTtl     { /* ... */ }
                action setTtl     { ttl := atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
                action lineCount  { lines++ }

#                action openBrace  { if brace { println("Brace already open")} ; brace = true }
#                action closeBrace { if !brace { println("Brace already closed")}; brace = false }
#                action brace      { brace }

                include "types.rl";

                nl  = [\n]+ $lineCount;
                comment = ';' [^\n]*;
                ttl = digit+ >mark;
#                bl  = ( [ \t]+
#                    | '(' $openBrace
#                    | ')' $closeBrace
#                    | (comment? nl)+ when brace
#                )+ %mark;
                bl = [ \t]+;

#                rdata  = [a-zA-Z0-9.]+ >mark;
                rdata = [^\n]+ >mark;
                qname  = [a-zA-Z0-9.\-_]+ >mark %setQname;
                qclass = ('IN'i|'CH'i|'HS'i) >mark %setQclass;

                lhs = qname? bl %defTtl (
                      (ttl %setTtl bl (qclass bl)?)
                    | (qclass bl (ttl %setTtl bl)?)
                )?;

                rhs = (
                      ( 'A'i        rdata ) %setA
                    | ( 'AAAA'i     rdata ) %setAAAA
                    | ( 'SOA'i      rdata ) %setSOA
                    | ( 'CNAME'i    rdata ) %setCNAME
                    | ( 'NS'i       rdata ) %setNS
                    | ( 'MX'i       rdata ) %setMX
                );

                rr = lhs rhs;
#                main := (rr? bl? ((comment? nl) when !brace))*;
                main := (rr? nl)*;

                write init;
                write exec;
        }%%
        
        if eof > -1 {
                if cs < z_first_final {
                        // No clue what I'm doing what so ever
                        if p == pe {
                                println("unexpected eof at line", lines)
                                return z, nil
                        } else {
                                println("error at position ", p, "\"",data[mark:p],"\" at line ", lines)
                                return z, nil
                        }
                }
        }
        return z, nil
}
