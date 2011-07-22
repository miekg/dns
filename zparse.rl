package dns

// Parse RRs
// With the thankful help of gdnsd and the Go examples for Ragel.

import (
    "os"
    "io"
    "net"
    "strings"
    "strconv"
)

//const _IOBUF = 65365
const _IOBUF = 3e7

// Return the rdata fields as a string slice. 
// All starting whitespace is deleted.
// If i is 0 no space are deleted from the final rdfs
func fields(s string, i int) (rdf []string) {
    rdf = strings.Fields(strings.TrimSpace(s))
    for i, _ := range rdf {
        rdf[i] = strings.TrimSpace(rdf[i])
    }
    if i > 0 && len(rdf) > i {
        // The last rdf contained embedded spaces, glue it back together.
        for j := i; j < len(rdf); j++ {
            rdf[i-1] += rdf[j]
        }
    }
    return
}

// Wrapper for strconv.Atoi*().
func atoi(s string) uint {
    i, err :=  strconv.Atoui(s)
    if err != nil {
        panic("not a number: " + s + " " + err.String())
    }
    return i
}

%%{
        machine z;
        write data;
}%%

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
        // guardian
        if data[len(data)-1] != '\n' {
            data += "\n"
        }
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
#                )+;
                bl = [ \t]+;

                rdata = [^\n]+ >mark;
                qname  = [a-zA-Z0-9.\-_]+ >mark %setQname;
                qclass = ('IN'i|'CH'i|'HS'i) >mark %setQclass;

                lhs = qname? bl %defTtl (
                      (ttl %setTtl bl (qclass bl)?)
                    | (qclass bl (ttl %setTtl bl)?)
                )?;

                rhs = (
                      ( 'A'i        rdata ) %setA
                    | ( 'PTR'i      rdata ) %setPTR
                    | ( 'TXT'i      rdata ) %setTXT
                    | ( 'SRV'i      rdata ) %setSRV
                    | ( 'CERT'i     rdata ) %setCERT
                    | ( 'NAPTR'i    rdata ) %setNAPTR
                    | ( 'AAAA'i     rdata ) %setAAAA
                    | ( 'SOA'i      rdata ) %setSOA
                    | ( 'CNAME'i    rdata ) %setCNAME
                    | ( 'DNAME'i    rdata ) %setDNAME
                    | ( 'NS'i       rdata ) %setNS
                    | ( 'MX'i       rdata ) %setMX
                    | ( 'DS'i       rdata ) %setDS
                    | ( 'DLV'i      rdata ) %setDLV
                    | ( 'TA'i       rdata ) %setTA
                    | ( 'DNSKEY'i   rdata ) %setDNSKEY
                    | ( 'RRSIG'i    rdata ) %setRRSIG
                    | ( 'NSEC'i     rdata ) %setNSEC
                    | ( 'NSEC3'i    rdata ) %setNSEC3
                    | ( 'NSEC3PARAM'i rdata ) %setNSEC3PARAM
                );

                rr = lhs rhs;
#                main := (rr? bl? ((comment? nl) when !brace))*;
                main := ((rr?|comment?) nl)*;

                write init;
                write exec;
        }%%
        
        if eof > -1 {
                if cs < z_first_final {
                        // No clue what I'm doing what so ever
                        if p == pe {
        println("p", p, "pe", pe)
        println("cs", cs, "z_first_final", z_first_final)
                                println("unexpected eof at line ", lines)
                                return z, nil
                        } else {
                                println("error at position ", p, "\"",data[mark:p],"\" at line ", lines)
                                return z, nil
                        }
                }
        }
        return z, nil
}
