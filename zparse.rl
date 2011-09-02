package dns

// Parse RRs
// With the thankful help of gdnsd and the Go examples for Ragel.

import (
    "os"
    "io"
    "net"
    "time"
    "strings"
    "strconv"
)

const _IOBUF = MaxMsgSize

// A Parser represents a DNS parser for a 
// particular input stream. Each parsed RR will be returned
// on the channel RR.
type Parser struct {
        // nothing here yet
        buf    []byte
        RR     chan RR
        Error  chan *ParseError
}

type ParseError struct {
        Error string
        name  string
        line  int
}

func (e *ParseError) String() string {
        s := e.Error + ": \""  + e.name + "\" at line: " + strconv.Itoa(e.line)
        return s
}

// NewParser creates a new DNS file parser from r.
// Need sliding window stuff TODO.
func NewParser(r io.Reader) *Parser {
        buf := make([]byte, _IOBUF)
        n, err := r.Read(buf)
        if err != nil {
            return nil
        }
        if buf[n-1] != '\n' {
            buf[n] = '\n'
            n++
        }
        buf = buf[:n]
        p := new(Parser)
        p.buf = buf
        p.RR = make(chan RR) 
        p.Error = make(chan ParseError)
        return p
}

// Translate the RRSIG's incep. and expir. times from 
// string values ("20110403154150") to an integer.
// Taking into account serial arithmetic (RFC 1982)
func dateToTime(s string) (uint32, os.Error) {
    t, e := time.Parse("20060102150405", s)
    if e != nil {
        return 0, e
    }
    mod := t.Seconds() / Year68
    ti := uint32(t.Seconds() - (mod * Year68))
    return ti, nil
}

// Return the rdata fields as a string slice. 
// All starting whitespace is deleted.
// If i is 0 no spaces are deleted from the final rdfs.
func fields(s string, i int) (rdf []string) {
    rdf = strings.Fields(s)
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

%%{
        machine z;
        write data;
}%%

// First will return the first RR found when parsing.
func (zp *Parser) First() (RR, os.Error) {
    // defer close something
    go run(zp, quit)
    select {
    case r := <-zp.RR:
        return r, nil
    case e := <-zp.Error:
        return nil, e
    }
}


// Run starts the parsers and returns the parsed Rr on the RR channel.
// Errors are return on the Error channel. After an error the parsing stops.
func (zp *Parser) Run(quit chan bool) {
    go run(zp, quit)
}

// Run parses an DNS master zone file. It returns each parsed RR
// on the channel as soon as it has been parsed.
func run(zp *Parser, quit chan bool) (err os.Error) {
        data := string(zp.buf)
        cs, p, pe := 0, 0, len(data)
        eof := len(data)

        defer close(zp.Error)
        defer close(zp.RR)

//        brace := false
        l := 1  // or... 0?
        mark := 0
        var hdr RR_Header
        // Need to listen to the quit channel

        %%{

                action mark       { mark = p }
                action lineCount  { l++ }
                action setQname   { if ! IsDomainName(data[mark:p]) {
                                            zp.Error <- &ParseError{Error: "bad qname: " + data[mark:p], line: l}
                                            return
                                    }
                                    hdr.Name = data[mark:p]
                                  }
                action errQclass  { zp.Error <- &ParseError{Error: "bad qclass: " + data[mark:p], line: l}; return }
                action setQclass  { hdr.Class = str_class[data[mark:p]] }
                action defTtl     { /* ... */ }
                action errTtl     { /* ... */ }
                action setTtl     { i, _ := strconv.Atoui(data[mark:p]); hdr.Ttl = uint32(i) }
#                action openBrace  { if brace { println("Brace already open")} ; brace = true }
#                action closeBrace { if !brace { println("Brace already closed")}; brace = false }
#                action brace      { brace }

                include "types.rl";

                nl  = [\n]+ $lineCount;
                comment = ';' [^\n]*;
                ttl = digit+ >mark; #@err(errTtl)
#                bl  = ( [ \t]+
#                    | '(' $openBrace
#                    | ')' $closeBrace
#                    | (comment? nl)+ when brace
#                )+;
                bl = [ \t]+;

                rdata = [^\n]+ >mark;
                qname  = [a-zA-Z0-9.\-_*]+ >mark %setQname;
                qclass = ('IN'i|'CH'i|'HS'i) >mark %setQclass; # @err(errQclass);

                lhs = qname? bl %defTtl (
                      (ttl %setTtl bl (qclass bl)?)
                    | (qclass bl (ttl %setTtl bl)?)
                )?;

                rhs = (
                      ( 'A'i        bl rdata ) %setA
                    | ( 'PTR'i      bl rdata ) %setPTR
                    | ( 'TXT'i      bl rdata ) %setTXT
                    | ( 'SRV'i      bl rdata ) %setSRV
                    | ( 'CERT'i     bl rdata ) %setCERT
                    | ( 'NAPTR'i    bl rdata ) %setNAPTR
                    | ( 'AAAA'i     bl rdata ) %setAAAA
                    | ( 'SOA'i      bl rdata ) %setSOA
                    | ( 'CNAME'i    bl rdata ) %setCNAME
                    | ( 'DNAME'i    bl rdata ) %setDNAME
                    | ( 'NS'i       bl rdata ) %setNS
                    | ( 'MX'i       bl rdata ) %setMX
                    | ( 'DS'i       bl rdata ) %setDS
                    | ( 'DLV'i      bl rdata ) %setDLV
                    | ( 'TA'i       bl rdata ) %setTA
                    | ( 'DNSKEY'i   bl rdata ) %setDNSKEY
                    | ( 'RRSIG'i    bl rdata ) %setRRSIG
                    | ( 'NSEC'i     bl rdata ) %setNSEC
                    | ( 'NSEC3'i    bl rdata ) %setNSEC3
                    | ( 'SSHFP'i    bl rdata ) %setSSHFP
                    | ( 'NSEC3PARAM'i bl rdata ) %setNSEC3PARAM
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
                                println("unexpected eof at line ", l)
                                return
                        } else {
                                println("error at position ", p, "\"",data[mark:p],"\" at line ", l)
                                return
                        }
                }
        }
        return
}
