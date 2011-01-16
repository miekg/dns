// Copyright Miek Gieben 2011
// Heavily influenced by the zone-parser from NSD

%{ 

package dns

import (
    "fmt"
)

// A yacc parser for DNS Resource Records contained in strings

%}

%union {
    val     string
    rrtype  uint16
    class   uint16
    ttl     uint16

}

/*
 * Types known to package dns
 */
%token <rrtype> Y_A Y_NS 

/*
 * Other elements of the Resource Records
 */
%token <ttl>    TTL
%token <class>  CLASS
%token <val>    VAL
%%
rr:     name TTL CLASS rrtype
  {
  
  };

name:   label
    |   name '.' label

label:  VAL

rrtype: 
      /* All supported RR types */
        Y_A
    |   Y_NS
%%

type DnsLex int

func (DnsLex) Lex(lval *yySymType) int {

    // yylval.rrtype = Str_rr($XX)  //give back TypeA, TypeNS
    // return Y_A this should be the token, another map?

//func scan(s string) (string, int) {
        if len(s) == 0 { 
                println("a bit short")
        }
	raw := []byte(s)
	chunk := ""
        off := 0
        brace := 0
redo:
	for off < len(raw) {
		c := raw[off]
//                println(c, string(c))
		switch c {
                case '\n':
                        // normal case??
                        if brace > 0 {
                                off++
                                continue
                        }
		case '.':
//                        println("off", off)
                        if off == 0 {
                                print("DOT")
				return ".", off + 1
                        } else {
                                return chunk, off
                        }
                case ' ','\t':
                        if brace != 0 {
                                off++
                                continue
                        }
                        // eat whitespace
                        // Look at next char
                        if raw[off+1] == ' ' {
                                off++
                                continue
                        } else {
                                // if chunk is empty, we have skipped whitespace, and seen nothing
                                if len(chunk) == 0 {
                                        off++
                                        goto redo
                                }
                                print("VAL ")
                                return chunk, off
                        }
                case '(':
                        brace++
                        off++
                        continue
                case ')':
                        brace--
                        if brace < 0 {
                                println("syntax error")
                        }
                        off++
                        continue
		}
                if c == ' ' { println("adding space") }
                if c == '\t' { println("adding tab") }
                chunk += string(c)
		off++
	}
        print("VAL ")
	return chunk, off
}
