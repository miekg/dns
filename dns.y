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

func (DnsLex) Lex(yylval *yySymType) int {

    // yylval.rrtype = Str_rr($XX)  //give back TypeA, TypeNS
    // return Y_A this should be the token, another map?

    return 0
}
