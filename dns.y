%{

package main

import (
    "fmt"
    "os"
)

var yylval *yySymType

%}

%union
{
        val string;

}


%type  <val> rr rdata

%token <val> QNAME TTL QCLASS QTYPE STR NL

%%
rr:
        QNAME TTL QCLASS QTYPE rdata
        {
        fmt.Fprintf(os.Stderr, "{%v}\n", $$)
        }
|       QNAME QCLASS TTL QTYPE rdata
|       QNAME TTL QTYPE rdata
|       QNAME QCLASS QTYPE rdata
|       QNAME QTYPE rdata
        {
        fmt.Fprintf(os.Stderr, "%v\n", $1)
        }

rdata:
        rdata STR
|       rdata NL
|       STR
|       NL
        {
        fmt.Fprintf(os.Stderr, "%v\n", $1)
        }

%%

func main() {
    yylval = new(yySymType)
    yyin = os.Stdin
    yyParse(yyLex(0))
}
