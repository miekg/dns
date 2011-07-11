    package main

    import "fmt"

CHAR    [A-Za-z0-9/+=a.{}]
WS      [ \t]

%x qclass qtype rdata
%%

^{CHAR}+            { 
                        YOUT("qname")
                        BEGIN(qclass)
                    }
WS                      YOUT(" ")
<qclass>WS              YOUT(" ")
<qtype>WS               YOUT(" ")
<rdata>WS               YOUT(" ")
;.*\n               {
                        YOUT("comment\n")
                        BEGIN(INITIAL)
                    }
<qclass>;.*\n       {
                        YOUT("comment\n")
                        BEGIN(INITIAL)
                    }
<qtype>;.*\n        {
                        YOUT("comment\n")
                        BEGIN(INITIAL)
                    }
<rdata>;.*\n        {
                        YOUT("comment\n")
                        BEGIN(INITIAL)
                    }

<qclass>{CHAR}+     {
                        YOUT("qclass/ttl")
                        BEGIN(qtype)
                    }
<qtype>{CHAR}+      {
                        YOUT("qtype")
                        BEGIN(rdata)
                    }
<rdata>{CHAR}+      {
                        YOUT("rdata")
                    }
<rdata>\n           {
                        YOUT("END\n\n")
                        BEGIN(INITIAL)
                    }
%%


func YOUT(s string) {
    fmt.Printf("%s", s)
}

func main() {
    yylex()
}
