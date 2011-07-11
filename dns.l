        package main
        import "fmt"

        var debug = true
        var lastOwner = string
    
CHAR    [A-Za-z0-9/+=a.{}]
BLANK   [ \t]

%s classttl rest
%%
<*>;.*\n            {
                        // Comments aren't interesting
                        YOUT("NL\n")
                        BEGIN(INITIAL)
                    }
<*>%$               {
                        // Empty lines
                        YOUT("\n")
                        BEGIN(INITIAL)
                    }

<INITIAL>^{CHAR}+   { 
                        YOUT("qname")
                        yylval = yytext
                        lastOwner = yylval
                        BEGIN(classttl)
                        return QNAME
                    }
<INITIAL>^{BLANK}+           {
                        YOUT("qname.")
                        // Return qname TOK, and fix yytext
                        yylval = lastOwner
                        BEGIN(classttl)
                        return QNAME
                    }

<classttl>{CHAR}+   {
                        yylval = yytext
                        switch yycheckit(yytext) {
                        case 0:
                            YOUT("{qtype:" + yytext + "}")
                            BEGIN(rest)
                            return QTYPE
                        case 1:
                            YOUT("qclass")
                            return QCLASS
                        case 2:
                            YOUT("ttl")
                            return TTL
                        }
                    }
<classttl>{BLANK}+  {
                        YOUT(".")
                    }

<rest>{CHAR}+       {
                        YOUT("str")
                        yylval = yytext
                        return STR
                    }
<rest>{BLANK}+      {
                        YOUT(".")
                    }
<rest>\n            {
                        YOUT("NL\n")
                        BEGIN(INITIAL)
                        return NL
                    }

%%

func yycheckit(s string) int {
    if s == "IN" {
        return 1
    }
    if s[0] >= '0' && s[0] <= '9' {
        return 2
    }
    return 0
}


func YOUT(s string) {
    if debug {
        fmt.Printf("%s", s)
    }
}

type yyLex int

func (yyLex) Lex(yylval *yySymType) int {
    yylex()   
    return 0
}

func (yyLex) Error(s string) {
    println(s)
}
