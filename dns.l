    package main

    import "fmt"
    
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

<INITIAL>^{CHAR}+            { 
                        YOUT("qname")
                        BEGIN(classttl)
                    }
<INITIAL>^{BLANK}+           {
                        YOUT("qname.")
                        // Return qname TOK, and fix yytext
                        BEGIN(classttl)
                    }

<classttl>{CHAR}+   {
                        switch yycheckit(yytext) {
                        case 0:
                            YOUT("{qtype:" + yytext + "}")
                            BEGIN(rest)
                        case 1:
                            YOUT("qclass")
                        case 2:
                            YOUT("ttl")
                        }
                    }
<classttl>{BLANK}+  {
                        YOUT(".")
                    }

<rest>{CHAR}+       {
                        YOUT("str")
                    }
<rest>{BLANK}+      {
                        YOUT(".")
                    }
<rest>\n            {
                        YOUT("NL\n")
                        BEGIN(INITIAL)
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
    fmt.Printf("%s", s)
}

func main() {
    yylex()
}
