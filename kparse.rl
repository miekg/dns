package dns

// Parse private key files

import (
    "os"
    "fmt"
    "strings"
)

%%{
        machine k;
        write data;
}%%

func Kparse(data string) (m map[string]string, err os.Error) {
        cs, p, pe := 0, 0, len(data)
        mark := 0
        k := ""
        k=k
        m = make(map[string]string)

        %%{
                action mark      { mark = p }
                action setKey    { k = strings.ToLower(data[mark:p]); fmt.Printf("key {%s}\n", k) }
                action setValue  { m[k] = data[mark:p]; fmt.Printf("value {%s}\n", data[mark:p]) }

                base64 = [a-zA-Z0-9.\\/+=() ]+ >mark;

                key = (
                      ('Private-key-format'i)
                    | ('Algorithm'i)
                    | ('Modulus'i)
                    | ('PublicExponent'i)
                    | ('PrivateExponent'i)
                    | ('Prime1'i)
                    | ('Prime2'i)
                    | ('Exponent1'i)
                    | ('Exponent2'i)
                    | ('Coefficient'i)
                    | ('Created'i)
                    | ('Publish'i)
                    | ('Activate'i)
                ) >mark %setKey;
                
                value = base64 %setValue;

                line = key ': ' value;
                main := ( line '\n' )*;

                write init;
                write exec;
        }%%

        if cs < z_first_final {
                // No clue what I'm doing what so ever
                if p == pe {
                        //return nil, os.ErrorString("unexpected eof")
                        println("err unexp eof")
                        return m, nil
                } else {
                        //return nil, os.ErrorString(fmt.Sprintf("error at position %d", p))
                        println("err ", p, "data:", string(data[p]))
                        return nil, nil
                }
        }
        return m, nil
}
