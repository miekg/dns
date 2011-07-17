package dns

// Parse private key files

import (
    "os"
    "io"
    "bufio"
    "strings"
)

%%{
        machine k;
        write data;
}%%

func Kparse(q io.Reader) (m map[string]string, err os.Error) {
        r := bufio.NewReader(q)

        m = make(map[string]string)
        k := ""
        data, err := r.ReadString('\n')
        for err == nil {
            cs, p, pe := 0, 0, len(data)
            mark := 0

        %%{
                action mark      { mark = p }
                action setKey    { k = strings.ToLower(data[mark:p]) }
                action setValue  { m[k] = data[mark:p] }

                base64 = [a-zA-Z0-9.\\/+=() ]+ >mark;

                key = (
                      ('Private-key-format'i)
                    | ('Algorithm'i)
                    | ('Modulus'i)
                    | ('PublicExponent'i)
                    | ('PrivateExponent'i)      # RSA, RFC ....?
                    | ('GostAsn1'i)             # GOST, RFC 5933
                    | ('PrivateKey'i)           # ECDSA, RFC xxxx (TBA)
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
            data, err = r.ReadString('\n')
        }

        /*
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
        */
        return m, nil
}
