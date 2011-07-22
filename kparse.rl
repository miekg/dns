package dns

// Parse private key files

import (
    "os"
    "strings"
)

%%{
        machine k;
        write data;
}%%

// Parse a private key file as defined in XXX.
// A map[string]string is returned with the values. All the keys
// are in lowercase. The algorithm is returned as m[algorithm] = "RSASHA1"
func (kp *Parser) PrivateKey() (m map[string]string, err os.Error) {
        m = make(map[string]string)
        var k string
        lines := strings.SplitAfter(string(kp.buf), "\n", -1)
        for _, data := range lines {
            cs, p, pe := 0, 0, len(data)
            mark := 0

        %%{
                action mark      { mark = p }
                action setKey    { k = strings.ToLower(data[mark:p]) }
                action setValue  { m[k] = data[mark:p] }
                action setAlg    { m[k] = strings.ToUpper(data[mark:p-1]) }

                bl = [ \t]+;
                base64any = [a-zA-Z0-9.\\/+=() ]+ >mark;
                algorithm = ( 'RSASHA1'i | 'RSASHA256'i ) >mark;
                comment = /^;/;

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
                
                value = ( base64any %setValue | digit+ bl '(' algorithm ')' %setAlg );

                line = ( key ': ' value | comment );
                main := ( line '\n' )*;

                write init;
                write exec;
        }%%
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
