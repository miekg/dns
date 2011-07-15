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

func Kparse(data string) (m map[string]string, err os.Error) {
        cs, p, pe, eof := 0, 0, len(data), len(data)
        mark := 0
        key := ""

        %%{
                action mark      { mark = p }
                action setKey    { key = strings.ToLower(data[mark:p]) }
                action setValue  { m[key] = data[mark:p] }

                key = (
                      ('Private-key-format'i)
                    | ('Algorithm'i)
                    | ('Modules'i)
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
                );
                
                value = any+;

                line = key /: ?/ value;
                main := line+;

                write init;
                write exec;
        }%%

        if cs < z_first_final {
                // No clue what I'm doing what so ever
                if p == pe {
                        //return nil, os.ErrorString("unexpected eof")
                        return nil, nil
                } else {
                        //return nil, os.ErrorString(fmt.Sprintf("error at position %d", p))
                        return nil, nil
                }
        }
        return r ,nil
}
