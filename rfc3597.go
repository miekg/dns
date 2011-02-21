package dns

// Unknown Resource Records

import "strconv"

func unknownClass(class int) string {
       return "CLASS" + strconv.Itoa(class)
}

func unknownType(t int) string {
        return "TYPE" + strconv.Itoa(t)
}
