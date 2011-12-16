package dns

import (
	"strings"
)

// Helper functions

// Only return those RR with the type t
func SieveRR(rr []RR, t uint16) (l []RR) {
	for _, r := range rr {
		if r.Header().Rrtype == t {
			l = append(l, r)
		}
	}
	return
}

// DnameLength returns the length of a packed dname.
func DomainNameLength(s string) int { // TODO better name
	// Special case for '.'
	if s == "." {
		return 1
	}

	// Add trailing dot to canonicalize name.
	if n := len(s); n == 0 || s[n-1] != '.' {
		return n + 1
	} else {
		return n + 1
	}
	panic("not reached")
	return 0
}

// Return a slice with the full name, one label shorter,
// shorter, until we, hit the root
// Each name is fully qualified.
// The root labels is added as last
func LabelSlice(s string) []string {
	if s[len(s)-1] != '.' {
		s += "."
	}
	ss := strings.Split(s, ".")
	labels := make([]string, 0)
	for i := 0; i < len(ss)-1; i++ {
		labels = append(labels, strings.Join(ss[i:], "."))
	}
	labels = append(labels, ".")
	return labels
}

// LabelSliceReverse reverse a label slice
func LabelSliceReverse(l []string) []string {
	for i, j := 0, len(l)-1; i < j; i, j = i+1, j-1 {
		l[i], l[j] = l[j], l[i]
	}
	return l
}

// Labels returns i labels from the left side of the name. 
// The counting start with 0. The returned names are fully
// qualified.
// So for "a.miek.nl." it returns [ a.miek.nl. miek.nl. nl. . ]
func Labels(s string, i int) string {
	ss := strings.Split(s, ".")
	return strings.Join(ss[:i+1], ".")
	// TODO fully qualified
}

// Labels returns the number of labels in a domain name.
func LabelCount(a string) (c uint8) {
	// walk the string and count the dots
	// except when it is escaped
	esc := false
	for _, v := range a {
		switch v {
		case '.':
			if esc {
				esc = !esc
				continue
			}
			c++
		case '\\':
			esc = true
		}
	}
	return
}
