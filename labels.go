package dns

// Holds a bunch of helper functions for dealing with labels.

// SplitLabels splits a domainname string into its labels.
func SplitLabels(s string) []string {
	last := byte('.')
	k := 0
	labels := make([]string, 0)
	s = Fqdn(s) // Make fully qualified
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			if last == '\\' {
				// do nothing
				break
			}
			labels = append(labels, s[k:i])
			k = i + 1 // + dot
		}
		last = s[i]
	}
	return labels
}

// CompareLabels compares the strings s1 and s2 and
// returns how many labels they have in common starting from the right.
// The comparison stops at the first inequality
//
// www.miek.nl and miek.nl have two labels in common: miek and nl
// www.miek.nl and www.bla.nl have one label in common: nl
func CompareLabels(s1, s2 string) (n int) {
	l1 := SplitLabels(s1)
	l2 := SplitLabels(s2)

	x1 := len(l1) - 1
	x2 := len(l2) - 1
	for {
		if x1 < 0 || x2 < 0 {
			break
		}
		if l1[x1] == l2[x2] {
			n++
		} else {
			break
		}
		x1--
		x2--
	}
	return
}

// This function is needed for easy handling of compression 
// pointers
// www.miek.nl, 2, gives that start of miek.nl (which is
// 2 labels from the right)
// labeloffset of zero is fishy as is a labeloffset larger
// than the number of labels... TODO: make it an error?
func offsetLabelFromRight(s string, labeloffset int) int {
	l := SplitLabels(s)
	fromleft := len(l) - labeloffset
	off := 0
	for i := 0; i < fromleft; i++ {
		off += len(l[i]) + 1
	}
	return off
}
