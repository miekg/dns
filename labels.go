package dns

// Holds a bunch of helper functions for dealing with labels.

// SplitLabels splits a domainname string into its labels.
// www.miek.nl. returns []string{"www", "miek", "nl"}
// The root label (.) returns nil.
func SplitLabels(s string) []string {
	if s == "." {
		return nil
	}

	k := 0
	labels := make([]string, 0)
	last := byte('.')
	lastlast := byte('.')
	s = Fqdn(s) // Make fully qualified
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			if last == '\\' {
				if lastlast != '\\' {
					// do nothing
					continue
				}
			}
			labels = append(labels, s[k:i])
			k = i + 1 // + dot
		}
		lastlast = last
		last = s[i]
	}
	return labels
}

// CompareLabels compares the strings s1 and s2 and
// returns how many labels they have in common starting from the right.
// The comparison stops at the first inequality. The labels are not downcased
// before the comparison.
//
// www.miek.nl. and miek.nl. have two labels in common: miek and nl
// www.miek.nl. and www.bla.nl. have one label in common: nl
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

// LenLabels returns the number of labels in a domain name.
func LenLabels(s string) (labels int) {
	if s == "." {
		return
	}
	last := byte('.')
	lastlast := byte('.')
	s = Fqdn(s) // Make fully qualified
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			if last == '\\' {
				if lastlast != '\\' {
					// do nothing
					continue
				}
			}
			labels++
		}
		lastlast = last
		last = s[i]
	}
	return
}
