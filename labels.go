// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

// Holds a bunch of helper functions for dealing with labels.

// SplitDomainName splits a name string into it's labels.
// www.miek.nl. returns []string{"www", "miek", "nl"}
// The root label (.) returns nil.
func SplitDomainName(s string) (labels []string) {
	fqdnEnd := 0 // offset of the final '.' or the length of the name
	idx := Split(s)
	begin := 0

	if s[len(s)-1] == '.' {
		fqdnEnd = len(s) - 1
	} else {
		fqdnEnd = len(s)
	}

	switch len(idx) {
	case 0:
		return nil
	case 1:
		// no-op
	default:
		end := 0
		for i := 1; i < len(idx); i++ {
			end = idx[i]
			labels = append(labels, s[begin:end-1])
			begin = end
		}
	}

	labels = append(labels, s[begin:fqdnEnd])
	return labels
}

// CompareDomainName compares the names s1 and s2 and
// returns how many labels they have in common starting from the *right*.
// The comparison stops at the first inequality. The names are not downcased
// before the comparison.
//
// www.miek.nl. and miek.nl. have two labels in common: miek and nl
// www.miek.nl. and www.bla.nl. have one label in common: nl
func CompareDomainName(s1, s2 string) (n int) {
	s1 = Fqdn(s1)
	s2 = Fqdn(s2)
	l1 := Split(s1)
	l2 := Split(s2)

	// the first check: root label
	if l1 == nil || l2 == nil {
		return
	}

	j1 := len(l1) - 1 // end
	i1 := len(l1) - 2 // start
	j2 := len(l2) - 1
	i2 := len(l2) - 2
	// the second check can be done here: last/only label
	// before we fall through into the for-loop below
	if s1[l1[j1]:] == s2[l2[j2]:] {
		n++
	} else {
		return
	}
	for {
		if i1 < 0 || i2 < 0 {
			break
		}
		if s1[l1[i1]:l1[j1]] == s2[l2[i2]:l2[j2]] {
			n++
		} else {
			break
		}
		j1--
		i1--
		j2--
		i2--
	}
	return
}

// SplitLabels splits a domainname string into its labels.
// www.miek.nl. returns []string{"www", "miek", "nl"}
// The root label (.) returns nil.
func SplitLabels(s string) []string {
	println("SplitLabels is to be removed in future versions, for the better named SplitDomainName")
	return SplitDomainName(s)
}

// CompareLabels compares the names s1 and s2 and
// returns how many labels they have in common starting from the right.
// The comparison stops at the first inequality. The labels are not lower cased
// before the comparison, the caller should take care of this.
//
// www.miek.nl. and miek.nl. have two labels in common: miek and nl
// www.miek.nl. and www.bla.nl. have one label in common: nl
func CompareLabels(s1, s2 string) (n int) {
	println("CompareLabels is to be removed in future versions, for better named CompareDomainName")
	return CompareDomainName(s1, s2)
}

// CountLabel counts the the number of labels in the string s.
func CountLabel(s string) (labels int) {
	if s == "." {
		return
	}
	s = Fqdn(s) // TODO(miek): annoyed I need this
	off := 0
	end := false
	for {
		off, end = NextLabel(s, off)
		labels++
		if end {
			return
		}
	}
	panic("dns: not reached")
}

// LenLabels returns the number of labels in the string s.
func LenLabels(s string) int {
	println("LenLabels is to be removed in future versions, for the better named CountLabel")
	return CountLabel(s)
}

// Split splits a name s into its label indexes.
// www.miek.nl. returns []int{0, 4, 9}. The root name (.) returns nil.
func Split(s string) []int {
	if s == "." {
		return nil
	}
	s = Fqdn(s)     // Grrr!
	idx := []int{0} // TODO(miek): could allocate more (10) and then extend when needed
	off := 0
	end := false

	for {
		off, end = NextLabel(s, off)
		if end {
			return idx
		}
		idx = append(idx, off)
	}
	panic("dns: not reached")
}

// NextLabel returns the index of the start of the next label in the
// string s. The bool end is true when the end of the string has been
// reached.
func NextLabel(s string, offset int) (i int, end bool) {
	quote := false
	for i = offset; i < len(s)-1; i++ {
		switch s[i] {
		case '\\':
			quote = !quote
		default:
			quote = false
		case '.':
			if quote {
				quote = !quote
				continue
			}
			return i + 1, false
		}
	}
	return i + 1, true
}
