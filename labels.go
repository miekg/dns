package dns

// Holds a bunch of helper functions for dealing with labels.

// SplitDomainName splits a name string into it's labels.
// www.miek.nl. returns []string{"www", "miek", "nl"}
// .www.miek.nl. returns []string{"", "www", "miek", "nl"},
// The root label (.) returns nil. Note that using
// strings.Split(s) will work in most cases, but does not handle
// escaped dots (\.) for instance.
// s must be a syntactically valid domain name, see IsDomainName.
func SplitDomainName(s string) (labels []string) {
	if s == "" {
		return nil
	}
	fqdnEnd := 0 // offset of the final '.' or the length of the name
	idx := Split(s)
	begin := 0
	if IsFqdn(s) {
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
		for _, end := range idx[1:] {
			labels = append(labels, s[begin:end-1])
			begin = end
		}
	}

	return append(labels, s[begin:fqdnEnd])
}

// CompareDomainName compares the names s1 and s2 and
// returns how many labels they have in common starting from the *right*.
// The comparison stops at the first inequality. The names are downcased
// before the comparison.
//
// www.miek.nl. and miek.nl. have two labels in common: miek and nl
// www.miek.nl. and www.bla.nl. have one label in common: nl
//
// s1 and s2 must be syntactically valid domain names.
func CompareDomainName(s1, s2 string) (n int) {
	// the first check: root label
	if s1 == "." || s2 == "." {
		return 0
	}

	l1 := Split(s1)
	l2 := Split(s2)

	j1 := len(l1) - 1 // end
	i1 := len(l1) - 2 // start
	j2 := len(l2) - 1
	i2 := len(l2) - 2
	// the second check can be done here: last/only label
	// before we fall through into the for-loop below
	if !equal(s1[l1[j1]:], s2[l2[j2]:]) {
		return
	}
	n++
	for {
		if i1 < 0 || i2 < 0 {
			break
		}
		if !equal(s1[l1[i1]:l1[j1]], s2[l2[i2]:l2[j2]]) {
			break
		}
		n++
		j1--
		i1--
		j2--
		i2--
	}
	return
}

// CountLabel counts the number of labels in the string s.
// s must be a syntactically valid domain name.
func CountLabel(s string) (labels int) {
	if s == "." {
		return
	}
	off := 0
	end := false
	for {
		off, end = NextLabel(s, off)
		labels++
		if end {
			return
		}
	}
}

// Split splits a name s into its label indexes.
// www.miek.nl. returns []int{0, 4, 9}, www.miek.nl also returns []int{0, 4, 9}.
// The root name (.) returns nil. Also see SplitDomainName.
// s must be a syntactically valid domain name.
func Split(s string) []int {
	if s == "." {
		return nil
	}
	idx := make([]int, 1, 3)
	off := 0
	end := false

	for {
		off, end = NextLabel(s, off)
		if end {
			return idx
		}
		idx = append(idx, off)
	}
}

// NextLabel returns the index of the start of the next label in the
// string s starting at offset.
// The bool end is true when the end of the string has been reached.
// Also see PrevLabel.
func NextLabel(s string, offset int) (i int, end bool) {
	if s == "" {
		return 0, true
	}
	for i = offset; i < len(s)-1; i++ {
		if s[i] != '.' {
			continue
		}
		j := i - 1
		for j >= 0 && s[j] == '\\' {
			j--
		}

		if (j-i)%2 == 0 {
			continue
		}

		return i + 1, false
	}
	return i + 1, true
}

// PrevLabel returns the index of the label when starting from the right and
// jumping n labels to the left.
// The bool start is true when the start of the string has been overshot.
// Also see NextLabel.
func PrevLabel(s string, n int) (i int, start bool) {
	if s == "" {
		return 0, true
	}
	if n == 0 {
		return len(s), false
	}

	l := len(s) - 1
	if s[l] == '.' {
		l--
	}

	for ; l >= 0 && n > 0; l-- {
		if s[l] != '.' {
			continue
		}
		j := l - 1
		for j >= 0 && s[j] == '\\' {
			j--
		}

		if (j-l)%2 == 0 {
			continue
		}

		n--
		if n == 0 {
			return l + 1, false
		}
	}

	return 0, n > 1
}

// Compare compares domains according to the canonical ordering specified in RFC4034
// returns an integer value similar to strcmp
// (0 for equal values, -1 if s1 < s2, 1 if s1 > s2)
func Compare(s1, s2 string) int {
	s1b := []byte(s1)
	s2b := []byte(s2)

	doDDD(s1b)
	doDDD(s2b)

	s1lend := len(s1)
	s2lend := len(s2)

	for i := 0; ; i++ {
		s1lstart, end1 := PrevLabel(s1, i)
		s2lstart, end2 := PrevLabel(s2, i)

		if end1 && end2 {
			return 0
		}

		s1l := string(s1b[s1lstart:s1lend])
		s2l := string(s2b[s2lstart:s2lend])

		if cmp := labelCompare(s1l, s2l); cmp != 0 {
			return cmp
		}

		s1lend = s1lstart - 1
		s2lend = s2lstart - 1
		if s1lend == -1 {
			s1lend = 0
		}
		if s2lend == -1 {
			s2lend = 0
		}
	}
}

// essentially strcasecmp
// (0 for equal values, -1 if s1 < s2, 1 if s1 > s2)
func labelCompare(a, b string) int {
	la := len(a)
	lb := len(b)
	minLen := la
	if lb < la {
		minLen = lb
	}
	for i := 0; i < minLen; i++ {
		ai := a[i]
		bi := b[i]
		if ai >= 'A' && ai <= 'Z' {
			ai |= 'a' - 'A'
		}
		if bi >= 'A' && bi <= 'Z' {
			bi |= 'a' - 'A'
		}
		if ai != bi {
			if ai > bi {
				return 1
			}
			return -1
		}
	}

	if la > lb {
		return 1
	} else if la < lb {
		return -1
	}
	return 0
}

// equal compares a and b while ignoring case. It returns true when equal otherwise false.
func equal(a, b string) bool {
	// might be lifted into API function.
	if len(a) != len(b) {
		return false
	}

	return labelCompare(a, b) == 0
}

func doDDD(b []byte) {
	lb := len(b)
	for i := 0; i < lb; i++ {
		if i+3 < lb && b[i] == '\\' && isDigit(b[i+1]) && isDigit(b[i+2]) && isDigit(b[i+3]) {
			b[i] = dddToByte(b[i+1 : i+4])
			for j := i + 1; j < lb-3; j++ {
				b[j] = b[j+3]
			}
			lb -= 3
		}
	}
}
