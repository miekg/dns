// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

const initialSize = 8

type QnameString []string

func NewQnameString() *QnameString {
	p := make(QnameString, 0)
	return &p
}

func (p *QnameString) Insert(i int, x string) {
	p.Expand(i, 1)
	(*p)[i] = x

}
func (p *QnameString) Expand(i, n int) {
	a := *p

	// make sure we have enough space
	len0 := len(a)
	len1 := len0 + n
	if len1 <= cap(a) {
		// enough space - just expand
		a = a[0:len1]
	} else {
		// not enough space - double capacity
		capb := cap(a) * 2
		if capb < len1 {
			// still not enough - use required length
			capb = len1
		}
		// capb >= len1
		a = p.realloc(len1, capb)
	}

	// make a hole
	for j := len0 - 1; j >= i; j-- {
		a[j+n] = a[j]
	}

	*p = a
}

func (p *QnameString) realloc(length, capacity int) (b []string) {
	if capacity < initialSize {
		capacity = initialSize
	}
	if capacity < length {
		capacity = length
	}
	b = make(QnameString, length, capacity)
	copy(b, *p)
	*p = b
	return
}
