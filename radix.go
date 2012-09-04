// Package radix implements a radix tree.                                                           
//                                                                                                  
// A radix tree is defined in:                                                                      
//    Donald R. Morrison. "PATRICIA -- practical algorithm to retrieve                              
//    information coded in alphanumeric". Journal of the ACM, 15(4):514-534,                        
//    October 1968                                                                                  
//
// Also see http://en.wikipedia.org/wiki/Radix_tree for more information.
//
package radix

// Radix represents a radix tree.
// The key of the root node of a tree is always empty.
type Radix struct {
	// children maps the first letter of each child to the child.
	children map[byte]*Radix
	key      string
	parent   *Radix // a pointer back to the parent

	// The contents of the radix node.
	Value interface{}
}

func (r *Radix) String() string {
	return r.stringHelper("")
}

func (r *Radix) stringHelper(indent string) (s string) {
	s = indent + r.Key() + ":"
	if r.Value == nil {
		s = indent + "<nil>:"
	}
	for i, _ := range r.children {
		s += string(i)
	}
	s += "\n"
	for i, r1 := range r.children {
		s += indent + string(i) + ":" + r1.stringHelper("  "+indent)
	}
	return s
}

// Key returns the full (from r down to this node) key under which r is stored.
func (r *Radix) Key() (s string) {
	for p := r; p != nil; p = p.parent {
		s = p.key + s
	}
	return
}

func longestCommonPrefix(key, bar string) (string, int) {
	if key == "" || bar == "" {
		return "", 0
	}
	x := 0
	for key[x] == bar[x] {
		x = x + 1
		if x == len(key) || x == len(bar) {
			break
		}
	}
	return key[:x], x // == bar[:x]
}

// Insert inserts the value into the tree with the specified key. It returns the radix node
// it just inserted. Insert must be called on the root of the tree.
func (r *Radix) Insert(key string, value interface{}) *Radix {
	// look up the child starting with the same letter as key
	// if there is no child with the same starting letter, insert a new one
	child, ok := r.children[key[0]]
	if !ok {
		r.children[key[0]] = &Radix{make(map[byte]*Radix), key, r, value}
		return r.children[key[0]]
	}

	if key == child.key {
		child.Value = value
		return child
	}

	commonPrefix, prefixEnd := longestCommonPrefix(key, child.key)

	if commonPrefix == child.key {
		return child.Insert(key[prefixEnd:], value)
	}

	// create new child node to replace current child
	newChild := &Radix{make(map[byte]*Radix), commonPrefix, r, nil}

	// replace child of current node with new child: map first letter of common prefix to new child
	r.children[commonPrefix[0]] = newChild

	// shorten old key to the non-shared part
	child.key = child.key[prefixEnd:]

	// map old child's new first letter to old child as a child of the new child
	newChild.children[child.key[0]] = child
	child.parent = newChild // update the pointer of the current child which is moved down

	// if there are key left of key, insert them into our new child
	if key != newChild.key {
		newChild.Insert(key[prefixEnd:], value)
	} else {
		newChild.Value = value
	}
	return newChild
}

// Find returns the node associated with key. All childeren of this node share the same prefix,
// r does not have to be the root of the radix tree, but it starts be looking at the children
// of the current node.
func (r *Radix) Find(key string) *Radix {
	if key == "" {
		return nil
	}
	child, ok := r.children[key[0]]
	if !ok {
		return nil
	}

	if key == child.key {
		return child
	}

	commonPrefix, prefixEnd := longestCommonPrefix(key, child.key)

	// if child.key is not completely contained in key, abort [e.g. trying to find "ab" in "abc"]
	if child.key != commonPrefix {
		return nil
	}

	// find the key left of key in child
	return child.Find(key[prefixEnd:])
}

// Find predecessor: Locates the largest string less than a given string, by lexicographic order.
// Predecessor returns the node who's key is the largest, but always smaller than the given key.
// If nothing is found nil is returned.
func (r *Radix) Predecessor(key string) *Radix {
	child, ok := r.children[key[0]]
	if !ok {
		for r.Value == nil {
			if r.parent == nil {
				return nil // Root node
			}
			r = r.parent
		}
		return r
	}
	// Ok, we found the node... 
	if key == child.key {
		for r.Value == nil {
			if r.parent == nil {
				return nil // Root node
			}
			r = r.parent
		}
		return r
	}

	commonPrefix, prefixEnd := longestCommonPrefix(key, child.key)

	// if child.key is not completely contained in key, return the parent
	if child.key != commonPrefix {
		for r.Value == nil {
			if r.parent == nil {
				return nil // Root node
			}
			r = r.parent
		}
		return r
	}
	// find the key left of key in child
	return child.Predecessor(key[prefixEnd:])
}

// Find successor: Locates the smallest string greater than a given string, by

// Prefix returns a slice with all the keys that share this prefix. Prefix
// needs to start from the root node.
func (r *Radix) Prefix(prefix string) []string {
	bestfit := r.prefix(prefix)
	if bestfit == nil {
		return nil
	}
	return bestfit.Keys()
}

func (r *Radix) prefix(prefix string) *Radix {
	if r.key == prefix {
		return r
	}

	child, ok := r.children[prefix[0]]
	if !ok {
		return nil
	}
	if prefix == child.key {
		return child
	}
	// The whole of the prefix is contained in the child's key
	_, prefixEnd := longestCommonPrefix(prefix, child.key)
	if prefixEnd+1 > len(prefix) {
		return child
	}
	return child.prefix(prefix[prefixEnd:])
}

// Up returns the first node above r which has a non-nil Value.
// If nothing is found nil is returned.
func (r *Radix) Up() *Radix {
	if r.parent == nil {
		return nil
	}
	// Walk until you can walk nomore
	for r = r.parent; r != nil && r.Value == nil; r = r.parent {
		// ...
	}
	return r
}

// Remove removes any value set to key. It returns the removed node or nil if the
// node cannot be found.
func (r *Radix) Remove(key string) *Radix {
	child, ok := r.children[key[0]]
	if !ok {
		return nil
	}

	// if the correct end node is found...
	if key == child.key {
		switch len(child.children) {
		case 0:
			// remove child from current node if child has no children on its own
			delete(r.children, key[0])
		case 1:
			// since len(child.children) == 1, there is only one subchild; we have to use range to get the value, though, since we do not know the key
			for _, subchild := range child.children {
				// essentially moves the subchild up one level to replace the child we want to delete, while keeping the key of child
				child.key = child.key + subchild.key
				child.Value = subchild.Value
				child.children = subchild.children
				child.parent = r
			}
		default:
			// if there are >= 2 subchilds, we can only set the value to nil, thus delete any value set to key
			child.Value = nil
		}
		return child
	}

	// Node has not been foundJ, key != child.keys

	commonPrefix, prefixEnd := longestCommonPrefix(key, child.key)
	// if child.key is not completely contained in key, abort [e.g. trying to delete "ab" from "abc"]
	if child.key != commonPrefix {
		return nil
	}
	// else: cut off common prefix and delete left string in child
	return child.Remove(key[prefixEnd:])
}

// Do calls function f on each node in the tree. f's parameter will be r.Value. The behavior of Do is              
// undefined if f changes r.                                                       
func (r *Radix) Do(f func(interface{})) {
	if r != nil {
		f(r.Value)
		for _, child := range r.children {
			child.Do(f)
		}
	}
}

// Len computes the number of nodes in the radix tree r.
func (r *Radix) Len() int {
	i := 0
	if r != nil {
		if r.Value != nil {
			i++
		}
		for _, child := range r.children {
			i += child.Len()
		}
	}
	return i
}

// Keys return all the keys from the node r and downwards
func (r *Radix) Keys() (s []string) {
	// get the full key for this node and use that to get all the other keys
	fullkey := r.key
	for p := r.parent; p != nil; p = p.parent {
		fullkey = p.key + fullkey
	}
	return r.keys(fullkey)
}

func (r *Radix) keys(fullkey string) (s []string) {
	if fullkey != "" { // root
		s = append(s, fullkey)
	}
	for _, c := range r.children {
		s = append(s, c.keys(fullkey+c.key)...)
	}
	return s
}

// New returns an initialized radix tree.
func New() *Radix {
	return &Radix{make(map[byte]*Radix), "", nil, nil}
}
