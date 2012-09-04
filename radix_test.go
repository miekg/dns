package radix

import (
	"fmt"
	"testing"
)

func printit(r *Radix, level int) {
	for i := 0; i < level; i++ {
		fmt.Print("\t")
	}
	fmt.Printf("%p '%v'  value: '%v'    parent %p\n", r, r.key, r.Value, r.parent)
	for _, child := range r.children {
		printit(child, level+1)
	}
}

func radixtree() *Radix {
	r := New()
	r.Insert("test", "a")
	r.Insert("tester", "a")
	r.Insert("team", "a")
	r.Insert("te", "a")
	return r
}

// None, of the childeren must have a prefix incommon with r.key
func validate(r *Radix) bool {
	return true
	for _, child := range r.children {
		_, i := longestCommonPrefix(r.key, child.key)
		if i != 0 {
			return false
		}
		validate(child)
	}
	return true
}

func TestPredecessor(t *testing.T) {
	r := radixtree()
	r.Insert("teak", "a")
	printit(r, 0)
	// team is below te, so we should find 'te'
	if x := r.Predecessor("team").Key(); x != "te" {
		t.Logf("Failed to find predecessor of team, found %s", x)
		t.Fail()
	}
	// tester is there, so we look for testeraaa
	if r.Predecessor("testeraaa").Key() != "tester" {
		t.Logf("Failed to find predecessor of testeraaa")
		t.Fail()
	}
	if r.Predecessor("testeraaahsahsjahsj").Key() != "tester" {
		t.Logf("Failed to find predecessor of testeraaa...")
		t.Fail()
	}
	// this should find nothing, or at least stop at the root node
	if r.Predecessor("atester").Key() != "" {
		t.Logf("Found predecessor of atester which shouldn't be there")
		t.Fail()
	}
}

func TestPrint(t *testing.T) {
	// TODO(mg): fix
}

func TestInsert(t *testing.T) {
	r := New()
	if !validate(r) {
		t.Log("Tree does not validate")
		t.Fail()
	}
	if r.Len() != 0 {
		t.Log("Len should be 0", r.Len())
	}
	r.Insert("test", nil)
	r.Insert("slow", nil)
	r.Insert("water", nil)
	r.Insert("tester", nil)
	r.Insert("testering", nil)
	r.Insert("rewater", nil)
	r.Insert("waterrat", nil)
	if !validate(r) {
		t.Log("Tree does not validate")
		t.Fail()
	}
}

func TestRemove(t *testing.T) {
	r := New()
	r.Insert("test", "aa")
	r.Insert("slow", "bb")

	if k := r.Remove("slow").Value; k != "bb" {
		t.Log("should be bb", k)
		t.Fail()
	}

	if r.Remove("slow") != nil {
		t.Log("should be nil")
		t.Fail()
	}
	r.Insert("test", "aa")
	r.Insert("tester", "aa")
	r.Insert("testering", "aa")
	r.Find("tester").Remove("test")
}

func TestKeys(t *testing.T) {
	r := radixtree()
	i := 0
	for _, k := range r.Keys() {
		if k == "" { i++ }
		if k == "te" { i++ }
		if k == "team" { i++ }
		if k == "test" { i++ }
		if k == "tester" { i++ }
	}
	if i != 5 {
		t.Fatal("not all keys seen")
	}
}

func ExampleFind() {
	r := New()
	r.Insert("tester", nil)
	r.Insert("testering", nil)
	r.Insert("te", nil)
	r.Insert("testeringandmore", nil)
	iter(r.Find("tester"))
	// Output:
	// prefix tester
	// prefix testering
	// prefix testeringandmore
}

func iter(r *Radix) {
	fmt.Printf("prefix %s\n", r.Key())
	for _, child := range r.children {
		iter(child)
	}
}

func BenchmarkFind(b *testing.B) {
	b.StopTimer()
	r := radixtree()
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		_ = r.Find("tester")
	}
}
