package dns

import "testing"

func TestInsert(t *testing.T) {
	z := NewZone("miek.nl.")
	mx, _ := NewRR("foo.miek.nl. MX 10 mx.miek.nl.")
	z.Insert(mx)
	node := z.Find("foo.miek.nl.")
	if node == nil {
		t.Fail()
	}
}

func TestRemove(t *testing.T) {
	z := NewZone("miek.nl.")
	mx, _ := NewRR("foo.miek.nl. MX 10 mx.miek.nl.")
	z.Insert(mx)
	node := z.Find("foo.miek.nl.")
	if node == nil {
		t.Fail()
	}
	z.Remove(mx)
	node = z.Find("foo.miek.nl.")
	if node != nil {
		println(node.String())
		t.Errorf("node(%s) still exists", node)
	}
}
