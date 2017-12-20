package cyclic

import (
	"testing"
)

// Tests NewGroup functionality
func TestNewGroup(t *testing.T) {
	p := NewInt(1000000010101111111)
	s := NewInt(192395897203)
	min := NewInt(2)
	max := NewInt(0)
	max.Mul(p, NewInt(1000))
	g := NewGen(min, max)
	actual := NewGroup(p, s, g)

	type testStruct struct {
		prime *Int
		seed  *Int
		g     Gen
	}
	expected := testStruct{p, s, g}
	tests := 1
	pass := 0
	if actual.prime.Cmp(expected.prime) != 0 {
		t.Errorf("TestNewGroup failed to initialize prime, expected: '%v',"+
			" got: '%v'", expected.prime.Text(10), actual.prime.Text(10))
	} else if actual.seed.Cmp(expected.seed) != 0 {
		t.Errorf("TestNewGroup failed to initialize seed, expected: '%v',"+
			" got: '%v'", expected.seed.Text(10), actual.seed.Text(10))
	} else {
		pass++
		println("NewGroup()", pass, "out of", tests, "tests passed.")
	}
}

func TestMulForGroup(t *testing.T) {
	p := NewInt(17)
	s := NewInt(15)
	min := NewInt(2)
	max := NewInt(1000)
	gen := NewGen(min, max)
	group := NewGroup(p, s, gen)

	actual := []*Int{
		group.Mul(NewInt(20), NewInt(10), NewInt(0)),
		group.Mul(NewInt(0), NewInt(10), NewInt(0)),
	}
	expected := []*Int{
		NewInt((20 * 10) % 17),
		NewInt(0),
	}

	tests := len(actual)
	pass := 0
	for i := 0; i < len(actual); i++ {
		if actual[i].Cmp(expected[i]) != 0 {
			t.Errorf("TestMulForGroup failed at index:%v, expected:%v, got:%v",
				i, expected[i].Text(10), actual[i].Text(10))
		} else {
			pass++
		}
	}
	println("Mul()", pass, "out of", tests, "tests passed.")
}

func TestInside(t *testing.T) {
	p := NewInt(17)
	s := NewInt(15)
	min := NewInt(2)
	max := NewInt(1000)
	gen := NewGen(min, max)
	group := NewGroup(p, s, gen)
	expected := []bool{
		false,
		false,
		false,
		true,
	}
	actual := []bool{
		group.Inside(NewInt(0)),
		group.Inside(NewInt(17)),
		group.Inside(NewInt(18)),
		group.Inside(NewInt(12)),
	}
	tests := len(expected)
	pass := 0
	for i := 0; i < len(expected); i++ {
		if actual[i] != expected[i] {
			t.Errorf("TestInside failed at index:%v, expected:%v, got:%v",
				i, expected, actual)
		} else {
			pass++
		}
	}
	println("Inside()", pass, "out of", tests, "tests passed.")
}

func TestInverse(t *testing.T) {
	p := NewInt(17)
	s := NewInt(15)
	min := NewInt(2)
	max := NewInt(1000)
	gen := NewGen(min, max)
	group := NewGroup(p, s, gen)
	x := NewInt(13)
	a := NewInt(10)
	inv := NewInt(0)
	inv = group.Inverse(a, inv)
	a = group.Mul(x, a, a)
	c := group.Mul(inv, a, NewInt(0))

	tests := 1
	pass := 0

	if c.Cmp(x) != 0 {
		t.Errorf("TestInverse failed, expected: '%v', got: '%v'",
			x.Text(10), c.Text(10))
	} else {
		pass++
	}
	println("Inverse()", pass, "out of", tests, "tests passed.")
}

/*
func TestSetSeed(t *testing.T) {
	expected := NewInt(0)
	gen := Gen{blah: *NewInt(0)}
	g := Group{prime: *NewInt(0), seed: *expected, g: gen}
	a := NewInt(42)
	g.SetSeed(a)

	var actual *Int
	actual = &(g.seed)

	if actual == expected {
		t.Errorf("TestSetK failed, expected: '%v', got: '%v'",
			expected, actual)
	}
}

func TestGen(t *testing.T) {
	expected := nilInt()
	gen := Gen{blah: *NewInt(0)}
	g := Group{prime: *NewInt(0), seed: *NewInt(0), g: gen}
	a := NewInt(42)
	actual := g.Gen(a)

	if actual != expected {
		t.Errorf("TestGen failed, expected: '%v', got: '%v'",
			expected, actual)
	}
}

func TestGetP(t *testing.T) {
	expected := nilInt()
	gen := Gen{blah: *NewInt(0)}
	g := Group{prime: *NewInt(0), seed: *NewInt(0), g: gen}
	a := NewInt(42)
	actual := g.GetP(a)

	if actual != expected {
		t.Errorf("TestGetP failed, expected: '%v', got: '%v'",
			expected, actual)
	}
}

func TestGroupMul(t *testing.T) {
	expected := nilInt()
	gen := Gen{blah: *NewInt(0)}
	g := Group{prime: *NewInt(0), seed: *NewInt(0), g: gen}
	slc := []*Int{NewInt(42)}
	c := NewInt(42)
	actual := g.GroupMul(slc, c)

	if actual != expected {
		t.Errorf("TestGroupMul failed, expected: '%v', got: '%v'",
			expected, actual)
	}
}

func TestExpForGroup(t *testing.T) {
	expected := nilInt()
	gen := Gen{blah: *NewInt(0)}
	g := Group{prime: *NewInt(0), seed: *NewInt(0), g: gen}
	x := NewInt(42)
	y := NewInt(42)
	z := NewInt(42)
	actual := g.Exp(x, y, z)

	if actual != expected {
		t.Errorf("TestExpForGroup failed, expected: '%v', got: '%v'",
			expected, actual)
	}
}

func TestRoot(t *testing.T) {
	expected := nilInt()
	gen := Gen{blah: *NewInt(0)}
	g := Group{prime: *NewInt(0), seed: *NewInt(0), g: gen}
	x := NewInt(42)
	y := NewInt(42)
	z := NewInt(42)
	actual := g.Root(x, y, z)

	if actual != expected {
		t.Errorf("TestRoot failed, expected: '%v', got: '%v'",
			expected, actual)
	}
}
*/
