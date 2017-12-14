package cyclic

import (
	"testing"
)

func TestNewGroup(t *testing.T) {
	expected := nilGroup()
	p := NewInt(42)
	g := Gen{blah: *NewInt(0)}

	actual := NewGroup(p, g)

	if actual != expected {
		t.Errorf("TestNewGroup failed, expected: '%v', got: '%v'",
			expected, actual)
	}
}

func TestMulForGroup(t *testing.T) {
	expected := nilInt()
	gen := Gen{blah: *NewInt(0)}
	g := Group{prime: *NewInt(0), seed: *NewInt(0), g: gen}
	a := NewInt(42)
	b := NewInt(42)
	c := NewInt(42)
	actual := g.Mul(a, b, c)

	if actual != expected {
		t.Errorf("TestMulForGroup failed, expected: '%v', got: '%v'",
			expected, actual)
	}
}

func TestInside(t *testing.T) {
	expected := false
	gen := Gen{blah: *NewInt(0)}
	g := Group{prime: *NewInt(0), seed: *NewInt(0), g: gen}
	actual := g.Inside(NewInt(0))

	if actual != expected {
		t.Errorf("TestInside failed, expected: '%v', got: '%v'",
			expected, actual)
	}
}

func TestInverse(t *testing.T) {
	expected := nilInt()
	gen := Gen{blah: *NewInt(0)}
	g := Group{prime: *NewInt(0), seed: *NewInt(0), g: gen}
	a := NewInt(42)
	b := NewInt(42)
	actual := g.Inverse(a, b)

	if actual != expected {
		t.Errorf("TestInverse failed, expected: '%v', got: '%v'",
			expected, actual)
	}
}

func TestSetSeed(t *testing.T) {
	expected := NewInt(0)
	gen := Gen{blah: *NewInt(0)}
	g := Group{prime: *NewInt(0), seed: *expected, g: gen}
	a := NewInt(42)
	g.SetK(a)

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
