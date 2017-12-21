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
}*/

func TestArrayMul(t *testing.T) {
	tests := 1
	pass := 0

	p := NewInt(11)

	expected := NewInt(10)

	min := NewInt(2)
	max := NewInt(0)
	max.Mul(p, NewInt(1000))
	seed := NewInt(42)
	gen := NewGen(min, max)

	g := NewGroup(p, seed, gen)

	slc := []*Int{
		NewInt(2),
		NewInt(3),
		NewInt(4),
		NewInt(5),
	}
	c := NewInt(42)
	actual := g.ArrayMul(slc, c)

	if actual.Cmp(expected) != 0 {
		t.Errorf("TestArrayMul failed, expected: '%v', got: '%v'",
			expected, actual)
	} else {
		pass++
	}

	println("ArrayMul()", pass, "out of", tests, "tests passed.")
}

func TestExpForGroup(t *testing.T) {

	p := NewInt(11)
	min := NewInt(2)
	max := NewInt(0)
	max.Mul(p, NewInt(1000))
	seed := NewInt(42)
	gen := NewGen(min, max)

	g := NewGroup(p, seed, gen)

	type testStructure struct {
		x *Int
		y *Int
		z *Int
	}

	testStrings := [][]string{
		{"42", "42", "4"},
		{"42", "69", "5"},
		{"-69", "42", "9"},
		{"1000000000", "9999999", "10"},
	}

	var testStructs []testStructure

	var sucess bool

	for i, strs := range testStrings {
		var ts testStructure

		ts.x, sucess = NewInt(0).SetString(strs[0], 10)

		if sucess != true {
			t.Errorf("Setup for Test of Exp() for Group failed at 'x' phase of index: %v", i)
		}

		ts.y, sucess = NewInt(0).SetString(strs[1], 10)

		if sucess != true {
			t.Errorf("Setup for Test of Exp() for Group failed at 'y' phase of index: %v", i)
		}

		ts.z, sucess = NewInt(0).SetString(strs[2], 10)

		if sucess != true {
			t.Errorf("Setup for Test of Exp() for Group failed at 'z' phase of index: %v", i)
		}

		testStructs = append(testStructs, ts)
	}

	tests := len(testStructs)
	pass := 0

	expected := 0

	for i, testi := range testStructs {
		actual := NewInt(0)
		actual = g.Exp(testi.x, testi.y, actual)

		result := actual.Cmp(testi.z)

		if result != expected {
			t.Errorf("Test of Exp() for Group failed at index: %v Expected: %v, %v; Actual: %v, %v",
				i, expected, testi.z.Text(10), result, actual.Text(10))
		} else {
			pass += 1
		}
	}
	println("Exp() for Group", pass, "out of", tests, "tests passed.")

}

func TestRoot(t *testing.T) {
	p := NewInt(11)
	min := NewInt(2)
	max := NewInt(0)
	max.Mul(p, NewInt(1000))
	seed := NewInt(42)
	gen := NewGen(min, max)

	g := NewGroup(p, seed, gen)

	type testStructure struct {
		x *Int
		y *Int
		z *Int
	}

	testStrings := [][]string{
		{"42", "42", "1"},
		{"42", "69", "5"},
		{"-69", "42", "10"},
		{"1000000000", "9999999", "10"},
	}

	var testStructs []testStructure

	var sucess bool

	for i, strs := range testStrings {
		var ts testStructure

		ts.x, sucess = NewInt(0).SetString(strs[0], 10)

		if sucess != true {
			t.Errorf("Setup for Test of Root() failed at 'x' phase of index: %v", i)
		}

		ts.y, sucess = NewInt(0).SetString(strs[1], 10)

		if sucess != true {
			t.Errorf("Setup for Test of Root() failed at 'y' phase of index: %v", i)
		}

		ts.z, sucess = NewInt(0).SetString(strs[2], 10)

		if sucess != true {
			t.Errorf("Setup for Test of Root() failed at 'z' phase of index: %v", i)
		}

		testStructs = append(testStructs, ts)
	}

	tests := len(testStructs)
	pass := 0

	expected := 0

	for i, testi := range testStructs {

		inv := NewInt(0)
		actual := NewInt(0)

		g.Inverse(testi.y, inv)

		actual = g.Exp(testi.x, inv, actual)

		result := actual.Cmp(testi.z)

		if result != expected {
			t.Errorf("Test of Root() failed at index: %v Expected: %v, %v; Actual: %v, %v",
				i, expected, testi.z.Text(10), result, actual.Text(10))
		} else {
			pass += 1
		}
	}
	println("Root()", pass, "out of", tests, "tests passed.")
}
