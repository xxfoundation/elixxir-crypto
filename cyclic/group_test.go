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
		true,
		false,
		false,
		true,
	}
	actual := []bool{
		group.Inside(NewInt(0)),
		group.Inside(NewInt(1)),
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
	x := NewInt(13) //message
	a := NewInt(10) //encryption key
	inv := NewInt(0)
	inv = group.Inverse(a, inv)       //decryption key
	a = group.Mul(x, a, a)            // encrypted message
	c := group.Mul(inv, a, NewInt(0)) //decrypted message (x)

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

func TestSetSeed(t *testing.T) {
	p := NewInt(17)
	s := NewInt(15)
	min := NewInt(2)
	max := NewInt(1000)
	gen := NewGen(min, max)
	group := NewGroup(p, s, gen)
	expected := NewInt(10)
	group.SetSeed(expected)
	pass := 0
	tests := 1
	if group.seed.Cmp(expected) != 0 {
		t.Errorf("SetSeed() failed, expected: '%v', got: '%v'",
			expected.Text(10), group.seed.Text(10))
	} else {
		pass++
	}
	println("SetSeed()", pass, "out of", tests, "tests passed.")
}

func TestGen(t *testing.T) {
	// setup test group and generator
	p := NewInt(17)
	s := NewInt(15)
	min := NewInt(2)
	max := NewInt(1000)
	gen := NewGen(min, max)
	group := NewGroup(p, s, gen)

	// setup array to keep track of frequency of random values
	r := NewInt(0)
	rand := make([]int, int(p.Int64()))

	// how many tests and the threshold max to be sufficientyly random
	tests := 30
	pass := 0
	thresh := 0.3

	// generate randoms
	for i := 0; i < tests; i++ {
		rand[int(group.Gen(r).Int64())]++
	}

	// check that frequency doesn't exceed threshold
	for i := 0; i < len(rand); i++ {
		if float64(rand[i])/float64(tests) > thresh {
			t.Errorf("TestGen() failed, insufficiently random, value: %v"+
				" occured: %v out of %v tests", i, rand[i], tests)
		} else {
			pass = pass + rand[i]
		}
	}
	println("Gen()", pass, "out of", tests, "tests passed.")
}

func TestGetP(t *testing.T) {
	// setup test group and generator
	p := NewInt(17)
	s := NewInt(15)
	min := NewInt(2)
	max := NewInt(1000)
	gen := NewGen(min, max)
	group := NewGroup(p, s, gen)
	actual := group.GetP(NewInt(0))
	tests := 1
	pass := 0
	if actual.Cmp(p) != 0 {
		t.Errorf("TestGetP failed, expected: '%v', got: '%v'",
			p.Text(10), actual.Text(10))
	} else {
		pass++
	}
	println("GetP()", pass, "out of", tests, "tests passed.")
}

/*
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
