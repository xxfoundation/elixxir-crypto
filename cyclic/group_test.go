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
	g := NewInt(5)
	rng := NewRandom(min, max)
	actual := NewGroup(p, s, g, rng)

	type testStruct struct {
		prime *Int
		seed  *Int
		g     *Int
		rng   Random
	}
	expected := testStruct{p, s, g, rng}
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
	rng := NewRandom(min, max)
	g := NewInt(5)
	group := NewGroup(p, s, g, rng)

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
	rng := NewRandom(min, max)
	g := NewInt(7)
	group := NewGroup(p, s, g, rng)
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
	g := NewInt(13)
	rng := NewRandom(min, max)
	group := NewGroup(p, s, g, rng)
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

func TestModP(t *testing.T) {
	p := []*Int{NewInt(17), NewIntFromString("717190887961", 10),
		NewIntFromString("717190905917", 10)}
	s := NewInt(15)
	min := NewInt(2)
	max := NewInt(1000)
	g := NewInt(13)
	rng := NewRandom(min, max)

	group := make([]Group, 0, len(p))
	for i := 0; i < len(p); i++ {
		group = append(group, NewGroup(p[i], s, g, rng))
	}

	expected := []*Int{NewInt(2), NewIntFromString("269673339004", 10),
		NewIntFromString("623940771224", 10)}
	a := []*Int{NewInt(5000), NewIntFromString("beefbeecafe80386", 16),
		NewIntFromString("77777777777777777777", 16)}
	actual := []*Int{NewInt(0), NewInt(0), NewInt(0)}
	for i := 0; i < len(actual); i++ {
		actual[i] = group[i].ModP(a[i], actual[i])
	}

	tests := 3
	pass := 0

	for i := 0; i < len(expected); i++ {
		if actual[i].Cmp(expected[i]) != 0 {
			t.Errorf("TestModP failed, expected: '%v', got: '%v'",
				expected[i].Text(10), actual[i].Text(10))
		} else {
			pass++
		}
	}
	println("ModP()", pass, "out of", tests, "tests passed.")
}

func TestSetSeed(t *testing.T) {
	p := NewInt(17)
	s := NewInt(15)
	min := NewInt(2)
	max := NewInt(1000)
	rng := NewRandom(min, max)
	g := NewInt(9)
	group := NewGroup(p, s, g, rng)
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
	g := NewInt(29)
	rng := NewRandom(min, max)
	group := NewGroup(p, s, g, rng)

	// setup array to keep track of frequency of random values
	r := NewInt(0)
	rand := make([]int, int(p.Int64()))

	// how many tests and the threshold max to be sufficientyly random
	tests := 500
	pass := 0
	thresh := 0.3

	// generate randoms
	for i := 0; i < tests; i++ {
		rand[int(group.Random(r).Int64())]++
	}

	// make sure 0 and 1 were not generated
	if rand[0] > 0 {
		t.Errorf("TestGen() failed, 0 is outside of the required range")
	}
	if rand[1] > 0 {
		t.Errorf("TestGen() failed, 1 is outside of the required range")
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
	println("Random()", pass, "out of", tests, "tests passed.")
}

func TestGetP(t *testing.T) {
	// setup test group and generator
	p := NewInt(17)
	s := NewInt(15)
	min := NewInt(2)
	max := NewInt(1000)
	rng := NewRandom(min, max)
	g := NewInt(29)
	group := NewGroup(p, s, g, rng)
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

func TestArrayMul(t *testing.T) {
	tests := 1
	pass := 0

	p := NewInt(11)

	expected := NewInt(10)

	min := NewInt(2)
	max := NewInt(0)
	max.Mul(p, NewInt(1000))
	seed := NewInt(42)
	rng := NewRandom(min, max)
	g := NewInt(7)

	grp := NewGroup(p, seed, g, rng)

	slc := []*Int{
		NewInt(2),
		NewInt(3),
		NewInt(4),
		NewInt(5),
	}

	c := NewInt(42)
	actual := grp.ArrayMul(slc, c)

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
	rng := NewRandom(min, max)
	g := NewInt(7)

	grp := NewGroup(p, seed, g, rng)

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
		actual = grp.Exp(testi.x, testi.y, actual)

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
	rng := NewRandom(min, max)
	g := NewInt(9)

	grp := NewGroup(p, seed, g, rng)

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

		grp.Inverse(testi.y, inv)

		actual = grp.Exp(testi.x, inv, actual)

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
