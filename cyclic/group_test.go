////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package cyclic

import (
	"crypto/sha256"
	"gitlab.com/elixxir/crypto/large"
	"math/rand"
	"testing"
)

// Tests NewGroup functionality
func TestNewGroup(t *testing.T) {
	p := large.NewInt(1000000010101111111)
	s := large.NewInt(192395897203)
	min := large.NewInt(2)
	max := large.NewInt(0)
	max.Mul(p, large.NewInt(1000))
	g := large.NewInt(5)
	rng := NewRandom(min, max)
	actual := NewGroup(p, s, g, rng)

	type testStruct struct {
		prime large.Int
		seed  large.Int
		g     large.Int
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

// Test creation of cyclicInt in the group from int64
func TestNewInt(t *testing.T) {
	p := large.NewInt(1000000010101111111)
	s := large.NewInt(192395897203)
	min := large.NewInt(2)
	max := large.NewInt(0)
	max.Mul(p, large.NewInt(1000))
	g := large.NewInt(5)
	rng := NewRandom(min, max)
	grp := NewGroup(p, s, g, rng)

	expected := large.NewInt(42)
	actual := grp.NewInt(42)

	if actual.value.Cmp(expected) != 0 {
		t.Errorf("NewInt creation failed, expected: %v,"+
			"got: %v", expected, actual.value)
	} else if actual.GetGroupFingerprint() != grp.GetFingerprint() {
		t.Errorf("NewInt is not in the group, expected group fingerprint: %v,"+
			"got: %v", grp.GetFingerprint(), actual.GetGroupFingerprint())
	}
}

// Test creation of cyclicInt in the group from large.Int
func TestNewIntFromLargeInt(t *testing.T) {
	p := large.NewInt(1000000010101111111)
	s := large.NewInt(192395897203)
	min := large.NewInt(2)
	max := large.NewInt(0)
	max.Mul(p, large.NewInt(1000))
	g := large.NewInt(5)
	rng := NewRandom(min, max)
	grp := NewGroup(p, s, g, rng)

	expected := large.NewInt(42)
	actual := grp.NewIntFromLargeInt(expected)

	if actual.value.Cmp(expected) != 0 {
		t.Errorf("NewIntFromLargeInt creation failed, expected: %v,"+
			"got: %v", expected, actual.value)
	} else if actual.GetGroupFingerprint() != grp.GetFingerprint() {
		t.Errorf("NewIntFromLargeInt is not in the group, expected group fingerprint: %v,"+
			"got: %v", grp.GetFingerprint(), actual.GetGroupFingerprint())
	}
}

// Test creation of cyclicInt in the group from byte array
func TestNewIntFromBytes(t *testing.T) {
	p := large.NewInt(1000000010101111111)
	s := large.NewInt(192395897203)
	min := large.NewInt(2)
	max := large.NewInt(0)
	max.Mul(p, large.NewInt(1000))
	g := large.NewInt(5)
	rng := NewRandom(min, max)
	grp := NewGroup(p, s, g, rng)

	expected := large.NewInt(42)
	value := []byte{0x2A}
	actual := grp.NewIntFromBytes(value)

	if actual.value.Cmp(expected) != 0 {
		t.Errorf("NewIntFromBytes creation failed, expected: %v,"+
			"got: %v", expected, actual.value)
	} else if actual.GetGroupFingerprint() != grp.GetFingerprint() {
		t.Errorf("NewIntFromBytes is not in the group, expected group fingerprint: %v,"+
			"got: %v", grp.GetFingerprint(), actual.GetGroupFingerprint())
	}
}

// Test creation of cyclicInt in the group from string
// Also confirm that if the string can't be converted, nil is returned
func TestNewIntFromString(t *testing.T) {
	p := large.NewInt(1000000010101111111)
	s := large.NewInt(192395897203)
	min := large.NewInt(2)
	max := large.NewInt(0)
	max.Mul(p, large.NewInt(1000))
	g := large.NewInt(5)
	rng := NewRandom(min, max)
	grp := NewGroup(p, s, g, rng)

	expected := large.NewInt(42)
	value := "42"
	actual := grp.NewIntFromString(value, 10)

	if actual.value.Cmp(expected) != 0 {
		t.Errorf("NewIntFromString creation failed, expected: %v,"+
			"got: %v", expected, actual.value)
	} else if actual.GetGroupFingerprint() != grp.GetFingerprint() {
		t.Errorf("NewIntFromString is not in the group, expected group fingerprint: %v,"+
			"got: %v", grp.GetFingerprint(), actual.GetGroupFingerprint())
	}

	errVal := grp.NewIntFromString("185", 5)

	if errVal != nil {
		t.Errorf("NewIntFromString should return nil when error occurs decoding string")
	}
}

// Test creation of cyclicInt in the group from max4kint
func TestNewMaxInt(t *testing.T) {
	p := large.NewInt(1000000010101111111)
	s := large.NewInt(192395897203)
	min := large.NewInt(2)
	max := large.NewInt(0)
	max.Mul(p, large.NewInt(1000))
	g := large.NewInt(5)
	rng := NewRandom(min, max)
	grp := NewGroup(p, s, g, rng)

	expected := large.NewMaxInt()
	actual := grp.NewMaxInt()

	if actual.value.Cmp(expected) != 0 {
		t.Errorf("NewMaxInt creation failed, expected: %v,"+
			"got: %v", expected, actual.value)
	} else if actual.GetGroupFingerprint() != grp.GetFingerprint() {
		t.Errorf("NewMaxInt is not in the group, expected group fingerprint: %v,"+
			"got: %v", grp.GetFingerprint(), actual.GetGroupFingerprint())
	}
}

// Test creation of cyclicInt in the group from uint64
func TestNewIntFromUInt(t *testing.T) {
	p := large.NewInt(1000000010101111111)
	s := large.NewInt(192395897203)
	min := large.NewInt(2)
	max := large.NewInt(0)
	max.Mul(p, large.NewInt(1000))
	g := large.NewInt(5)
	rng := NewRandom(min, max)
	grp := NewGroup(p, s, g, rng)

	expected := large.NewInt(42)
	actual := grp.NewIntFromUInt(uint64(42))

	if actual.value.Cmp(expected) != 0 {
		t.Errorf("NewIntFromUInt creation failed, expected: %v,"+
			"got: %v", expected, actual.value)
	} else if actual.GetGroupFingerprint() != grp.GetFingerprint() {
		t.Errorf("NewIntFromUInt is not in the group, expected group fingerprint: %v,"+
			"got: %v", grp.GetFingerprint(), actual.GetGroupFingerprint())
	}
}

// Test group fingerprint getter
func TestGetFingerprint(t *testing.T) {
	p := large.NewInt(1000000010101111111)
	s := large.NewInt(192395897203)
	min := large.NewInt(2)
	max := large.NewInt(0)
	max.Mul(p, large.NewInt(1000))
	g := large.NewInt(5)
	rng := NewRandom(min, max)
	grp := NewGroup(p, s, g, rng)

	h := sha256.New()
	h.Write(p.Bytes())
	h.Write(g.Bytes())
	expected := large.NewIntFromBytes(h.Sum(nil)[:GroupFingerprintSize]).Uint64()

	if grp.GetFingerprint() != expected {
		t.Errorf("GetFingerprint returned wrong value, expected: %v,"+
			"got: %v", expected, grp.GetFingerprint())
	}
}

// Test multiplication under the group
func TestMul(t *testing.T) {
	prime := int64(107)
	p := large.NewInt(prime)
	s := large.NewInt(15)
	min := large.NewInt(2)
	max := large.NewInt(1000)
	rng := NewRandom(min, max)
	g := large.NewInt(5)
	group := NewGroup(p, s, g, rng)

	actual := []*Int{
		group.Mul(group.NewInt(20), group.NewInt(11), group.NewInt(0)),
		group.Mul(group.NewInt(0), group.NewInt(10), group.NewInt(0)),
	}
	expected := []*Int{
		group.NewInt((20 * 11) % prime),
		group.NewInt(0),
	}

	tests := len(actual)
	pass := 0
	for i := 0; i < len(actual); i++ {
		if actual[i].value.Cmp(expected[i].value) != 0 {
			t.Errorf("TestMulForGroup failed at index:%v, expected:%v, got:%v",
				i, expected[i].value.Text(10), actual[i].value.Text(10))
		} else {
			pass++
		}
	}
	println("Mul()", pass, "out of", tests, "tests passed.")
}

// Test that mul panics if cyclicInt doesn't belong to the group
func TestMul_Panic(t *testing.T) {
	prime := int64(107)
	p := large.NewInt(prime)
	s := large.NewInt(15)
	min := large.NewInt(2)
	max := large.NewInt(1000)
	rng := NewRandom(min, max)
	g := large.NewInt(5)
	group := NewGroup(p, s, g, rng)
	g2 := large.NewInt(2)
	group2 := NewGroup(p, s, g2, rng)

	a := group.NewInt(20)
	b := group2.NewInt(11)
	c := group.NewInt(0)

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Mul should panic when one of involved " +
				"cyclicInts doesn't belong to the group")
		}
	}()

	group.Mul(a, b, c)
}

// Test Inside that checks if a number is inside the group
func TestInside(t *testing.T) {
	p := large.NewInt(17)
	s := large.NewInt(15)
	min := large.NewInt(2)
	max := large.NewInt(1000)
	rng := NewRandom(min, max)
	g := large.NewInt(7)
	group := NewGroup(p, s, g, rng)
	expected := []bool{
		false,
		true,
		false,
		false,
		true,
	}
	actual := []bool{
		group.Inside(group.NewInt(0)),
		group.Inside(group.NewInt(1)),
		group.Inside(group.NewInt(17)),
		group.Inside(group.NewInt(18)),
		group.Inside(group.NewInt(12)),
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

// Test that inside panics if cyclicInt doesn't belong to the group
func TestInside_Panic(t *testing.T) {
	prime := int64(107)
	p := large.NewInt(prime)
	s := large.NewInt(15)
	min := large.NewInt(2)
	max := large.NewInt(1000)
	rng := NewRandom(min, max)
	g := large.NewInt(5)
	group := NewGroup(p, s, g, rng)
	g2 := large.NewInt(2)
	group2 := NewGroup(p, s, g2, rng)

	a := group2.NewInt(20)

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Inside should panic when " +
				"cyclicInt doesn't belong to the group")
		}
	}()

	group.Inside(a)
}

// Test modulus under the group
func TestModP(t *testing.T) {
	p := []large.Int{large.NewInt(17), large.NewIntFromString("717190887961", 10),
		large.NewIntFromString("717190905917", 10)}
	s := large.NewInt(15)
	min := large.NewInt(2)
	max := large.NewInt(1000)
	g := large.NewInt(13)
	rng := NewRandom(min, max)

	group := make([]Group, 0, len(p))
	for i := 0; i < len(p); i++ {
		group = append(group, NewGroup(p[i], s, g, rng))
	}

	expected := []large.Int{large.NewInt(2), large.NewIntFromString("269673339004", 10),
		large.NewIntFromString("623940771224", 10)}
	a := []large.Int{large.NewInt(5000), large.NewIntFromString("beefbeecafe80386", 16),
		large.NewIntFromString("77777777777777777777", 16)}
	actual := make([]*Int, len(expected))
	for i := 0; i < len(expected); i++ {
		actual[i] = group[i].NewIntFromLargeInt(a[i])
		group[i].ModP(actual[i], actual[i])
	}

	tests := 3
	pass := 0

	for i := 0; i < len(expected); i++ {
		if actual[i].value.Cmp(expected[i]) != 0 {
			t.Errorf("TestModP failed, expected: '%v', got: '%v'",
				expected[i].Text(10), actual[i].value.Text(10))
		} else {
			pass++
		}
	}
	println("ModP()", pass, "out of", tests, "tests passed.")
}

// Test that inside panics if cyclicInt doesn't belong to the group
func TestModP_Panic(t *testing.T) {
	prime := int64(107)
	p := large.NewInt(prime)
	s := large.NewInt(15)
	min := large.NewInt(2)
	max := large.NewInt(1000)
	rng := NewRandom(min, max)
	g := large.NewInt(5)
	group := NewGroup(p, s, g, rng)
	g2 := large.NewInt(2)
	group2 := NewGroup(p, s, g2, rng)

	a := group.NewInt(20)
	b := group2.NewInt(0)

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("ModP should panic when one of involved " +
				"cyclicInts doesn't belong to the group")
		}
	}()

	group.ModP(a, b)
}

// Test Inverse under the group
func TestInverse(t *testing.T) {
	p := large.NewInt(17)
	s := large.NewInt(15)
	min := large.NewInt(2)
	max := large.NewInt(1000)
	g := large.NewInt(13)
	rng := NewRandom(min, max)
	group := NewGroup(p, s, g, rng)
	x := group.NewInt(13) //message
	a := group.NewInt(10) //encryption key
	inv := group.NewInt(0)
	inv = group.Inverse(a, inv)             //decryption key
	a = group.Mul(x, a, a)                  // encrypted message
	c := group.Mul(inv, a, group.NewInt(0)) //decrypted message (x)

	tests := 1
	pass := 0

	if c.value.Cmp(x.value) != 0 {
		t.Errorf("TestInverse failed, expected: '%v', got: '%v'",
			x.value.Text(10), c.value.Text(10))
	} else {
		pass++
	}
	println("Inverse()", pass, "out of", tests, "tests passed.")
}

// Test that inverse panics if cyclicInt doesn't belong to the group
func TestInverse_Panic(t *testing.T) {
	prime := int64(107)
	p := large.NewInt(prime)
	s := large.NewInt(15)
	min := large.NewInt(2)
	max := large.NewInt(1000)
	rng := NewRandom(min, max)
	g := large.NewInt(5)
	group := NewGroup(p, s, g, rng)
	g2 := large.NewInt(2)
	group2 := NewGroup(p, s, g2, rng)

	a := group.NewInt(20)
	b := group2.NewInt(0)

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Inverse should panic when one of involved " +
				"cyclicInts doesn't belong to the group")
		}
	}()

	group.Inverse(a, b)
}

// Test setting the seed of the group
func TestSetSeed(t *testing.T) {
	p := large.NewInt(17)
	s := large.NewInt(15)
	min := large.NewInt(2)
	max := large.NewInt(1000)
	rng := NewRandom(min, max)
	g := large.NewInt(9)
	group := NewGroup(p, s, g, rng)
	expected := large.NewInt(10)
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

// This test proves that group.Random() probably never generates a random number
// outside of the cyclic group
func TestRandom(t *testing.T) {
	p := large.NewInt(5)
	s := large.NewInt(3)
	min := large.NewInt(0)
	max := large.NewInt(1000)
	rng := NewRandom(min, max)
	g := large.NewInt(4)
	group := NewGroup(p, s, g, rng)
	for i := 0; i < 100000; i++ {
		group.Random(group.NewInt(0))
	}
}

// This test forces random to panic by overwriting the group P
func TestRandom_Error(t *testing.T) {
	p := large.NewInt(5)
	s := large.NewInt(3)
	min := large.NewInt(0)
	max := large.NewInt(1000)
	rng := NewRandom(min, max)
	g := large.NewInt(4)
	group := NewGroup(p, s, g, rng)

	// Overwrite p, which doesn't change internal psub2, which is used in rand
	group.prime = large.NewInt(1)

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Random should panic when generating a number outside the group")
		}
	}()

	group.Random(group.NewInt(0))
}

// Test that random panics if cyclicInt doesn't belong to the group
func TestRandom_Panic(t *testing.T) {
	prime := int64(107)
	p := large.NewInt(prime)
	s := large.NewInt(15)
	min := large.NewInt(2)
	max := large.NewInt(1000)
	rng := NewRandom(min, max)
	g := large.NewInt(5)
	group := NewGroup(p, s, g, rng)
	g2 := large.NewInt(2)
	group2 := NewGroup(p, s, g2, rng)

	a := group2.NewInt(20)

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Random should panic when " +
				"cyclicInt doesn't belong to the group")
		}
	}()

	group.Random(a)
}

func TestGen(t *testing.T) {
	// setup test group and generator
	p := large.NewInt(17)
	s := large.NewInt(15)
	min := large.NewInt(2)
	max := large.NewInt(1000)
	g := large.NewInt(29)
	rng := NewRandom(min, max)
	group := NewGroup(p, s, g, rng)

	// setup array to keep track of frequency of random values
	r := group.NewInt(0)
	rand := make([]int, int(p.Int64()))

	// how many tests and the threshold max to be sufficientyly random
	tests := 500
	pass := 0
	thresh := 0.3

	// generate randoms
	for i := 0; i < tests; i++ {
		rand[int(group.Random(r).value.Int64())]++
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

// Test prime getter from the group
func TestGetP(t *testing.T) {
	// setup test group and generator
	p := large.NewInt(17)
	s := large.NewInt(15)
	min := large.NewInt(2)
	max := large.NewInt(1000)
	rng := NewRandom(min, max)
	g := large.NewInt(29)
	group := NewGroup(p, s, g, rng)
	actual := group.GetP()
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

// Test prime-1 getter from the group
func TestGetPSub1(t *testing.T) {
	// setup test group and generator
	p := large.NewInt(17)
	s := large.NewInt(15)
	min := large.NewInt(2)
	max := large.NewInt(1000)
	rng := NewRandom(min, max)
	g := large.NewInt(29)
	group := NewGroup(p, s, g, rng)
	actual := group.GetPSub1()
	ps1 := large.NewInt(16)
	tests := 1
	pass := 0
	if actual.Cmp(ps1) != 0 {
		t.Errorf("TestGetPSub1 failed, expected: '%v', got: '%v'",
			ps1.Text(10), actual.Text(10))
	} else {
		pass++
	}
	println("GetPSub1()", pass, "out of", tests, "tests passed.")
}

// Test array multiplication under the group
func TestArrayMul(t *testing.T) {
	tests := 1
	pass := 0

	p := large.NewInt(11)

	expected := large.NewInt(10)

	min := large.NewInt(2)
	max := large.NewInt(0)
	max.Mul(p, large.NewInt(1000))
	seed := large.NewInt(42)
	rng := NewRandom(min, max)
	g := large.NewInt(7)

	grp := NewGroup(p, seed, g, rng)

	slc := []*Int{
		grp.NewInt(2),
		grp.NewInt(3),
		grp.NewInt(4),
		grp.NewInt(5),
	}

	c := grp.NewInt(42)
	actual := grp.ArrayMul(slc, c)

	if actual.value.Cmp(expected) != 0 {
		t.Errorf("TestArrayMul failed, expected: '%v', got: '%v'",
			expected, actual)
	} else {
		pass++
	}

	println("ArrayMul()", pass, "out of", tests, "tests passed.")
}

// Test that ArrayMult panics if cyclicInt doesn't belong to the group
func TestArrayMult_Panic(t *testing.T) {
	prime := int64(107)
	p := large.NewInt(prime)
	s := large.NewInt(15)
	min := large.NewInt(2)
	max := large.NewInt(1000)
	rng := NewRandom(min, max)
	g := large.NewInt(5)
	group := NewGroup(p, s, g, rng)
	g2 := large.NewInt(2)
	group2 := NewGroup(p, s, g2, rng)

	slc := []*Int{
		group.NewInt(2),
		group2.NewInt(3),
		group.NewInt(4),
		group.NewInt(5),
	}
	a := group.NewInt(20)

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("ArrayMult should panic when one of involved " +
				"cyclicInts doesn't belong to the group")
		}
	}()

	group.ArrayMul(slc, a)
}

// Test exponentiation under the group
func TestExp(t *testing.T) {
	p := large.NewInt(11)
	min := large.NewInt(2)
	max := large.NewInt(0)
	max.Mul(p, large.NewInt(1000))
	seed := large.NewInt(42)
	rng := NewRandom(min, max)
	g := large.NewInt(7)
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

	for i, strs := range testStrings {
		var ts testStructure

		ts.x = grp.NewIntFromString(strs[0], 10)

		if ts.x == nil {
			t.Errorf("Setup for Test of Exp() for Group failed at 'x' phase of index: %v", i)
		}

		ts.y = grp.NewIntFromString(strs[1], 10)

		if ts.y == nil {
			t.Errorf("Setup for Test of Exp() for Group failed at 'y' phase of index: %v", i)
		}

		ts.z = grp.NewIntFromString(strs[2], 10)

		if ts.z == nil {
			t.Errorf("Setup for Test of Exp() for Group failed at 'z' phase of index: %v", i)
		}

		testStructs = append(testStructs, ts)
	}

	tests := len(testStructs)
	pass := 0

	expected := 0

	for i, testi := range testStructs {
		actual := grp.NewInt(0)
		actual = grp.Exp(testi.x, testi.y, actual)

		result := actual.value.Cmp(testi.z.value)

		if result != expected {
			t.Errorf("Test of Exp() for Group failed at index: %v Expected: %v, %v; Actual: %v, %v",
				i, expected, testi.z.value.Text(10), result, actual.value.Text(10))
		} else {
			pass += 1
		}
	}
	println("Exp() for Group", pass, "out of", tests, "tests passed.")

}

// Test that Exp panics if cyclicInt doesn't belong to the group
func TestExp_Panic(t *testing.T) {
	prime := int64(107)
	p := large.NewInt(prime)
	s := large.NewInt(15)
	min := large.NewInt(2)
	max := large.NewInt(1000)
	rng := NewRandom(min, max)
	g := large.NewInt(5)
	group := NewGroup(p, s, g, rng)
	g2 := large.NewInt(2)
	group2 := NewGroup(p, s, g2, rng)

	a := group2.NewInt(20)
	b := group.NewInt(11)
	c := group.NewInt(0)

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Exp should panic when one of involved " +
				"cyclicInts doesn't belong to the group")
		}
	}()

	group.Exp(a, b, c)
}

// Test random Coprime number generation under the group
func TestRandomCoprime(t *testing.T) {
	// setup test group and generator
	p := large.NewInt(17)
	s := large.NewInt(15)
	min := large.NewInt(2)
	max := large.NewInt(1000)
	g := large.NewInt(29)
	rng := NewRandom(min, max)
	group := NewGroup(p, s, g, rng)

	// setup array to keep track of frequency of random values
	r := group.NewInt(0)
	rand := make([]int, int(p.Int64()))

	// how many tests and the threshold max to be sufficientyly random
	tests := 500
	pass := 0
	thresh := 0.3

	// generate randoms
	for i := 0; i < tests; i++ {
		rand[int(group.RandomCoprime(r).value.Int64())]++
	}

	// make sure 0 and 1 were not generated
	if rand[0] > 0 {
		t.Errorf("TestRandomeCoprime() failed, 0 is outside of the required range")
	}
	if rand[1] > 0 {
		t.Errorf("TestRandomeCoprime() failed, 1 is outside of the required range")
	}

	// check that frequency doesn't exceed threshold
	for i := 0; i < len(rand); i++ {
		if float64(rand[i])/float64(tests) > thresh {
			t.Errorf("TestRandomCoprime() failed, insufficiently random, value: %v"+
				" occured: %v out of %v tests", i, rand[i], tests)
		} else {
			pass = pass + rand[i]
		}
	}
	println("Random()", pass, "out of", tests, "tests passed.")
}

// Test that RandomCoprime panics if cyclicInt doesn't belong to the group
func TestRandomCoprime_Panic(t *testing.T) {
	prime := int64(107)
	p := large.NewInt(prime)
	s := large.NewInt(15)
	min := large.NewInt(2)
	max := large.NewInt(1000)
	rng := NewRandom(min, max)
	g := large.NewInt(5)
	group := NewGroup(p, s, g, rng)
	g2 := large.NewInt(2)
	group2 := NewGroup(p, s, g2, rng)

	a := group2.NewInt(20)

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("RandomCoprime should panic when " +
				"cyclicInt doesn't belong to the group")
		}
	}()

	group.RandomCoprime(a)
}

// You pass a value x = a^y to the RootCoprime function, where y is (supposed to be) coprime with (p-1).
// If y is coprime, then the function returns the value of a
func TestRootCoprime(t *testing.T) {
	tests := 2
	pass := 0

	p := large.NewInt(17)
	s := large.NewInt(15)
	g := large.NewInt(29)
	min := large.NewInt(2)
	max := large.NewInt(1000)
	rng := NewRandom(min, max)

	group := NewGroup(p, s, g, rng)

	a := []*Int{group.NewInt(5), group.NewInt(4), group.NewInt(15)}
	x := group.NewInt(0)
	y := []*Int{group.NewInt(5), group.NewInt(11), group.NewInt(2)}
	z := []*Int{group.NewInt(0), group.NewInt(0), group.NewInt(0)}

	passing := []bool{true, true, false}

	for i := 0; i < 2; i++ {
		group.Exp(a[i], y[i], x)

		group.RootCoprime(x, y[i], z[i])

		if z[i].value.Cmp(a[i].value) != 0 && passing[i] {
			t.Errorf("RootCoprime Error: Function did not output expected value!")
		} else {
			pass++
		}

	}

	println("RootCoprime", pass, "out of", tests, "tests passed.")
}

// Test that RootCoprime panics if cyclicInt doesn't belong to the group
func TestRootCoprime_Panic(t *testing.T) {
	prime := int64(107)
	p := large.NewInt(prime)
	s := large.NewInt(15)
	min := large.NewInt(2)
	max := large.NewInt(1000)
	rng := NewRandom(min, max)
	g := large.NewInt(5)
	group := NewGroup(p, s, g, rng)
	g2 := large.NewInt(2)
	group2 := NewGroup(p, s, g2, rng)

	a := group.NewInt(20)
	b := group.NewInt(11)
	c := group2.NewInt(0)

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("RootCoprime should panic when one of involved " +
				"cyclicInts doesn't belong to the group")
		}
	}()

	group.RootCoprime(a, b, c)
}

// Test finding a small coprime inverse number in the group
func TestFindSmallCoprimeInverse(t *testing.T) {
	primeString := "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
		"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
		"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
		"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
		"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
		"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
		"15728E5A8AACAA68FFFFFFFFFFFFFFFF"

	p := large.NewIntFromString(primeString, 16)
	s := large.NewInt(2)
	g := large.NewInt(2)
	min := large.NewInt(2)
	max := large.NewInt(1000)
	rng := NewRandom(min, max)
	group := NewGroup(p, s, g, rng)

	num := 1000

	totalBitLen := 0

	bits := uint32(256)

	for i := 0; i < num; i++ {
		z := group.NewInt(0)

		base := group.Random(group.NewInt(0))

		group.FindSmallCoprimeInverse(z, bits)

		zinv := large.NewInt(0).ModInverse(z.value, group.psub1)

		totalBitLen += len(zinv.Bytes()) * 8

		if len(zinv.Bytes())*8 > int(bits) {
			t.Errorf("FindSmallExponent Error: Inverse too large on "+
				"attempt %v; Expected: <%v, Recieved: %v", i, bits,
				uint32(len(zinv.Bytes())*8))
		}

		baseZ := group.NewInt(0)

		group.Exp(base, z, baseZ)

		basecalc := group.NewInt(0)

		basecalc = group.RootCoprime(baseZ, z, basecalc)

		if base.value.Cmp(basecalc.value) != 0 {
			t.Errorf("FindSmallExponent Error: Result incorrect"+
				" on attempt %v; Expected: %s, Recieved: %s", i, base.value.Text(10),
				basecalc.value.Text(10))
		}
	}

	avgBitLen := float32(totalBitLen) / float32(num)

	if float32(avgBitLen) < 0.98*float32(bits) {
		t.Errorf("FindSmallExponent Error: Inverses are not the correct length on average "+
			"; Expected: ~%v, Recieved: %v", 0.95*float32(bits), avgBitLen)
	}

}

// Test finding a small coprime inverse in a group with small p
// This will hit the case where the generated number equals (p-1)/2
func TestFindSmallCoprimeInverse_SmallGroup(t *testing.T) {
	p := large.NewInt(107)
	s := large.NewInt(2)
	g := large.NewInt(2)
	min := large.NewInt(2)
	max := large.NewInt(1000)
	rng := NewRandom(min, max)

	group := NewGroup(p, s, g, rng)
	one := large.NewInt(1)
	num := 1000

	bits := uint32(p.BitLen()-1)

	for i := 0; i < num; i++ {
		z := group.NewInt(1)

		base := group.Random(group.NewInt(0))

		// z will be unchanged if a number with no inverse is returned
		for z.value.Cmp(one) == 0 {
			group.FindSmallCoprimeInverse(z, bits)
		}

		zinv := large.NewInt(0).ModInverse(z.value, group.psub1)

		if zinv.BitLen() > int(bits) {
			t.Errorf("FindSmallExponent Error: Inverse too large on "+
				"attempt %v; Expected: <%v, Recieved: %v", i, bits,
				zinv.BitLen())
		}

		baseZ := group.NewInt(0)

		group.Exp(base, z, baseZ)

		basecalc := group.NewInt(0)

		basecalc = group.RootCoprime(baseZ, z, basecalc)

		if base.value.Cmp(basecalc.value) != 0 {
			t.Errorf("FindSmallExponent Error: Result incorrect"+
				" on attempt %v; Expected: %s, Recieved: %s", i, base.value.Text(10),
				basecalc.value.Text(10))
		}
	}
}

// Test finding a small coprime inverse in an unsafe group, meaning
// that some numbers don't have an inverse
func TestFindSmallCoprimeInverse_UnsafeGroup(t *testing.T) {
	p := large.NewInt(101)
	s := large.NewInt(2)
	g := large.NewInt(2)
	min := large.NewInt(2)
	max := large.NewInt(1000)
	rng := NewRandom(min, max)

	group := NewGroup(p, s, g, rng)
	one := large.NewInt(1)
	num := 1000

	bits := uint32(6)

	for i := 0; i < num; i++ {
		z := group.NewInt(1)

		base := group.Random(group.NewInt(0))

		// z will be unchanged if a number with no inverse is returned
		for z.value.Cmp(one) == 0 {
			group.FindSmallCoprimeInverse(z, bits)
		}

		zinv := large.NewInt(0).ModInverse(z.value, group.psub1)

		if zinv.BitLen() > int(bits) {
			t.Errorf("FindSmallExponent Error: Inverse too large on "+
				"attempt %v; Expected: <%v, Recieved: %v", i, bits,
				zinv.BitLen())
		}

		baseZ := group.NewInt(0)

		group.Exp(base, z, baseZ)

		basecalc := group.NewInt(0)

		basecalc = group.RootCoprime(baseZ, z, basecalc)

		if base.value.Cmp(basecalc.value) != 0 {
			t.Errorf("FindSmallExponent Error: Result incorrect"+
				" on attempt %v; Expected: %s, Recieved: %s", i, base.value.Text(10),
				basecalc.value.Text(10))
		}
	}
}

// Test that FindSmallCoprimeInverse panics when number of bits is >= log2(p)
func TestFindSmallCoprimeInverse_Panic(t *testing.T) {
	p := large.NewInt(107)
	s := large.NewInt(2)
	g := large.NewInt(2)
	min := large.NewInt(2)
	max := large.NewInt(1000)
	rng := NewRandom(min, max)

	group := NewGroup(p, s, g, rng)
	z := group.NewInt(1)

	bits := uint32(7)

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("FindSmallCoprimeInverse should panic on bits >= log2(g.prime)")
		}
	}()

	group.FindSmallCoprimeInverse(z, bits)
}

// Test that FindSmallCoprimeInverse panics if cyclicInt doesn't belong to the group
func TestFindSmallCoprimeInverse_PanicArgs(t *testing.T) {
	prime := int64(107)
	p := large.NewInt(prime)
	s := large.NewInt(15)
	min := large.NewInt(2)
	max := large.NewInt(1000)
	rng := NewRandom(min, max)
	g := large.NewInt(5)
	group := NewGroup(p, s, g, rng)
	g2 := large.NewInt(2)
	group2 := NewGroup(p, s, g2, rng)

	a := group2.NewInt(20)

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("RootCoprime should panic when " +
				"cyclicInt doesn't belong to the group")
		}
	}()

	group.FindSmallCoprimeInverse(a, uint32(p.BitLen()-1))
}

// BENCHMARKS

func BenchmarkExpForGroup(b *testing.B) {
	primeString := "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
		"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
		"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
		"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
		"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
		"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
		"15728E5A8AACAA68FFFFFFFFFFFFFFFF"

	p := large.NewIntFromString(primeString, 16)
	min := large.NewInt(2)
	max := large.NewInt(0)
	max.Mul(p, large.NewInt(1000))
	seed := large.NewInt(42)
	rng := NewRandom(min, max)
	g := large.NewInt(2)
	grp := NewGroup(p, seed, g, rng)

	//prebake inputs

	r := rand.New(rand.NewSource(42))
	z := grp.NewInt(0)
	G := grp.NewIntFromLargeInt(grp.G)

	var inputs []*Int
	var outputs []*Int

	for i := 0; i < b.N; i++ {
		byteField := make([]byte, 32)
		r.Read(byteField)
		nint := grp.NewIntFromBytes(byteField)
		inputs = append(inputs, nint)
		outputs = append(outputs, grp.NewInt(0))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		grp.Exp(G, inputs[i], z)
	}
}

func BenchmarkMulForGroup(b *testing.B) {
	primeString := "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
		"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
		"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
		"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
		"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
		"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
		"15728E5A8AACAA68FFFFFFFFFFFFFFFF"

	p := large.NewIntFromString(primeString, 16)
	min := large.NewInt(2)
	max := large.NewInt(0)
	max.Mul(p, large.NewInt(1000))
	seed := large.NewInt(42)
	rng := NewRandom(min, max)
	g := large.NewInt(2)
	grp := NewGroup(p, seed, g, rng)

	//prebake inputs

	r := rand.New(rand.NewSource(42))
	z := grp.NewInt(0)

	var inputA []*Int
	var inputB []*Int
	var outputs []*Int

	for i := 0; i < b.N; i++ {
		byteField := make([]byte, 255)
		r.Read(byteField)
		nint := grp.NewIntFromBytes(byteField)
		inputA = append(inputA, nint)
		r.Read(byteField)
		mint := grp.NewIntFromBytes(byteField)
		inputB = append(inputB, mint)
		outputs = append(outputs, grp.NewInt(0))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		grp.Mul(inputA[i], inputB[i], z)
	}
}

func BenchmarkInverse(b *testing.B) {
	primeString := "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
		"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
		"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
		"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
		"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
		"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
		"15728E5A8AACAA68FFFFFFFFFFFFFFFF"

	p := large.NewIntFromString(primeString, 16)
	min := large.NewInt(2)
	max := large.NewInt(0)
	max.Mul(p, large.NewInt(1000))
	seed := large.NewInt(42)
	rng := NewRandom(min, max)
	g := large.NewInt(2)
	grp := NewGroup(p, seed, g, rng)

	//prebake inputs

	r := rand.New(rand.NewSource(42))
	z := grp.NewInt(0)
	G := grp.NewIntFromLargeInt(grp.G)

	var inputs []*Int
	var outputs []*Int

	for i := 0; i < b.N; i++ {
		byteField := make([]byte, 256)
		r.Read(byteField)
		nint := grp.NewIntFromBytes(byteField)
		nint = grp.Exp(G, nint, z)
		inputs = append(inputs, nint)
		outputs = append(outputs, grp.NewInt(0))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		grp.Inverse(inputs[i], outputs[i])
	}
}
