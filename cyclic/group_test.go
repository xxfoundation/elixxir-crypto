////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package cyclic

import (
	"math/rand"
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
	prime := int64(107)

	p := NewInt(prime)
	s := NewInt(15)
	min := NewInt(2)
	max := NewInt(1000)
	rng := NewRandom(min, max)
	g := NewInt(5)
	group := NewGroup(p, s, g, rng)

	actual := []*Int{
		group.Mul(NewInt(20), NewInt(11), NewInt(0)),
		group.Mul(NewInt(0), NewInt(10), NewInt(0)),
	}
	expected := []*Int{
		NewInt((20 * 11) % prime),
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

// This test proves that group.Random() probably never generates a random number
// outside of the cyclic group
func TestRandomInsidePanic(t *testing.T) {
	p := NewInt(5)
	s := NewInt(3)
	min := NewInt(0)
	max := NewInt(1000)
	rng := NewRandom(min, max)
	g := NewInt(4)
	group := NewGroup(p, s, g, rng)
	for i := 0; i < 100000; i++ {
		group.Random(NewInt(0))
	}
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

func TestGetPSub1(t *testing.T) {
	// setup test group and generator
	p := NewInt(17)
	s := NewInt(15)
	min := NewInt(2)
	max := NewInt(1000)
	rng := NewRandom(min, max)
	g := NewInt(29)
	group := NewGroup(p, s, g, rng)
	actual := group.GetPSub1(NewInt(0))
	ps1 := NewInt(16)
	tests := 1
	pass := 0
	if actual.Cmp(ps1) != 0 {
		t.Errorf("TestGetP failed, expected: '%v', got: '%v'",
			ps1.Text(10), actual.Text(10))
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

	p := NewIntFromString(primeString, 16)
	min := NewInt(2)
	max := NewInt(0)
	max.Mul(p, NewInt(1000))
	seed := NewInt(42)
	rng := NewRandom(min, max)
	g := NewInt(2)
	grp := NewGroup(p, seed, g, rng)

	//prebake inputs

	r := rand.New(rand.NewSource(42))
	z := NewInt(0)

	var inputs []*Int
	var outputs []*Int

	for i := 0; i < b.N; i++ {
		byteField := make([]byte, 32)
		r.Read(byteField)
		nint := NewIntFromBytes(byteField)
		inputs = append(inputs, nint)
		outputs = append(outputs, NewInt(0))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		grp.Exp(g, inputs[i], z)
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

	p := NewIntFromString(primeString, 16)
	min := NewInt(2)
	max := NewInt(0)
	max.Mul(p, NewInt(1000))
	seed := NewInt(42)
	rng := NewRandom(min, max)
	g := NewInt(2)
	grp := NewGroup(p, seed, g, rng)

	//prebake inputs

	r := rand.New(rand.NewSource(42))
	z := NewInt(0)

	var inputA []*Int
	var inputB []*Int
	var outputs []*Int

	for i := 0; i < b.N; i++ {
		byteField := make([]byte, 255)
		r.Read(byteField)
		nint := NewIntFromBytes(byteField)
		inputA = append(inputA, nint)
		r.Read(byteField)
		mint := NewIntFromBytes(byteField)
		inputB = append(inputB, mint)
		outputs = append(outputs, NewInt(0))
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

	p := NewIntFromString(primeString, 16)
	min := NewInt(2)
	max := NewInt(0)
	max.Mul(p, NewInt(1000))
	seed := NewInt(42)
	rng := NewRandom(min, max)
	g := NewInt(2)
	grp := NewGroup(p, seed, g, rng)

	//prebake inputs

	r := rand.New(rand.NewSource(42))
	z := NewInt(0)

	var inputs []*Int
	var outputs []*Int

	for i := 0; i < b.N; i++ {
		byteField := make([]byte, 256)
		r.Read(byteField)
		nint := NewIntFromBytes(byteField)
		nint = grp.Exp(g, nint, z)
		inputs = append(inputs, nint)
		outputs = append(outputs, NewInt(0))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		grp.Inverse(inputs[i], outputs[i])
	}
}

func TestRandomCoprime(t *testing.T) {
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
		rand[int(group.RandomCoprime(r).Int64())]++
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

// You pass a value x = a^y to the RootCoprime function, where y is (supposed to be) coprime with (p-1).
// If y is coprime, then the function returns the value of a
func TestGroup_RootCoprime(t *testing.T) {

	tests := 2
	pass := 0

	p := NewInt(17)
	s := NewInt(15)
	g := NewInt(29)
	min := NewInt(2)
	max := NewInt(1000)
	rng := NewRandom(min, max)

	group := NewGroup(p, s, g, rng)

	a := []*Int{NewInt(5), NewInt(4), NewInt(15)}
	x := NewInt(0)
	y := []*Int{NewInt(5), NewInt(11), NewInt(2)}
	z := []*Int{NewInt(0), NewInt(0), NewInt(0)}

	passing := []bool{true, true, false}

	for i := 0; i < 2; i++ {
		group.Exp(a[i], y[i], x)

		group.RootCoprime(x, y[i], z[i])

		if z[i].Cmp(a[i]) != 0 && passing[i] {
			t.Errorf("RootCoprime Error: Function did not output expected value!")
		} else {
			pass++
		}

	}

	println("RootCoprime", pass, "out of", tests, "tests passed.")
}

func TestGroup_FindSmallCoprimeInverse(t *testing.T) {
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

	p := NewIntFromString(primeString, 16)

	s := NewInt(2)
	g := NewInt(2)
	min := NewInt(2)
	max := NewInt(1000)
	rng := NewRandom(min, max)

	group := NewGroup(p, s, g, rng)

	num := 1000

	totalBitLen := 0

	bits := uint32(256)

	for i := 0; i < num; i++ {
		z := NewInt(0)

		base := group.Random(NewInt(0))

		group.FindSmallCoprimeInverse(z, bits)

		zinv := NewInt(0).ModInverse(z, group.psub1)

		totalBitLen += len(zinv.Bytes()) * 8

		if len(zinv.Bytes())*8 > int(bits) {
			t.Errorf("FindSmallExponent Error: Inverse too large on "+
				"attempt %v; Expected: <%v, Recieved: %v", i, bits,
				uint32(len(zinv.Bytes())*8))
		}

		baseZ := NewInt(0)

		group.Exp(base, z, baseZ)

		basecalc := NewInt(0)

		basecalc = group.RootCoprime(baseZ, z, basecalc)

		if base.Cmp(basecalc) != 0 {
			t.Errorf("FindSmallExponent Error: Result incorrect"+
				" on attempt %v; Expected: %s, Recieved: %s", i, base.Text(10),
				basecalc.Text(10))
		}
	}

	avgBitLen := float32(totalBitLen) / float32(num)

	if float32(avgBitLen) < 0.98*float32(bits) {
		t.Errorf("FindSmallExponent Error: Inverses are not the correct length on average "+
			"; Expected: ~%v, Recieved: %v", 0.95*float32(bits), avgBitLen)
	}

}

func TestGroup_FindSmallCoprimeInverse_UnsafeGroup(t *testing.T) {
	p := NewInt(107)
	s := NewInt(2)
	g := NewInt(2)
	min := NewInt(2)
	max := NewInt(1000)
	rng := NewRandom(min, max)

	group := NewGroup(p, s, g, rng)
	one := NewInt(1)
	num := 1000

	bits := uint32(6)

	for i := 0; i < num; i++ {
		z := NewInt(1)

		base := group.Random(NewInt(0))

		// z will be unchanged if a number with no inverse is returned
		for z.Cmp(one) == 0 {
			group.FindSmallCoprimeInverse(z, bits)
		}

		zinv := NewInt(0).ModInverse(z, group.psub1)

		if zinv.BitLen() > int(bits) {
			t.Errorf("FindSmallExponent Error: Inverse too large on "+
				"attempt %v; Expected: <%v, Recieved: %v", i, bits,
				zinv.BitLen())
		}

		baseZ := NewInt(0)

		group.Exp(base, z, baseZ)

		basecalc := NewInt(0)

		basecalc = group.RootCoprime(baseZ, z, basecalc)

		if base.Cmp(basecalc) != 0 {
			t.Errorf("FindSmallExponent Error: Result incorrect"+
				" on attempt %v; Expected: %s, Recieved: %s", i, base.Text(10),
				basecalc.Text(10))
		}
	}
}

func TestGroup_FindSmallCoprimeInverse_Panic(t *testing.T) {
	p := NewInt(101)
	s := NewInt(2)
	g := NewInt(2)
	min := NewInt(2)
	max := NewInt(1000)
	rng := NewRandom(min, max)

	group := NewGroup(p, s, g, rng)
	z := NewInt(1)

	bits := uint32(7)

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("FindSmallCoprimeInverse should panic on bits >= log2(g.prime)")
		}
	}()

	group.FindSmallCoprimeInverse(z, bits)
}
