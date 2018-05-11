package cyclic

import (
	"bytes"
	"testing"
)

// Tests Rand function using 4000 bit Int as max and 2 as min
func TestRand(t *testing.T) {
	max := NewInt(0)
	max.SetString("oi2n40g27kmjfdkkn332lg1eep4ji585egipan1ap1l70jbk008ib5k"+
		"n96aj38ej5nc99infk3j5mhlfbibhlnm9p0c180pengk4m8977i6l9m44be2p85ejl"+
		"j5oilp1b5bp8ffdm5g1bff562jii0kjmni4kinphma7a0981debkk4g19h01iii4m6"+
		"oklf9fkc1d6j7jn2bgn82mkjlha7gojoolm7oi6m1p015d15jogel3pg3ff57bm717o"+
		"74lk0ij9moo9cna40bl7jl07fp48k3n8oidnb4gd3cld05aee4i3j25i95ej97cfhbdg"+
		"lm8id80h737i8bnm6emc8ji8gbh7557po5m75062l80coa0ckd1glio8l69ka282hbc"+
		"j3565m2m49aclh80kem8lnpjillp492774ip38m97icg5pjkdcgch6e3d88da1109p61"+
		"5oh4k6oboda0okf1ocakg7gc1f11c681pk1p4863e2f4p7bfjh3h22lgl4nakjpjd8n8"+
		"fppo7j3aehdaf8de65ip4bpn0jhkjeik4e5lh0b2okih4n1h4eh50oa3k593a4pi05pf"+
		"894ce4c2dbcagbk20f47jeh0o46l9gopigo4d8l6n446ehph80ljhf4cg35fdj0hfi93"+
		"fl1pa3kd1a6akmbbh2e9g1jddjjg9lp2akmake3n8lljb361mpa7pnhjhj1fdabn0mf7"+
		"h7i4ef1gjc9pheb5ehng5pa76pp36a19fpp81499dodgm0c876325ff1ifm7olkm200m"+
		"h1doag6kpbl3p789fk2d71d4oah319h9k10498ipfo71gjofb603ag", 26)

	// 6 less than max
	largeMin := NewIntFromString("oi2n40g27kmjfdkkn332lg1eep4ji585egipan1ap1l70jbk008ib5k"+
		"n96aj38ej5nc99infk3j5mhlfbibhlnm9p0c180pengk4m8977i6l9m44be2p85ejl"+
		"j5oilp1b5bp8ffdm5g1bff562jii0kjmni4kinphma7a0981debkk4g19h01iii4m6"+
		"oklf9fkc1d6j7jn2bgn82mkjlha7gojoolm7oi6m1p015d15jogel3pg3ff57bm717o"+
		"74lk0ij9moo9cna40bl7jl07fp48k3n8oidnb4gd3cld05aee4i3j25i95ej97cfhbdg"+
		"lm8id80h737i8bnm6emc8ji8gbh7557po5m75062l80coa0ckd1glio8l69ka282hbc"+
		"j3565m2m49aclh80kem8lnpjillp492774ip38m97icg5pjkdcgch6e3d88da1109p61"+
		"5oh4k6oboda0okf1ocakg7gc1f11c681pk1p4863e2f4p7bfjh3h22lgl4nakjpjd8n8"+
		"fppo7j3aehdaf8de65ip4bpn0jhkjeik4e5lh0b2okih4n1h4eh50oa3k593a4pi05pf"+
		"894ce4c2dbcagbk20f47jeh0o46l9gopigo4d8l6n446ehph80ljhf4cg35fdj0hfi93"+
		"fl1pa3kd1a6akmbbh2e9g1jddjjg9lp2akmake3n8lljb361mpa7pnhjhj1fdabn0mf7"+
		"h7i4ef1gjc9pheb5ehng5pa76pp36a19fpp81499dodgm0c876325ff1ifm7olkm200m"+
		"h1doag6kpbl3p789fk2d71d4oah319h9k10498ipfo71gjofb603aa", 26)

	smallMin := NewInt(2)
	largeGen := NewRandom(largeMin, max)
	smallGen := NewRandom(smallMin, max)
	rand := NewInt(0)
	tests := 10000
	pass := 0
	for i := 0; i < tests/2; i++ {
		x := largeGen.Rand(rand)
		if x.Cmp(max) > 0 || x.Cmp(largeMin) < 0 {
			t.Errorf("Rand() failed, random Int outside range")
		} else {
			pass++
		}
	}
	for i := 0; i < tests/2; i++ {
		x := smallGen.Rand(rand)
		if x.Cmp(max) > 0 || x.Cmp(smallMin) < 0 {
			t.Errorf("Rand() failed, random Int outside range")
		} else {
			pass++
		}
	}
	println("Rand()", pass, "out of", tests, "tests passed.")
}

func TestSetMin(t *testing.T) {
	tests := 1
	pass := 0
	gen := NewRandom(NewInt(0), NewInt(10))
	gen.SetMin(NewInt(5))
	// expected fmax
	expected := NewInt(6)
	actual := gen.fmax
	if actual.Cmp(expected) != 0 {
		t.Errorf("SetMin() failed: fmax is %v, expected %v", actual.Text(10), expected.Text(10))
	} else {
		pass++
		println("SetMin()", pass, "out of", tests, "tests passed.")
	}
}

func TestSetMinFromInt64(t *testing.T) {
	tests := 1
	pass := 0
	gen := NewRandom(NewInt(0), NewInt(10))
	gen.SetMinFromInt64(-1)
	// expected fmax
	expected := NewInt(12)
	actual := gen.fmax
	if actual.Cmp(expected) != 0 {
		t.Errorf("SetMinFromInt64() failed: fmax is %v, expected %v", actual.Text(10), expected.Text(10))
	} else {
		pass++
		println("SetMinFromInt64()", pass, "out of", tests, "tests passed.")
	}
}

func TestSetMax(t *testing.T) {
	tests := 1
	pass := 0
	gen := NewRandom(NewInt(6), NewInt(10))
	gen.SetMax(NewInt(16))
	// expected fmax
	expected := NewInt(11)
	actual := gen.fmax
	if actual.Cmp(expected) != 0 {
		t.Errorf("SetMax() failed: fmax is %v, expected %v", actual.Text(10), expected.Text(10))
	} else {
		pass++
		println("SetMax()", pass, "out of", tests, "tests passed.")
	}
}

func TestSetMaxFromInt64(t *testing.T) {
	tests := 1
	pass := 0
	gen := NewRandom(NewInt(5), NewInt(10))
	gen.SetMaxFromInt64(16)
	// expected fmax
	expected := NewInt(12)
	actual := gen.fmax
	if actual.Cmp(expected) != 0 {
		t.Errorf("SetMaxFromInt64() failed: fmax is %v, expected %v", actual.Text(10), expected.Text(10))
	} else {
		pass++
		println("SetMaxFromInt64()", pass, "out of", tests, "tests passed.")
	}
}

// This test generates a Random Key of 256 bits (32 bytes)
func TestGenerateRandomKey(t *testing.T) {

	tests := 2
	pass := 0

	size := 32
	a, _ := GenerateRandomKey(size)
	b, _ := GenerateRandomKey(size)

	if len(a) != size {
		t.Errorf("TestGenerateKeys(): Key Size is Wrong")
	} else {
		pass++
	}

	if bytes.Equal(a, b) {
		t.Errorf("TestGenerateKeys(): Keys should have not been the same")
	} else {
		pass++
	}

	println("TestGenerateKeys():", pass, "out of", tests, "tests passed.")
}
