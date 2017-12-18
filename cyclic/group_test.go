package cyclic

import (
	"testing"
)

/*
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
	min := NewInt(2)
	gen := NewGen(max)
	rand := NewInt(0)
	tests := 10000
	pass := 0
	for i := 0; i < tests; i++ {
		x := gen.Rand(rand)
		//fmt.Printf("Random int: %v\n", x.Text(2))
		if x.Cmp(max) > 0 || x.Cmp(min) < 0 {
			t.Errorf("Rand() failed, random Int outside range")
		} else {
			pass++
		}
	}
	println("Rand()", pass, "out of", tests, "tests passed.")
}
