package cyclic

import (
	"testing"
)

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
