package cryptops

import (
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/large"
	"testing"
)

func TestMul3_Consistency(t *testing.T) {
	// Tests for consistency with the old cryptop, Realtime Encrypt,
	// message tests
	grp := cyclic.NewGroup(large.NewInt(107), large.NewInt(23),
		large.NewInt(27))

    tests := [][]*cyclic.Int{
    	{grp.NewInt(39), grp.NewInt(65), grp.NewInt(52)},
    	{grp.NewInt(86), grp.NewInt(44), grp.NewInt(68)},
    	{grp.NewInt(66), grp.NewInt(94), grp.NewInt(11)},
	}
    expected := []*cyclic.Int{
    	grp.NewInt(103),
    	grp.NewInt(84),
    	grp.NewInt(85),
	}
    for i:= range tests {
        out := grp.NewInt(1)
        result := Mul3(grp, tests[i][0], tests[i][1], tests[i][2], out)

        if expected[i].Cmp(result) != 0{
        	t.Errorf("Discrepancy at %v. Got %v, expected %v", i,
        		result.Text(10), result.Text(10))
		}
	}
}

func TestMul3_Commutativity(t *testing.T) {
	t.Error("Unimplemented")
}

func TestMul3_Correctness(t *testing.T) {
	t.Error("Unimplemented")
}

func TestMul3Prototype_GetInputSize(t *testing.T) {
	expected := uint32(1)
	if Mul3.GetInputSize() != expected{
		t.Errorf("Mul3 input size was %v, not %v", Mul3.GetInputSize(), expected)
	}
}

func TestMul3Prototype_GetName(t *testing.T) {
	expected := "Mul3"
	if Mul3.GetName() != expected{
		t.Errorf("Mul3 name was %v, not %v", Mul3.GetName(), expected)
	}
}
