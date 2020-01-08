////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////
package cryptops

import (
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/large"
	"math/rand"
	"testing"
)

// Ensure that Mul3 satisfies the interface
// Will cause a compile error if it doesn't
var _ Cryptop = Mul3

func TestMul3_Consistency(t *testing.T) {
	// Tests for consistency with the old cryptop, Realtime Encrypt,
	// message tests
	grp := cyclic.NewGroup(large.NewInt(107), large.NewInt(23))

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
	for i := range tests {
		result := Mul3(grp, tests[i][0], tests[i][1], tests[i][2])

		if expected[i].Cmp(tests[i][2]) != 0 {
			t.Errorf("Discrepancy at %v. Got %v, expected %v", i,
				result.Text(10), result.Text(10))
		}
	}
}

// Makes sure that mul3 operands are commutative
func TestMul3_Commutativity(t *testing.T) {
	var primeString = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
		"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
		"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
		"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
		"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
		"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
		"15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" +
		"ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
		"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" +
		"F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
		"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" +
		"43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7" +
		"88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA" +
		"2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6" +
		"287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED" +
		"1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9" +
		"93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199" +
		"FFFFFFFFFFFFFFFF"
	var prime = large.NewIntFromString(primeString, 16)
	grp := cyclic.NewGroup(prime, large.NewInt(5))

	prng := rand.New(rand.NewSource(82))

	buf := make([]byte, len(prime.Bytes()))
	for i := 0; i < 100; i++ {
		// hope that the seed only generates stuff in the group and doesn't panic
		_, err := prng.Read(buf)
		if err != nil {
			t.Error(err)
		}
		x := grp.NewIntFromBytes(buf)
		_, err = prng.Read(buf)
		if err != nil {
			t.Error(err)
		}
		y := grp.NewIntFromBytes(buf)
		_, err = prng.Read(buf)
		if err != nil {
			t.Error(err)
		}
		z := grp.NewIntFromBytes(buf)

		//ensure that Mul3 is completely commutative
		var out1, out2 *cyclic.Int
		out1 = z.DeepCopy()
		Mul3(grp, x, y, out1)

		out2 = z.DeepCopy()
		Mul3(grp, y, x, out2)
		if out1.Cmp(out2) != 0 {
			t.Errorf("Out1 not equal to Out2 at index %v", i)
		}

		out2 = y.DeepCopy()
		Mul3(grp, z, x, out2)
		if out1.Cmp(out2) != 0 {
			t.Errorf("Out1 not equal to Out2 at index %v", i)
		}

		out2 = x.DeepCopy()
		Mul3(grp, z, y, out2)
		if out1.Cmp(out2) != 0 {
			t.Errorf("Out1 not equal to Out2 at index %v", i)
		}

		out2 = z.DeepCopy()
		Mul3(grp, y, x, out2)
		if out1.Cmp(out2) != 0 {
			t.Errorf("Out1 not equal to Out2 at index %v", i)
		}

		out2 = x.DeepCopy()
		Mul3(grp, y, z, out2)
		if out1.Cmp(out2) != 0 {
			t.Errorf("Out1 not equal to Out2 at index %v", i)
		}
	}
}

// Make sure that multiplying a second time by the modular multiplicative
// inverse
func TestMul3_Correctness(t *testing.T) {
	var primeString = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
		"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
		"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
		"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
		"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
		"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
		"15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" +
		"ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
		"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" +
		"F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
		"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" +
		"43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7" +
		"88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA" +
		"2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6" +
		"287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED" +
		"1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9" +
		"93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199" +
		"FFFFFFFFFFFFFFFF"
	var prime = large.NewIntFromString(primeString, 16)
	grp := cyclic.NewGroup(prime, large.NewInt(5))

	prng := rand.New(rand.NewSource(82))

	buf := make([]byte, len(prime.Bytes()))
	for i := 0; i < 100; i++ {
		// hope that the seed only generates stuff in the group and doesn't panic
		_, err := prng.Read(buf)
		if err != nil {
			t.Error(err)
		}
		x := grp.NewIntFromBytes(buf)
		_, err = prng.Read(buf)
		if err != nil {
			t.Error(err)
		}
		y := grp.NewIntFromBytes(buf)
		z := grp.NewInt(1)

		// start with x*y
		Mul3(grp, x, y, z)
		if z.Cmp(grp.NewInt(1)) == 0 {
			t.Errorf("Z was 1 after multiplication, "+
				"indicating that the mul was a no-op somehow and seriously"+
				" damaging the credibility of the test at index %v", i)
		}

		xInv := grp.Inverse(x, grp.NewInt(1))
		yInv := grp.Inverse(y, grp.NewInt(1))
		// multiply x*y with x inverse and y inverse. result should be 1
		Mul3(grp, xInv, yInv, z)
		if z.Cmp(grp.NewInt(1)) != 0 {
			t.Errorf("Multiplying by modular multiplicative inverse didn't"+
				" result in 1 at index %v", i)
		}
	}
}

// Shows that the value of out is included in the operation
func TestMul3Inclusion(t *testing.T) {
	grp := cyclic.NewGroup(large.NewInt(107), large.NewInt(23))
	timesOne := grp.NewInt(1)
	x := grp.NewInt(80)
	y := grp.NewInt(40)
	timesOne = Mul3(grp, x, y, timesOne)

	timesTwo := grp.NewInt(2)
	timesTwo = Mul3(grp, x, y, timesTwo)
	// timesOne times 2 should be equal to timesTwo, if the last parameter is
	// what's overwritten
	otherTimesTwo := grp.Mul(timesOne, grp.NewInt(2), grp.NewInt(1))
	if otherTimesTwo.Cmp(timesTwo) != 0 {
		t.Error("Mul3 multiplication didn't accumulate into output parameter")
	}
}

func TestMul3Prototype_GetInputSize(t *testing.T) {
	expected := uint32(1)
	if Mul3.GetInputSize() != expected {
		t.Errorf("Mul3 input size was %v, not %v", Mul3.GetInputSize(), expected)
	}
}

func TestMul3Prototype_GetName(t *testing.T) {
	expected := "Mul3"
	if Mul3.GetName() != expected {
		t.Errorf("Mul3 name was %v, not %v", Mul3.GetName(), expected)
	}
}
