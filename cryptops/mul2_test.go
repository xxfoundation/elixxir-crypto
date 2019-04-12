package cryptops

import (
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/large"
	"math/rand"
	"testing"
)

// Three tests,
// Consistency -  if function is used twice with the same numbers the result should be the same
// Communitive property - order of numbers put in should not effect the out output
// Inverse - if I get the inverse it should return the inputs



// Ensure that Mul2 satisfies the interface
// Will cause a compile error if it doesn't
var _ Cryptop = Mul2

func TestMul2_Consistency(t *testing.T) {
	// Tests for consistency with the old cryptop, Realtime Encrypt,
	// message tests
	prime := large.NewInt(11)
	primeQ := large.NewInt(5)
	gen := large.NewInt(4)
	grp := cyclic.NewGroup(prime, gen, primeQ) // g = { 5, 9, 3, 1 }

	tests := [][]*cyclic.Int{
		{grp.NewInt(1), grp.NewInt(1)},
		{grp.NewInt(3), grp.NewInt(3)},
		{grp.NewInt(5), grp.NewInt(1)},
		{grp.NewInt(1), grp.NewInt(5)},
	}

	expected := []*cyclic.Int{
		grp.NewInt(1),
		grp.NewInt(9),
		grp.NewInt(5),
		grp.NewInt(5),
	}

	for i := range tests {
		result := Mul2(grp, tests[i][0], tests[i][1])

		if expected[i].Cmp(result) != 0 {
			t.Errorf("Discrepancy at %v. Got %v, expected %v", i,
				result.Text(10), expected[i].Text(10))
		}
	}
}

// Makes sure that mul3 operands are commutative
func TestMul2_Commutativity(t *testing.T) {
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
	grp := cyclic.NewGroup(prime, large.NewInt(5), large.NewInt(53))

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


		//ensure that Mul2 is completely commutative
		var in1, in2, out1, out2 *cyclic.Int
		in1 = y.DeepCopy()
		in2 = x.DeepCopy()
		out1 = Mul2(grp, x, in1)

		out2 = Mul2(grp, y, in2)
		if out2.Cmp(out1) != 0 {
			t.Errorf("Out1 not equal to Out2 at index %v", i)
		}
	}
}

// Make sure that multiplying a second time by the modular multiplicative
// inverse
func TestMul2_Correctness(t *testing.T) {
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
	grp := cyclic.NewGroup(prime, large.NewInt(5), large.NewInt(53))

	prng := rand.New(rand.NewSource(82))

	buf := make([]byte, len(prime.Bytes()))
	for i := 0; i < 100; i++ {
		// hope that the seed only generates stuff in the group and doesn't panic
		_, err := prng.Read(buf)
		if err != nil {
			t.Error(err)
		}
		x := grp.NewIntFromBytes(buf)

		y := grp.NewInt(1)

		// start with x*y
		Mul2(grp, x, y)
		if y.Cmp(grp.NewInt(1)) == 0 {
			t.Errorf("Y was 1 after multiplication, "+
				"indicating that the mul was a no-op somehow and seriously"+
				" damaging the credibility of the test at index %v", i)
		}

		xInv := grp.Inverse(x, grp.NewInt(1))
		// multiply x*y with x inverse and y inverse. result should be 1
		Mul2(grp, xInv, y)
		if y.Cmp(grp.NewInt(1)) != 0 {
			t.Errorf("Multiplying by modular multiplicative inverse didn't"+
				" result in 1 at index %v", i)
		}
	}
}





//Tests that Mul2 conforms to the cryptops interface
func TestMul2_CryptopsInterface(t *testing.T) {

	var face interface{}
	var cryptop Cryptop
	face = Mul2
	cryptop, ok := face.(Cryptop)
	el, ok2 := cryptop.(Mul2Prototype)
	el.GetName()

	if !(ok && ok2) {
		t.Errorf("Mul2: Does not conform to the cryptops interface")
	}
}


//testMul2Signature_GetMinSize shows that Mul2.MinSize returns the correct min size
func TestMul2Signature_GetInputSize(t *testing.T) {
	expected := 1
	if Mul2.GetInputSize() != 1 {
		t.Errorf("Mul2: MinSize not correct: Recieved %v, Expected %v", Mul2.GetInputSize(), expected)
	}
}

//TestMul2Signature_GetName shows that Mul2.GetName returns the correct name
func TestMul2Signature_GetName(t *testing.T) {
	expected := "Mul2"
	if Mul2.GetName() != expected {
		t.Errorf("Mul2: Name not correct: Recieved %v, Expected %v", Mul2.GetName(), expected)
	}
}
