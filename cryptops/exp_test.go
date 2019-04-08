package cryptops

import (
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/large"
	"math/rand"
	"testing"
)

// Tests the correctness of exponentiation under the group.
func TestExp(t *testing.T) {
	grp := cyclic.NewGroup(large.NewInt(117), large.NewInt(5), large.NewInt(53))

	testVals := [][]*cyclic.Int{
		{grp.NewInt(42), grp.NewInt(41), grp.NewInt(9)},
		{grp.NewInt(42), grp.NewInt(63), grp.NewInt(27)},
		{grp.NewInt(69), grp.NewInt(42), grp.NewInt(27)},
		{grp.NewInt(99), grp.NewInt(81), grp.NewInt(99)},
	}

	for _, val := range testVals {
		result := grp.Exp(val[0], val[1], grp.NewInt(1))

		if result.Cmp(val[2]) != 0 {
			t.Errorf("Exp() did not produce the correct exponentiation "+
				"under the group\n\trecieved: %v\n\texpected: %v",
				result.Text(10), val[2].Text(10))
		}
	}
}

// Tests the mathematical properties of exponentiation under the group.
func TestExp_MathProp(t *testing.T) {
	prng := rand.New(rand.NewSource(64))

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

	for i := 0; i < 10; i++ {
		x := grp.NewInt(prng.Int63())
		coprime := grp.RandomCoprime(grp.NewInt(1))
		result := grp.Exp(x, coprime, grp.NewInt(1))
		coprimeRoot := grp.RootCoprime(result, coprime, grp.NewInt(1))

		if coprimeRoot.Cmp(x) != 0 {
			t.Errorf("Exp() did not produce the correct exponentiation "+
				"under the group\n\trecieved: %v\n\texpected: %v",
				coprimeRoot.Text(10), x.Text(10))
		}
	}
}
