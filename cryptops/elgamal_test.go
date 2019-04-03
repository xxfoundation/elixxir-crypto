package cryptops

import (
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/large"
	"testing"
)

//Tests that Elgamal conforms to the cryptops interface
func TestElGamal_CryptopsInterface(t *testing.T) {

	defer func(t *testing.T) {
		if r := recover(); r != nil {
			t.Errorf("ElGamal: Does not conform to cryptops interfece: %v", r)
		}
	}(t)

	var face interface{}
	var cryptop Cryptop
	face = ElGamal
	cryptop = face.(Cryptop)
	el := cryptop.(ElGamalSignature)
	el.GetName()
}

//testElGamalSignature_GetMinSize shows that Elgamal.MinSize returns the correct min size
func TestElGamalSignature_GetMinSize(t *testing.T) {
	expected := 1
	if ElGamal.GetMinSize() != 1 {
		t.Errorf("ElGamal: MinSize not correct: Recieved %v, Expected %v", ElGamal.GetMinSize(), expected)
	}
}

//TestElGamalSignature_GetName shows that Elgamal.GetName returns the correct name
func TestElGamalSignature_GetName(t *testing.T) {
	expected := "ElGamal"
	if ElGamal.GetName() != expected {
		t.Errorf("ElGamal: Name not correct: Recieved %v, Expected %v", ElGamal.GetName(), expected)
	}
}

//Tests properties of Elgamal by undoing the encryption and showing the correct result is obtained
func TestElgamal_Single(t *testing.T) {
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
	g := large.NewInt(2)
	q := large.NewInt(1283)
	grp := cyclic.NewGroup(p, g, q)

	tests := 10

	for i := 0; i < tests; i++ {
		cypherPrivateKey := grp.FindSmallCoprimeInverse(grp.NewInt(1), 256)
		publicCypherKey := grp.ExpG(cypherPrivateKey, grp.NewInt(1))

		ecrKeys := grp.NewInt(1)
		cypher := grp.NewInt(1)

		keyInv := grp.Random(grp.NewInt(1))

		privateKey := grp.FindSmallCoprimeInverse(grp.NewInt(1), 256)

		ElGamal(grp, ecrKeys, cypher, keyInv, privateKey, publicCypherKey)

		cypher = grp.RootCoprime(cypher, cypherPrivateKey, grp.NewInt(1))

		pubkey := grp.ExpG(privateKey, grp.NewInt(1))
		if pubkey.Cmp(cypher) != 0 {
			t.Errorf("Elgamal: Decrypted Cypher incorrect, got wrong public key, Expected %v, Recieved: %v",
				pubkey.Text(16), cypher.Text(16))
		}

		cypherInv := grp.Inverse(cypher, grp.NewInt(1))
		keyInvActual := grp.Mul(ecrKeys, cypherInv, grp.NewInt(1))

		if keyInvActual.Cmp(keyInv) != 0 {
			t.Errorf("Elgamal: Key not decrypted properly, Expected %v, Recieved: %v",
				keyInv.Text(16), keyInvActual.Text(16))
		}

	}

}
