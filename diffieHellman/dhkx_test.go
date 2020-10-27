////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package diffieHellman

import (
	"encoding/hex"
	"gitlab.com/elixxir/crypto/csprng"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/large"
	"testing"
)

// Tests that private key generates a valid private Key and errors and edge
// cases are handled correctly
func TestGeneratePrivateKey(t *testing.T) {

	const numGenerations = 50

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
	p := large.NewInt(1)
	p.SetString(primeString, 16)
	g := large.NewInt(2)
	grp := cyclic.NewGroup(p, g)

	rng := csprng.NewSystemRNG()

	// create a private key and check it is the correct length with the default size
	// do this over and over becasue the size can generate smaller
	maxSize := 0

	for i := 0; i < numGenerations; i++ {
		privKey := GeneratePrivateKey(DefaultPrivateKeyLength, grp, rng)
		if privKey.BitLen() > maxSize {
			maxSize = privKey.BitLen()
		}
	}

	if maxSize != DefaultPrivateKeyLengthBits {
		t.Errorf("Generated Private Keys never met correct length: "+
			"Expected :%v, Received: %v", DefaultPrivateKeyLength, maxSize)
	}
}

//tests public keys are generated correctly
func TestGeneratePublicKey(t *testing.T) {
	const numTests = 50

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
	p := large.NewInt(1)
	p.SetString(primeString, 16)
	g := large.NewInt(2)
	grp := cyclic.NewGroup(p, g)

	rng := csprng.NewSystemRNG()

	for i := 0; i < numTests; i++ {
		//create public key
		privKey := GeneratePrivateKey(DefaultPrivateKeyLength, grp, rng)
		publicKey := GeneratePublicKey(privKey, grp)

		//create public key manually
		publicKeyExpected := grp.NewInt(1)
		grp.Exp(grp.GetGCyclic(), privKey, publicKeyExpected)

		if publicKey.Cmp(publicKeyExpected) != 0 {
			t.Errorf("Public key generated on attempt %v incorrect;"+
				"\n\tExpected: %s \n\tRecieved: %s \n\tPrivate key: %s", i,
				publicKeyExpected.TextVerbose(16, 0),
				publicKey.TextVerbose(16, 0),
				privKey.TextVerbose(16, 0))
		}
	}
}

//tests Session keys are generated correctly
func TestGenerateSessionKey(t *testing.T) {
	const numTests = 50

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
	p := large.NewInt(1)
	p.SetString(primeString, 16)
	g := large.NewInt(2)
	grp := cyclic.NewGroup(p, g)

	rng := csprng.NewSystemRNG()

	for i := 0; i < numTests; i++ {
		//create session key
		privKey := GeneratePrivateKey(DefaultPrivateKeyLength, grp, rng)
		publicKey := GeneratePublicKey(privKey, grp)
		session := GenerateSessionKey(privKey, publicKey, grp)

		//create public key manually
		sessionExpected := grp.NewInt(1)
		grp.Exp(publicKey, privKey, sessionExpected)

		if session.Cmp(sessionExpected) != 0 {
			t.Errorf("Session key generated on attempt %v incorrect;"+
				"\n\tExpected: %s \n\tRecieved: %s \n\tPrivate key: %s", i,
				sessionExpected.TextVerbose(16, 0),
				session.TextVerbose(16, 0),
				privKey.TextVerbose(16, 0))
		}
	}
}

// Verifies that checkPublic key returns correct responses on valid and
// invalid inputs
func TestCheckPublicKey(t *testing.T) {

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
	p := large.NewInt(1)
	p.SetString(primeString, 16)
	g := large.NewInt(2)
	grp := cyclic.NewGroup(p, g)

	rng := csprng.NewSystemRNG()

	// Creation of a DH Key Pair with valid parameters
	privKey := GeneratePrivateKey(DefaultPrivateKeyLength, grp, rng)
	publicKey := GeneratePublicKey(privKey, grp)

	// Random 2048 bit number that is not a quadratic residue
	randomNum := "27a0ed88dd37d9d9c041bd31500e239ac050b618502a64e7f703dba20390" +
		"36638ca17c7bca05973b9ab5057bc535bebe6b98afee010785a32ae06184dcfe12123" +
		"5ea901d154d317480f381ff1fc49867d22d3c8f1f9e83e6d19f7554401fc32148b3d0" +
		"40c57c7d7cc08445776bd8ffc0d62016bf82708985c97b873d0f81a87072d6bfbbbb0" +
		"1e31679386641720c444c00a64720ffe3649d2b1fdf458acf65d0e695d6a293c34c70" +
		"e84d5e5a66d710475b6baea78df56e0c5ee735d496c1e3bc7f5fa95b4cd1b1bd849f9" +
		"487411805e7c9a1503735ba3d7d71ffb8f51e8530abb335e9c315e56677d30a4f7144" +
		"0a34a6954938d29fd24a72aae3d4a0c2873ed4"

	a, _ := hex.DecodeString(randomNum)
	x := grp.NewIntFromBytes(a)

	rightSymbol := CheckPublicKey(grp, publicKey)
	fakeSymbol := CheckPublicKey(grp, grp.NewInt(1))
	falseSymbol := CheckPublicKey(grp, x)

	if !rightSymbol {
		t.Errorf("Public Key is supposed to be valid!")
	}

	if fakeSymbol {
		t.Errorf("1 should not be valid input!")
	}

	if falseSymbol {
		t.Errorf("Random value should not be valid!")
	}

}

//benchmarks session key creation
func BenchmarkCreateDHSessionKey(b *testing.B) {
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
	p := large.NewInt(1)
	p.SetString(primeString, 16)
	g := large.NewInt(2)
	grp := cyclic.NewGroup(p, g)

	pubkeys := make([]*cyclic.Int, b.N)
	privkeys := make([]*cyclic.Int, b.N)

	rng := csprng.NewSystemRNG()

	for i := 0; i < b.N; i++ {
		// Creation of two different DH Key Pairs with valid parameters
		privkeys[i] = GeneratePrivateKey(DefaultPrivateKeyLength, grp, rng)
		tmpPrivKey := GeneratePrivateKey(DefaultPrivateKeyLength, grp, rng)
		pubkeys[i] = GeneratePublicKey(tmpPrivKey, grp)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GenerateSessionKey(pubkeys[i], privkeys[i], grp)
	}
}
