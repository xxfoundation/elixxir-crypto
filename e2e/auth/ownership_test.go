////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package auth

import (
	"encoding/base64"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/diffieHellman"
	"gitlab.com/xx_network/crypto/large"
	"math/rand"
	"testing"
)

//Tests that the generated proofs do not change
func TestMakeOwnershipProof_Consistency(t *testing.T) {

	expected := []string{
		"aG1BkGOnHEwO4ik1IrSMdLEUPPoQPpjabgMC/JFNTfo=",
		"GR9FD79Tsp9DLTzdbEGFiKBSafGMu2eJNeY7PMKpY3U=",
		"KSg+MJHksiG4Yg9mpu79z+hAsHOgcP2RIgE3zqNxWwg=",
		"R+1T9UDxTSkIDqa+fDQBifYYBZSLd6dIsE/ArCpgdF4=",
		"mb7XkuFz1UjCYZbmKAeOUMSKo8synVtBShycjHS66H0=",
	}

	grp := getGrp()
	prng := rand.New(rand.NewSource(42))

	for i := 0; i < len(expected); i++ {
		myPrivKey := diffieHellman.GeneratePrivateKey(
			diffieHellman.DefaultPrivateKeyLength, grp, prng)
		partnerPubKey := diffieHellman.GeneratePublicKey(
			diffieHellman.GeneratePrivateKey(512, grp, prng), grp)
		proof := MakeOwnershipProof(myPrivKey, partnerPubKey, grp)
		proof64 := base64.StdEncoding.EncodeToString(proof)
		if expected[i] != proof64 {
			t.Errorf("received and expected do not match at index %v\n"+
				"\treceived: %s\n\texpected: %s", i, proof64, expected[i])
		}
	}
}

//Tests that the generated proofs are verified
func TestMakeOwnershipProof_Verified(t *testing.T) {

	const numTests = 100

	grp := getGrp()
	prng := rand.New(rand.NewSource(69))

	for i := 0; i < numTests; i++ {
		myPrivKey := diffieHellman.GeneratePrivateKey(
			diffieHellman.DefaultPrivateKeyLength, grp, prng)
		partnerPubKey := diffieHellman.GeneratePublicKey(
			diffieHellman.GeneratePrivateKey(512, grp, prng), grp)
		proof := MakeOwnershipProof(myPrivKey, partnerPubKey, grp)

		if !VerifyOwnershipProof(myPrivKey, partnerPubKey, grp, proof) {
			t.Errorf("Proof could not be verified at index %v", i)
		}
	}
}

//Tests that the generated proof fingerprints are always the same
func TestMakeOwnershipProofFP_Consistency(t *testing.T) {

	expected := []string{
		"Yj9ZJTuCvekX5+MqoCilaxU9RaJZeVdHz2+XDY9+H2o=",
		"a57o+Dk0HzgxVHpxVap/YauaCv+GYmO7Jvhxa8XvkZU=",
		"C3v2JIjInugyWndHl3b+KSZQ982uHN84fKItmUS0Zr0=",
		"BYXdUwJpC57p9Qzto1QX/qC4rjr7RbSnDP0NSLQJjdY=",
		"FllCGVIyINMeeuYjHSAFGvCR7DeedJAiJ4JPSY1hMNE=",
	}

	grp := getGrp()
	prng := rand.New(rand.NewSource(42))

	for i := 0; i < len(expected); i++ {
		myPrivKey := diffieHellman.GeneratePrivateKey(
			diffieHellman.DefaultPrivateKeyLength, grp, prng)
		partnerPubKey := diffieHellman.GeneratePublicKey(
			diffieHellman.GeneratePrivateKey(512, grp, prng), grp)
		proof := MakeOwnershipProof(myPrivKey, partnerPubKey, grp)
		proofFP := MakeOwnershipProofFP(proof)
		proofFP64 := base64.StdEncoding.EncodeToString(proofFP[:])
		if expected[i] != proofFP64 {
			t.Errorf("received and expected do not match at index %v\n"+
				"\treceived: %s\n\texpected: %s", i, proofFP64, expected[i])
		}
	}
}

//Tests that bad proofs are not verified
func TestVerifyOwnershipProof_Bad(t *testing.T) {

	const numTests = 100

	grp := getGrp()
	prng := rand.New(rand.NewSource(420))

	for i := 0; i < numTests; i++ {
		myPrivKey := diffieHellman.GeneratePrivateKey(
			diffieHellman.DefaultPrivateKeyLength, grp, prng)
		partnerPubKey := diffieHellman.GeneratePublicKey(
			diffieHellman.GeneratePrivateKey(512, grp, prng), grp)
		proof := make([]byte, 32)
		prng.Read(proof)

		if VerifyOwnershipProof(myPrivKey, partnerPubKey, grp, proof) {
			t.Errorf("Proof was verified at index %v when it is bad", i)
		}

	}
}

func getGrp() *cyclic.Group {
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
	return cyclic.NewGroup(p, g)
}
