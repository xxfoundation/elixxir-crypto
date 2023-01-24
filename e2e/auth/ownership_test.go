////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package auth

import (
	"encoding/base64"
	"encoding/hex"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/diffieHellman"
	"gitlab.com/elixxir/crypto/nike/dh"
	"gitlab.com/xx_network/crypto/large"
)

// Tests that the generated proofs do not change
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

// Tests that the generated proofs are verified
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

// Tests that the generated proofs are verified
func TestMakeOwnershipProof_VerifiedVector(t *testing.T) {

	//prng := rand.New(rand.NewSource(69))

	/*
		myPrivKey := diffieHellman.GeneratePrivateKey(
			diffieHellman.DefaultPrivateKeyLength, grp, prng)
		myPubKey := diffieHellman.GeneratePublicKey(myPrivKey, grp)

		partnerPrivKey := diffieHellman.GeneratePrivateKey(
			diffieHellman.DefaultPrivateKeyLength, grp, prng)
		partnerPubKey := diffieHellman.GeneratePublicKey(partnerPrivKey, grp)
	*/

	/*
		myPrivKey, myPubKey := dh.DHNIKE.NewKeypair()
		partnerPrivKey, partnerPubKey := dh.DHNIKE.NewKeypair()
	*/

	myPrivKeyBytes, err := hex.DecodeString("f0a3b839313b25f3ffbae5abc055d56be654ff288c3275e0f58595464cc9d1fe97c6ad70122e10cbc73b4b551b3589da270b2a5f74038c0ded0b76db1ab558092a441d6e8620f544b3a5ecc0358920ee8122047e9d761c0a48faa39f6903762649d19d762a1761db7de8bf6d2e1fde89313e0e383cf1c303577bfa7378dde20d8d483b5e397b32c28cea72658deea74e1afeb772e1f46eb444c6d1fb12a8adda88c664c0829f13f6c63453e84c5babb92c3e09c9f587c729cd5a971a59b66e26a318f35c2348bb441e496a3dc4329f5cea5a2c2a8a38627c0173451f3a42db85cc692ee1073af2d4a66676b61285d7981b56873bdca27effbc54d8f7908d7560f36ea69bf5db576a")
	require.NoError(t, err)
	myPrivKey, err := dh.DHNIKE.UnmarshalBinaryPrivateKey(myPrivKeyBytes)
	require.NoError(t, err)

	/*
		myPubKeyBytes, err := hex.DecodeString("f0a3b839313b25f3c16384bdd1d1acc8f8519d24190fc2076627319adc1b4f33ee4d8a9e010efe9871df0621122e42139608d289ca98a77fd037c407d69ef7043cbc9f0857e5ea5ab24411aa3327fd8a3fee278d54851286b814ec4e5c57d3212e59815dc799a270d1831d76a41dd2f746f9ee6e5a8cb5184443be66db948a37d5093ef5a677b046c8107d90f9b364a9e72d72eaf13d8216206ac4e13d913f2577389a79a8cade73f2aaa2d176151f3a1b4323e84eac4e61fd4618d5cdc84030881e3c241eabe0ae22803c17f58106f2d8b950d200a7733c54665518adfb9b22e4c96ad15977ea6ccdff9e770058bb97a3b0222ca82b559f8e2d5f4684064138f1d8a4a380e44b10")
		require.NoError(t, err)
		myPubKey, err := dh.DHNIKE.UnmarshalBinaryPublicKey(myPubKeyBytes)
		require.NoError(t, err)

		partnerPrivKeyBytes, err := hex.DecodeString("f0a3b839313b25f3d995caed608f3d7b19ce235cea7d5094ffa2e8066ed9864308cdb6ceabbf65563ed8aa9f2b2f1df1ad7c724422eddcbb15833cdd273eabc56c9d76fba794b0166748e57babc45ff174c801d08821782c1195a92b7c58b2ffa46e9e283ec139d1ed0156a0493c4e7f303d48cf6505deaaf9636ebad4950b7eeb6694275129d4a1009652f4792c798a432a090da4c1f7779ff62df1cf756987f7ddbf8345fc91debad831d7d2518d85783b59b0680b3b0a8d3aa59bc7f7e47451212ef05ec9d740e6a51dec49f10de733130eeb9d553e6d778ae3b03bff4ca7da1c76bfdecc67b25475381ce1fc01274276ed38b4840bb8ccaa0752395d14efdee707e545e2f65d")
		require.NoError(t, err)
		partnerPrivKey, err := dh.DHNIKE.UnmarshalBinaryPrivateKey(partnerPrivKeyBytes)
		require.NoError(t, err)
	*/
	partnerPubKeyBytes, err := hex.DecodeString("f0a3b839313b25f39d91be284d3d06a2691e2e54624db78a27c3b34c619bfe25e167edd7224c95eb1e97d863675bb202b200f3f533434b8dc06d6516bd5cafb078d040bb972180fccd0c80cade0b355019e5523211b240d4c9ab54fce4b3893ec76ab169ba3867428918fb4a19a9fcf002d8e3c7542ab82245eace54223f0e05b2a78d8b3c20f4974f6b1744a418e0ae7bd8a3bd6f44b43f39512aa04860b9d740d92b2f6e9f051b8cafc504ea533a37cded80960fa01c5901dd94db17ad2dfeba5ec3729b0fa4b6b740812ad64094bbdec31f65539d7ef6923fdd18c77347885b729bed21effe687520679291fc4b6972c1f3bcfcdd7a6d46064005fb069c6c560f4aaf1b9af5a4")
	require.NoError(t, err)
	partnerPubKey, err := dh.DHNIKE.UnmarshalBinaryPublicKey(partnerPubKeyBytes)
	require.NoError(t, err)

	/*
		t.Logf("myPrivKey %x", myPrivKey.Bytes())
		t.Logf("myPubKey %x", myPubKey.Bytes())
		t.Logf("partnerPrivKey %x", partnerPrivKey.Bytes())
		t.Logf("partnerPubKey %x", partnerPubKey.Bytes())
	*/

	proofString := "e2335310a889a7917cc88560cb18d561c607b466db106a6b89ea23aa76314e8a"
	proofBytes, err := hex.DecodeString(proofString)
	require.NoError(t, err)

	grp := getGrp()

	proof := MakeOwnershipProof(myPrivKey.(*dh.PrivateKey).CyclicInt(), partnerPubKey.(*dh.PublicKey).CyclicInt(), grp)

	require.Equal(t, proofBytes, proof)

	t.Logf("proof: %x", proof)

	require.True(t, VerifyOwnershipProof(myPrivKey.(*dh.PrivateKey).CyclicInt(), partnerPubKey.(*dh.PublicKey).CyclicInt(), grp, proof))
}

// Tests that the generated proof fingerprints are always the same
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

// Tests that bad proofs are not verified
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
