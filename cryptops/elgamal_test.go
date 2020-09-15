////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package cryptops

import (
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/large"
	"testing"
)

//Tests that Elgamal conforms to the cryptops interface
func TestElGamal_CryptopsInterface(t *testing.T) {

	var face interface{}
	var cryptop Cryptop
	face = ElGamal
	cryptop, ok := face.(Cryptop)
	el, ok2 := cryptop.(ElGamalPrototype)
	el.GetName()

	if !(ok && ok2) {
		t.Errorf("ElGamal: Does not conform to the cryptops interface")
	}
}

//Tests properties of Elgamal by undoing the encryption and showing the correct result is obtained
//This is done by opening the cypher, inverting it, and multiplying the result into the encrypted keys
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
	grp := cyclic.NewGroup(p, g)

	tests := 10

	for i := 0; i < tests; i++ {
		cypherPrivateKey := grp.FindSmallCoprimeInverse(grp.NewInt(1), 256)
		publicCypherKey := grp.ExpG(cypherPrivateKey, grp.NewInt(1))

		ecrKeys := grp.NewInt(1)
		cypher := grp.NewInt(1)

		keyInv := grp.Random(grp.NewInt(1))

		privateKey := grp.FindSmallCoprimeInverse(grp.NewInt(1), 256)

		ElGamal(grp, keyInv, privateKey, publicCypherKey, ecrKeys, cypher)

		decCypher := grp.RootCoprime(cypher, cypherPrivateKey, grp.NewInt(1))

		pubkey := grp.ExpG(privateKey, grp.NewInt(1))
		if pubkey.Cmp(decCypher) != 0 {
			t.Errorf("Elgamal: Decrypted Cypher incorrect, got wrong public key on attempt %v, Expected %v, Received: %v",
				i, pubkey.Text(16), decCypher.Text(16))
		}

		cypherInv := grp.Inverse(decCypher, grp.NewInt(1))
		keyInvActual := grp.Mul(ecrKeys, cypherInv, grp.NewInt(1))

		if keyInvActual.Cmp(keyInv) != 0 {
			t.Errorf("Elgamal: Key not decrypted properly on attempt %v, Expected %v, Received: %v",
				i, keyInv.Text(16), keyInvActual.Text(16))
		}
	}
}

//Tests properties of Elgamal by undoing the encryption and showing the correct result is obtained after
//two successive operations
//This is done by opening the cypher, inverting it, and multiplying the result into the encrypted keys
//Shows that the system is multiplicatively commutative
func TestElgamal_Double(t *testing.T) {
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
	grp := cyclic.NewGroup(p, g)

	tests := 10

	for i := 0; i < tests; i++ {
		cypherPrivateKey1 := grp.FindSmallCoprimeInverse(grp.NewInt(1), 256)
		cypherPrivateKey2 := grp.FindSmallCoprimeInverse(grp.NewInt(1), 256)
		publicCypherKey := grp.ExpG(cypherPrivateKey1, grp.NewInt(1))
		publicCypherKey = grp.Exp(publicCypherKey, cypherPrivateKey2, publicCypherKey)

		ecrKeys := grp.NewInt(1)
		cypher := grp.NewInt(1)

		keyInv1 := grp.Random(grp.NewInt(1))
		keyInv2 := grp.Random(grp.NewInt(1))

		privateKey1 := grp.FindSmallCoprimeInverse(grp.NewInt(1), 256)
		privateKey2 := grp.FindSmallCoprimeInverse(grp.NewInt(1), 256)

		ElGamal(grp, keyInv1, privateKey1, publicCypherKey, ecrKeys, cypher)
		ElGamal(grp, keyInv2, privateKey2, publicCypherKey, ecrKeys, cypher)

		decCypher0 := grp.RootCoprime(cypher, cypherPrivateKey1, grp.NewInt(1))
		decCypher := grp.RootCoprime(decCypher0, cypherPrivateKey2, grp.NewInt(1))

		pubkey1 := grp.ExpG(privateKey1, grp.NewInt(1))
		pubkey2 := grp.ExpG(privateKey2, grp.NewInt(1))
		pubkey := grp.Mul(pubkey1, pubkey2, grp.NewInt(1))

		if pubkey.Cmp(decCypher) != 0 {
			t.Errorf("Elgamal: Decrypted double Cypher incorrect, got wrong public key on attempt %v, Expected %v, Received: %v",
				i, pubkey.Text(16), decCypher.Text(16))
		}

		cypherInv := grp.Inverse(decCypher, grp.NewInt(1))
		keyInvActual := grp.Mul(ecrKeys, cypherInv, grp.NewInt(1))

		keyInvDouble := grp.Mul(keyInv1, keyInv2, grp.NewInt(1))

		if keyInvActual.Cmp(keyInvDouble) != 0 {
			t.Errorf("Elgamal: Key not doubly decrypted properly on attempt %v, Expected %v, Received: %v",
				i, keyInvDouble.Text(16), keyInvActual.Text(16))
		}
	}
}

//TestsElgamal for consistency, show that its results do not change
func TestElgamal_Consistency(t *testing.T) {
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
	grp := cyclic.NewGroup(p, g)

	cypherPrivateKeyStr := "ed4cbf3b315fea62a09b4c03bcee3d502ea4556c880bba88a44260b51203e8dc4562724" +
		"d8c8eef980eb9a072ee1fe9563f68ee674f68fc0b8c0be3f37d690dcd2e9e481220e726" +
		"840e2504ead6f995056ae462aa590ddc6ef9fa0458a2998e497da91ceada84bbbfc7c2d" +
		"6f0322af7412b57898eb2a4063480a2d941cd3cfede641cb1e86354e7ebbabbd57d81dd" +
		"2f77e5f28ff0cbe2f36a276d4ca36568ac0dc004409929ed0929cc611de91952cd58583" +
		"d0a0f6ed7366511dca4153090d4fb17b029176e3148d1c5f452fd0529716345a7743702" +
		"cca5ea18abd35b6b3cf945cb6df8e061bb131deee108705491424cdb4656b933463e891" +
		"1cdfa7fd6279ac1"

	expectedEcrStr := "ba916825cb35f112455ecfc3a0d33d41fe0a9c1edcf857cd509b8015368a60a45c4851df2c699" +
		"7c339cb5f002a006ad726e3c8e79a7a6385d1705406c931ddeef16322970aeaf5fca5410b9c0c" +
		"d5db89f886d6914711ae04170f838890f737be1c6372767662b1a49caa92fb3414ae444eb0ab2" +
		"d831b6553f7d6be22be2cecd47ccc7cb88bb2b7b02a0da7a858539e1262536b198e421212bda2" +
		"152c8565301c6101a909ddfe925ac5cec9d23227f526a432f8be19607c57a4b3536244de5770f" +
		"f295400a7b7325d761245be1218e154aa8c7074324ca08b73f347e44e6bcce6ebb8616e4cd87b" +
		"ddfb4a7a0fc6324e7df7430dee032cc8fa5553e6af6ca85b2b"

	expectedCypherStr := "e401bb964ad779b8af15327299930e17ac609302d255b06d8bb0e55816aad24fa8cce57ee78c" +
		"029ff6df63d20bc6675938b0a99081fdd5bdab4497adf7cb8909b402ec65617c4f0217540846" +
		"64bf4a0c829b452b56997ce2493047e3c0b6fc57f5e933b70ef0b72171f553662d1f8632201a" +
		"c6c4ba5c314a96721a9d84643b617e4584d1a59e0738b4587a2f9be076c1dac0fc70cbfd2499" +
		"40dd8b64589da760e1c039cc100245949a9b457d8054d6c964b7445ed84a0a55e975d8ba9406" +
		"823fcf978b9a5ac91e0776e4920589eec3806a53a746c17473ba55222ef347d4b5e6c91a4b34" +
		"94e6f11069b32ca2192f757bee6345fd200ae8201dd1f1a2fb9684bf"

	keyInvStr := "7ae007bf648d166b9c462116d2578d3c45e5cff1ebb7d5199079b8238dd55eaaf9985815c2d04515ecac39" +
		"b8da26c71123fa24a66241929c0185c342a4b6f8f768bdb126d258f31856b9a6a5e127cac15f048919f0a9" +
		"7b90b602b485a2711855ab4828a7f7f11a8c7d4abf1a44605381d65f679ca0edd559f5d63d557ad2a07900" +
		"94a4926e0cc3edefb0b5b0b00c28fbd8a1b84796b1eab8ad8ae2151efd779eb8770539399ea4dd8ac32078" +
		"1284c6c9b68841f31daa2094c858acddb01156b8f7a14d0fa320fa19ad8c32df2b3fbe74f38e5f378ce3d7" +
		"2a4e3f8ee1aeb5a957d120e165869fc2019d574fc25dd397d1d73ddd4c153bdf1958f7fa7458e55fcc"

	privatekey := "f8d10f26a3629d8325b7698b014fa77ee4f89d709fcaaa85782fb6cc7ac840cee280310a2dccd523695248" +
		"779ca79496b1e84e3916e7b9cae2326ef5d388d667d3e160ebec5866098d42688fcba50282d7c3defacbc7" +
		"8adad9a2dd2e900ee45910887ea9b853c5859909a0bfdc95ece2c6acbba05f4ed700d46c8d7e04b0d17aa0" +
		"d08d927d87e87558e9d01006feb66c60bf65bcc0b4bb254e374bb2bd16a87c85fd841422ad9267e33b3a7c" +
		"30617c41fa45d6fcef009893af716e7f0d19a6616a4dd1f8f8dcd70204c8534746147ff4e1b40e83525a27" +
		"575e814057ad81acc9eb4dd4fde13ca04fd9af391691844f6b37d99a96e40a88bef29ac746d842113b"

	cypherPrivateKey := grp.NewIntFromString(cypherPrivateKeyStr, 16)
	publicCypherKey := grp.ExpG(cypherPrivateKey, grp.NewInt(1))

	ecrKeys := grp.NewInt(1)
	expectedEcrKeys := grp.NewIntFromString(expectedEcrStr, 16)
	cypher := grp.NewInt(1)
	expectedCypher := grp.NewIntFromString(expectedCypherStr, 16)

	keyInv := grp.NewIntFromString(keyInvStr, 16)

	privateKey := grp.NewIntFromString(privatekey, 16)

	ElGamal(grp, keyInv, privateKey, publicCypherKey, ecrKeys, cypher)

	if cypher.Cmp(expectedCypher) != 0 {
		t.Errorf("ElGamal: Crypher incorrect in consistency test: Received %v, Expected %v",
			expectedCypher.Text(16), cypher.Text(16))
	}

	if ecrKeys.Cmp(expectedEcrKeys) != 0 {
		t.Errorf("ElGamal: EcrKeys incorrect in consistency test: Received %v, Expected %v",
			expectedEcrKeys.Text(16), ecrKeys.Text(16))
	}

}

//testElGamalSignature_GetMinSize shows that Elgamal.MinSize returns the correct min size
func TestElGamalSignature_GetMinSize(t *testing.T) {
	expected := 1
	if ElGamal.GetInputSize() != 1 {
		t.Errorf("ElGamal: MinSize not correct: Received %v, Expected %v", ElGamal.GetInputSize(), expected)
	}
}

//TestElGamalSignature_GetName shows that Elgamal.GetName returns the correct name
func TestElGamalSignature_GetName(t *testing.T) {
	expected := "ElGamal"
	if ElGamal.GetName() != expected {
		t.Errorf("ElGamal: Name not correct: Received %v, Expected %v", ElGamal.GetName(), expected)
	}
}
