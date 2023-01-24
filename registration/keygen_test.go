////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package registration

import (
	"crypto/sha256"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/diffieHellman"
	"gitlab.com/elixxir/crypto/hash"
	"gitlab.com/xx_network/crypto/large"
	"math/rand"
	"testing"
)

var grp *cyclic.Group

// Test key generation by using the default DSA group
// then creating 2 DSA key pairs, and calling the
// GenerateBaseKey function from both sides of the DH exchange
// to guarantee that the same base keys are generated
// Also confirm that base transmission and reception keys are different
func TestGenerateBaseKey(t *testing.T) {
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

	prng := rand.New(rand.NewSource(42))

	ownPrivKey := diffieHellman.GeneratePrivateKey(diffieHellman.DefaultPrivateKeyLength, grp, prng)
	ownPubKey := diffieHellman.GeneratePublicKey(ownPrivKey, grp)

	peerPrivKey := diffieHellman.GeneratePrivateKey(diffieHellman.DefaultPrivateKeyLength, grp, prng)
	peerPubKey := diffieHellman.GeneratePublicKey(peerPrivKey, grp)

	// Generate transmission base keys using blake2b as the hash
	b, _ := hash.NewCMixHash()
	ownBaseTKey := GenerateBaseKey(grp, peerPubKey, ownPrivKey, b)
	b.Reset()
	peerBaseTKey := GenerateBaseKey(grp, ownPubKey, peerPrivKey, b)

	if ownBaseTKey.Cmp(peerBaseTKey) != 0 {
		t.Errorf("Generated Base Key using blake2b is different between own and peer")
		t.Errorf("own: %x", ownBaseTKey.Bytes())
		t.Errorf("peer: %x", peerBaseTKey.Bytes())
	}

	// Generate reception base keys using sha256 as the hash
	h := sha256.New()
	ownBaseRKey := GenerateBaseKey(grp, peerPubKey, ownPrivKey, h)
	h.Reset()
	peerBaseRKey := GenerateBaseKey(grp, ownPubKey, peerPrivKey, h)

	if ownBaseRKey.Cmp(peerBaseRKey) != 0 {
		t.Errorf("Generated Base Key using sha256 is different between own and peer")
		t.Errorf("own: %x", ownBaseRKey.Bytes())
		t.Errorf("peer: %x", peerBaseRKey.Bytes())
	}

	if ownBaseTKey.Cmp(ownBaseRKey) == 0 {
		t.Errorf("Generated Base Keys are the same")
	}
}
