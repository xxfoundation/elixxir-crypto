////////////////////////////////////////////////////////////////////////////////
// Copyright © 2019 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package registration

import (
	"crypto/sha256"
	"gitlab.com/elixxir/crypto/csprng"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/hash"
	"gitlab.com/elixxir/crypto/signature"
	"testing"
)

var grp cyclic.Group

// Test key generation by using the default DSA group
// then creating 2 DSA key pairs, and calling the
// GenerateBaseKey function from both sides of the DH exchange
// to guarantee that the same base keys are generated
// Also confirm that base transmission and reception keys are different
func TestGenerateBaseKey(t *testing.T) {
	dsaParams := signature.GetDefaultDSAParams()
	p := dsaParams.GetP()
	min := cyclic.NewInt(2)
	max := cyclic.NewInt(0)
	max.Mul(p, cyclic.NewInt(1000))
	seed := cyclic.NewInt(42)
	grp = cyclic.NewGroup(p, seed, dsaParams.GetG(), cyclic.NewRandom(min, max))

	rng := csprng.NewSystemRNG()
	ownPrivKey := dsaParams.PrivateKeyGen(rng)
	ownPubKey := ownPrivKey.PublicKeyGen()

	peerPrivKey := dsaParams.PrivateKeyGen(rng)
	peerPubKey := peerPrivKey.PublicKeyGen()

	// Generate transmission base keys using blake2b as the hash
	b, _ := hash.NewCMixHash()
	ownBaseTKey := GenerateBaseKey(&grp, peerPubKey, ownPrivKey, b)
	b.Reset()
	peerBaseTKey := GenerateBaseKey(&grp, ownPubKey, peerPrivKey, b)

	if ownBaseTKey.Cmp(peerBaseTKey) != 0 {
		t.Errorf("Generated Base Key using blake2b is different between own and peer")
		t.Errorf("own: %x", ownBaseTKey.Bytes())
		t.Errorf("peer: %x", peerBaseTKey.Bytes())
	}

	// Generate reception base keys using sha256 as the hash
	h := sha256.New()
	ownBaseRKey := GenerateBaseKey(&grp, peerPubKey, ownPrivKey, h)
	h.Reset()
	peerBaseRKey := GenerateBaseKey(&grp, ownPubKey, peerPrivKey, h)

	if ownBaseRKey.Cmp(peerBaseRKey) != 0 {
		t.Errorf("Generated Base Key using sha256 is different between own and peer")
		t.Errorf("own: %x", ownBaseRKey.Bytes())
		t.Errorf("peer: %x", peerBaseRKey.Bytes())
	}

	if ownBaseTKey.Cmp(ownBaseRKey) == 0 {
		t.Errorf("Generated Base Keys are the same")
	}
}
