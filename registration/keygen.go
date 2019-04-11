////////////////////////////////////////////////////////////////////////////////
// Copyright © 2019 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package registration

import (
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/diffieHellman"
	"gitlab.com/elixxir/crypto/signature"
	"hash"
)

// Generate a Base Key from DHKX using DSA Keys
// g is the group used in DSA
// peerPubKey is the DSA PublicKey of the peer
// ownPrivKey is the DSA PrivateKey of the caller
// h is the hash to be used on the DHKX sessionKey
// returns base key to be used in CMIX
func GenerateBaseKey(g *cyclic.Group, peerPubKey *signature.DSAPublicKey,
	ownPrivKey *signature.DSAPrivateKey, h hash.Hash) *cyclic.Int {

	pubKey := g.NewIntFromLargeInt(peerPubKey.GetKey())
	privKey := g.NewIntFromLargeInt(ownPrivKey.GetKey())
	sessionKey, _ := diffieHellman.CreateDHSessionKey(pubKey, privKey, g)

	h.Write(sessionKey.Bytes())
	return g.NewIntFromBytes(h.Sum(nil))
}
