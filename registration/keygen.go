////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package registration

import (
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/diffieHellman"
	"hash"
)

//TODO: Fix this comment, no longer use DSA

// Generate a Base Key from DHKX using DSA Keys
// g is the group used in DSA
// peerPubKey is the DSA PublicKey of the peer
// ownPrivKey is the DSA PrivateKey of the caller
// h is the hash to be used on the DHKX sessionKey
// returns base key to be used in CMIX
func GenerateBaseKey(g *cyclic.Group, peerPubKey *cyclic.Int,
	ownPrivKey *cyclic.Int, h hash.Hash) *cyclic.Int {

	sessionKey, _ := diffieHellman.CreateDHSessionKey(peerPubKey, ownPrivKey, g)

	h.Write(sessionKey.Bytes())
	return g.NewIntFromBytes(h.Sum(nil))
}
