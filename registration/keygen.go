////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

// Package registration contains functions for generating data for registration.
// This includes base key and user ID generation
package registration

import (
	"fmt"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/diffieHellman"
	"hash"
)

// GenerateBaseKey generates a Base Key from DHKX using RSA Keys
// g is the group used in RSA
// peerPubKey is the RSA PublicKey of the peer
// ownPrivKey is the RSA PrivateKey of the caller
// h is the hash to be used on the DHKX sessionKey
// Returns base key to be used in CMIX
func GenerateBaseKey(g *cyclic.Group, peerPubKey *cyclic.Int,
	ownPrivKey *cyclic.Int, h hash.Hash) *cyclic.Int {

	sessionKey := diffieHellman.GenerateSessionKey(ownPrivKey, peerPubKey, g)

	fmt.Println(sessionKey.Text(16))

	h.Write(sessionKey.Bytes())
	return g.NewIntFromBytes(h.Sum(nil))
}
