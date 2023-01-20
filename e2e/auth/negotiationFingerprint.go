////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package auth

import (
	"github.com/cloudflare/circl/dh/sidh"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/xx_network/crypto/cyclic"
	"gitlab.com/xx_network/crypto/hash"
)

const NegotiationFingerprintLen = 32

// CreateNegotiationFingerprint creates a fingerprint for a re-authentication
// negotiation from the partner's DH public key and SIDH public key.
func CreateNegotiationFingerprint(partnerDhPubKey *cyclic.Int,
	partnerSidhPubKey *sidh.PublicKey) []byte {
	h, err := hash.NewCMixHash()
	if err != nil {
		jww.FATAL.Panicf(
			"Could not get hash to make request fingerprint: %+v", err)
	}

	h.Write(partnerDhPubKey.Bytes())

	partnerSidhPubkeyBytes := make([]byte, partnerSidhPubKey.Size()+1)
	partnerSidhPubkeyBytes[0] = byte(partnerSidhPubKey.Variant())
	partnerSidhPubKey.Export(partnerSidhPubkeyBytes[1:])
	h.Write(partnerSidhPubkeyBytes)

	return h.Sum(nil)[:NegotiationFingerprintLen]
}
