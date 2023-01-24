////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

// Package cmix contains utility functions for preparing, encrypting, and decrypting
// messages sent and received by cMix. In cMix, messages are encrypted by the sending clients,
// partially decrypted by the nodes, then re-encrypted for the receiving clients by the nodes,
// and finally decrypted by the receiving clients. The operational encrypt/decrypt for each of
// these operations is the same. There is also a key selection system driven by a ratcheting protocol.

// Any extensions or modifications to the core messaging functionality should be done here,
// except for conversion of the encrypted message types to the comms messages used for transmitting data.
package cmix

import (
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/hash"
)

// GenerateClientGatewayKey hashes the symmetric key between client and the node
func GenerateClientGatewayKey(baseKey *cyclic.Int) []byte {
	h, err := hash.NewCMixHash()
	if err != nil {
		jww.ERROR.Panicf("Failed to create hash: %v", err)
	}

	h.Reset()

	h.Write(baseKey.Bytes())

	clientGatewayKey := h.Sum(nil)

	return clientGatewayKey
}
