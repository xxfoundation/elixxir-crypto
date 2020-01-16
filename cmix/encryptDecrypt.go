////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
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
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/primitives/format"
	"golang.org/x/crypto/blake2b"
)

// ClientEncrypt encrypts the message for the client by multiplying the
// inverted encryption key by the message payload
func ClientEncrypt(grp *cyclic.Group, msg *format.Message,
	salt []byte, baseKeys []*cyclic.Int) *format.Message {

	// Get the salt for associated data
	hash, err := blake2b.New256(nil)
	if err != nil {
		panic("E2E Client Encrypt could not get blake2b Hash")
	}
	hash.Reset()
	hash.Write(salt)

	// Get encryption keys
	keyEcrA := ClientKeyGen(grp, salt, baseKeys)
	keyEcrB := ClientKeyGen(grp, hash.Sum(nil), baseKeys)

	// Get message payloads as cyclic integers
	payloadA := grp.NewIntFromBytes(msg.GetPayloadA())
	payloadB := grp.NewIntFromBytes(msg.GetPayloadBForEncryption())

	// Encrypt payload A with the key
	EcrPayloadA := grp.Mul(keyEcrA, payloadA, grp.NewInt(1))
	EcrPayloadB := grp.Mul(keyEcrB, payloadB, grp.NewInt(1))

	// Create the encrypted message
	encryptedMsg := format.NewMessage()

	encryptedMsg.SetPayloadA(EcrPayloadA.LeftpadBytes(format.PayloadLen))
	encryptedMsg.SetPayloadB(EcrPayloadB.LeftpadBytes(format.PayloadLen))

	return encryptedMsg

}
