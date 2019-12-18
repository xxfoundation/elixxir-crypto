////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////
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

	//get the salt for associated data
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

	//Create the encrypted message
	encryptedMsg := format.NewMessage()

	encryptedMsg.SetPayloadA(EcrPayloadA.LeftpadBytes(format.PayloadLen))
	encryptedMsg.SetPayloadB(EcrPayloadB.LeftpadBytes(format.PayloadLen))

	return encryptedMsg

}
