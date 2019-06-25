package cmix

import (
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/primitives/format"
)

// Encrypts the message for the client by multiplying the inverted encryption
// key by the message payload and associated data if encrypt = true
// Decrypt the message for the client by multiplying the inverted decryption key
// by the message payload if encrypt = false
func ClientEncryptDecrypt(encrypt bool,
	grp *cyclic.Group, msg *format.Message,
	salt []byte, baseKeys []*cyclic.Int) *format.Message {
	// Get inverted encrypted key
	keyEncInv := ClientKeyGen(grp, salt, baseKeys)

	// Get message payloads as cyclic integers
	payloadA := grp.NewIntFromBytes(msg.GetPayloadA())
	payloadB := grp.NewIntFromBytes(msg.GetPayloadBForEncryption())
	// Multiply message payload with the key
	grp.Mul(keyEncInv, payloadA, payloadA)
	// Only multiply associated data if encrypting
	if encrypt {
		grp.Mul(keyEncInv, payloadB, payloadB)

	}
	// Create new message with multiplied parts
	encryptedMsg := format.NewMessage()
	encryptedMsg.SetPayloadA(payloadA.LeftpadBytes(format.PayloadLen))
	encryptedMsg.SetDecryptedPayloadB(payloadB.LeftpadBytes(format.PayloadLen))

	return encryptedMsg
}
