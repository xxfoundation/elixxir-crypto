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

	// Get message payload and associated data as cyclic integers
	payload := grp.NewIntFromBytes(msg.SerializePayload())
	associatedData := grp.NewIntFromBytes(msg.SerializeAssociatedData())

	// Multiply message payload with the key
	grp.Mul(keyEncInv, payload, payload)
	// Only multiply associated data if encrypting
	if encrypt {
		grp.Mul(keyEncInv, associatedData, associatedData)
	}
	// Create new message with multiplied parts
	encryptedMsg := &format.Message{
		Payload:        format.DeserializePayload(payload.
			LeftpadBytes(uint64(format.TOTAL_LEN))),
		AssociatedData: format.DeserializeAssociatedData(associatedData.
			LeftpadBytes(uint64(format.TOTAL_LEN))),
	}

	return encryptedMsg
}
