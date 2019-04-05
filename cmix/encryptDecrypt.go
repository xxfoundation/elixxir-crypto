package cmix

import (
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/primitives/format"
)

func ClientEncryptDecrypt(grp *cyclic.Group, msg *format.Message, salt []byte, baseKeys []*cyclic.Int) *format.Message {
	// Get inverted encrypted key
	keyEncInv := ClientKeyGen(grp, salt, baseKeys)

	// Get message payload and associated data as cyclic integers
	payload := grp.NewIntFromBytes(msg.SerializePayload())
	associatedData := grp.NewIntFromBytes(msg.SerializeAssociatedData())

	// Multiply message payload and associated data with the key
	grp.Mul(keyEncInv, payload, payload)
	grp.Mul(keyEncInv, associatedData, associatedData)
	// Create new message with multiplied parts
	encryptedMsg := &format.Message{
		Payload:        format.DeserializePayload(payload.Bytes()),
		AssociatedData: format.DeserializeAssociatedData(associatedData.Bytes()),
	}

	return encryptedMsg
}
