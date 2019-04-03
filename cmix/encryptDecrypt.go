package cmix

import (
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/primitives/format"
)

func EncryptDecrypt(grp *cyclic.Group, msg *format.Message, baseKeys []*cyclic.Int, salt []byte) *format.Message {
	// Generate encrypted keys
	encKey := keyGen(grp, baseKeys, salt)

	// Get message payload and associated data as cyclic.Ints
	payload := grp.NewIntFromBytes(msg.SerializePayload())
	associatedData := grp.NewIntFromBytes(msg.SerializeAssociatedData())

	// Multiply message payload and associated data with the keys
	multPayload := grp.Mul(encKey, payload, grp.NewInt(1))
	multAssociatedData := grp.Mul(encKey, associatedData, grp.NewInt(1))

	// Create nes message with multiplied parts
	encryptedMsg := format.Message{
		Payload:        format.DeserializePayload(multPayload.Bytes()),
		AssociatedData: format.DeserializeAssociatedData(multAssociatedData.Bytes()),
	}

	return &encryptedMsg
}

// Generates the key for use by EncryptDecrypt() by generating encryption keys
// from the base keys, multiplies them together, and inverts them.
func keyGen(grp *cyclic.Group, baseKeys []*cyclic.Int, salt []byte) *cyclic.Int {
	// Make slice to hold all generated intermediary keys inside the group
	keys := make([]*cyclic.Int, len(baseKeys))

	// Generate all the encryption keys
	for i, baseKey := range baseKeys {
		keys[i] = NewEncryptionKey(salt, baseKey, grp)
	}

	// Multiply all the keys together
	multKeys := grp.MulMulti(grp.NewInt(1), keys...)

	// Invert the multiplied keys
	multInvKeys := grp.Inverse(multKeys, grp.NewInt(1))

	return multInvKeys
}
