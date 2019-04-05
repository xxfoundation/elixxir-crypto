package cmix

import (
	"gitlab.com/elixxir/primitives/format"
	"math/rand"
	"reflect"
	"testing"
)

// Fill message with random payload and associated data
func makeMsg() *format.Message {
	rng := rand.New(rand.NewSource(42))
	payloadArr := grp.NewInt(rng.Int63()).Bytes()
	associatedDataArr := grp.NewInt(rng.Int63()).Bytes()
	msg := &format.Message{
		Payload:        format.DeserializePayload(payloadArr),
		AssociatedData: format.DeserializeAssociatedData(associatedDataArr),
	}

	return msg
}

// Shows that ClientEncryptDecrypt() correctly encrypts the message. This proves
// the multiplicative properties used for encryption.
func TestEncryptDecrypt(t *testing.T) {
	msg := makeMsg()

	// Get encrypted message
	size := 10
	baseKeys := makeBaseKeys(size)

	encMsg := ClientEncryptDecrypt(grp, msg, salt, baseKeys)

	// Get encryption key
	keyEnc := ClientKeyGen(grp, salt, baseKeys)

	multPayload := grp.NewInt(1)
	multAssociatedData := grp.NewInt(1)
	grp.Mul(keyEnc, grp.NewIntFromBytes(msg.SerializePayload()), multPayload)
	grp.Mul(keyEnc, grp.NewIntFromBytes(msg.SerializeAssociatedData()), multAssociatedData)

	testMsg := format.Message{
		Payload:        format.DeserializePayload(multPayload.Bytes()),
		AssociatedData: format.DeserializeAssociatedData(multAssociatedData.Bytes()),
	}

	if !reflect.DeepEqual(encMsg.SerializePayload(), testMsg.SerializePayload()) {
		t.Errorf("EncryptDecrypt() did not produce the correct payload\n\treceived: %d\n\texpected: %d", encMsg.SerializePayload(), testMsg.SerializePayload())
	}

	if !reflect.DeepEqual(encMsg.SerializeAssociatedData(), testMsg.SerializeAssociatedData()) {
		t.Errorf("EncryptDecrypt() did not produce the correct associated data\n\treceived: %d\n\texpected: %d", encMsg.SerializeAssociatedData(), testMsg.SerializeAssociatedData())
	}
}

// Shows that multiplying the encrypted message by the inverse key decrypts it.
func TestEncryptDecrypt_Invert(t *testing.T) {
	msg := makeMsg()

	// Get encrypted message
	size := 10
	baseKeys := makeBaseKeys(size)

	encMsg := ClientEncryptDecrypt(grp, msg, salt, baseKeys)

	// Get encryption key
	keyEncInv := ClientKeyGen(grp, salt, baseKeys)
	grp.Inverse(keyEncInv, keyEncInv)

	multPayload := grp.NewInt(1)
	multAssociatedData := grp.NewInt(1)
	grp.Mul(keyEncInv, grp.NewIntFromBytes(encMsg.SerializePayload()), multPayload)
	grp.Mul(keyEncInv, grp.NewIntFromBytes(encMsg.SerializeAssociatedData()), multAssociatedData)

	testMsg := format.Message{
		Payload:        format.DeserializePayload(multPayload.Bytes()),
		AssociatedData: format.DeserializeAssociatedData(multAssociatedData.Bytes()),
	}

	if !reflect.DeepEqual(testMsg.SerializePayload(), msg.SerializePayload()) {
		t.Errorf("EncryptDecrypt() did not produce the correct payload\n\treceived: %d\n\texpected: %d", testMsg.SerializePayload(), msg.SerializePayload())
	}

	if !reflect.DeepEqual(testMsg.SerializeAssociatedData(), msg.SerializeAssociatedData()) {
		t.Errorf("EncryptDecrypt() did not produce the correct associated data\n\treceived: %d\n\texpected: %d", testMsg.SerializeAssociatedData(), msg.SerializeAssociatedData())
	}
}
