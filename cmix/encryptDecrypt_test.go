package cmix

import (
	"fmt"
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

// Tests the consistency of ClientEncryptDecrypt() to correctly encrypt the
// message.
func TestEncryptDecrypt_Consistency(t *testing.T) {
	// Create expected values
	expectPL := []byte{27, 13, 80, 192, 130, 143, 140, 156, 106, 146, 89, 140, 3, 66, 215, 249, 22, 59, 188, 75, 244,
		185, 44, 218, 25, 227, 47, 113, 28, 139, 195, 241, 137, 237, 85, 236, 55, 60, 222, 200, 32, 176, 150, 49, 213,
		20, 117, 156, 54, 138, 124, 204, 227, 178, 218, 230, 6, 196, 11, 128, 182, 24, 49, 226, 123, 202, 52, 251, 107,
		195, 166, 87, 14, 100, 227, 229, 63, 136, 34, 229, 239, 35, 213, 222, 11, 49, 230, 228, 12, 124, 54, 96, 58,
		103, 52, 61, 226, 23, 119, 213, 4, 52, 69, 83, 14, 215, 69, 24, 208, 191, 32, 7, 114, 253, 217, 243, 56, 117,
		252, 254, 239, 96, 251, 168, 202, 83, 116, 20, 39, 114, 101, 6, 16, 240, 51, 82, 25, 15, 55, 147, 190, 241, 232,
		242, 138, 197, 170, 21, 78, 68, 5, 49, 64, 243, 100, 208, 166, 206, 140, 177, 176, 187, 247, 173, 208, 59, 229,
		60, 47, 64, 243, 199, 169, 155, 209, 250, 117, 224, 37, 108, 26, 187, 105, 29, 151, 91, 207, 43, 202, 193, 211,
		184, 198, 251, 159, 215, 53, 95, 221, 193, 21, 61, 50, 18, 37, 137, 102, 178, 178, 169, 198, 82, 183, 184, 138,
		203, 235, 107, 234, 211, 1, 87, 33, 114, 45, 97, 38, 224, 181, 167, 133, 179, 193, 188, 97, 251, 216, 251, 115,
		110, 203, 219, 199, 225, 195, 194, 136, 27, 169, 146, 183, 109, 130, 232, 241, 99}
	expectAD := []byte{107, 71, 75, 145, 192, 76, 9, 52, 247, 76, 228, 4, 133, 157, 36, 173, 94, 188, 7, 138, 71, 199,
		52, 254, 29, 183, 253, 13, 68, 170, 40, 201, 166, 43, 28, 91, 85, 28, 3, 153, 5, 16, 127, 197, 220, 173, 141,
		136, 3, 24, 77, 0, 23, 205, 104, 129, 47, 109, 210, 57, 188, 40, 18, 97, 247, 15, 236, 186, 225, 47, 218, 239,
		0, 4, 47, 71, 210, 154, 244, 229, 65, 2, 243, 201, 195, 176, 163, 234, 55, 18, 121, 223, 189, 65, 165, 217, 191,
		75, 113, 24, 115, 78, 65, 178, 233, 76, 83, 228, 68, 170, 158, 42, 200, 243, 32, 60, 120, 125, 57, 63, 38, 121,
		251, 44, 237, 39, 181, 165, 74, 101, 247, 84, 205, 134, 212, 158, 235, 73, 202, 20, 91, 38, 18, 207, 154, 109,
		102, 108, 248, 43, 235, 118, 178, 193, 68, 13, 43, 50, 125, 44, 185, 22, 124, 2, 224, 50, 96, 34, 232, 190, 249,
		128, 57, 50, 190, 135, 155, 37, 83, 213, 132, 10, 34, 221, 5, 126, 42, 50, 174, 184, 25, 101, 163, 72, 118, 163,
		43, 172, 224, 1, 56, 151, 171, 126, 151, 120, 240, 152, 25, 90, 148, 159, 97, 134, 176, 118, 115, 82, 140, 149,
		90, 231, 26, 154, 109, 115, 201, 17, 3, 12, 194, 91, 112, 39, 35, 187, 61, 108, 50, 253, 64, 50, 7, 46, 47, 208,
		184, 174, 76, 57, 13, 24, 58, 118, 139, 31}

	// Encrypt message
	encMsg := ClientEncryptDecrypt(grp, makeMsg(), salt, makeBaseKeys(10))

	fmt.Printf("PL: %v\n", encMsg.SerializePayload())
	fmt.Printf("AD: %v\n", encMsg.SerializeAssociatedData())

	if !reflect.DeepEqual(encMsg.SerializePayload(), expectPL) {
		t.Errorf("EncryptDecrypt() did not produce the correct payload in consistency test"+
			"\n\treceived: %d\n\texpected: %d",
			encMsg.SerializePayload(), expectPL)
	}

	if !reflect.DeepEqual(encMsg.SerializeAssociatedData(), expectAD) {
		t.Errorf("EncryptDecrypt() did not produce the correct associated data in consistency test"+
			"\n\treceived: %d\n\texpected: %d",
			encMsg.SerializeAssociatedData(), expectAD)
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
