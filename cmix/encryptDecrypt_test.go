package cmix

import (
	"fmt"
	"gitlab.com/elixxir/primitives/format"
	"math/rand"
	"reflect"
	"testing"
)

// Fill part of message with random payload and associated data
func makeMsg() *format.Message {
	rng := rand.New(rand.NewSource(42))
	payloadA := make([]byte, format.PayloadLen)
	payloadB := make([]byte, format.PayloadLen)
	rng.Read(payloadA)
	rng.Read(payloadB)
	msg := format.NewMessage()
	msg.SetPayloadA(payloadA)
	msg.SetDecryptedPayloadB(payloadB)

	return msg
}

// Shows that ClientEncryptDecrypt() correctly encrypts the message. This proves
// the multiplicative properties used for encryption.
func TestEncrypt(t *testing.T) {
	msg := makeMsg()

	// Get encrypted message
	size := 10
	baseKeys := makeBaseKeys(size)

	encMsg := ClientEncryptDecrypt(true, grp, msg, salt, baseKeys)

	// Get encryption key
	keyEnc := ClientKeyGen(grp, salt, baseKeys)

	multPayloadA := grp.NewInt(1)
	multPayloadB := grp.NewInt(1)
	grp.Mul(keyEnc, grp.NewIntFromBytes(msg.GetPayloadA()), multPayloadA)
	grp.Mul(keyEnc, grp.NewIntFromBytes(msg.GetPayloadBForEncryption()), multPayloadB)

	testMsg := format.NewMessage()
	testMsg.SetPayloadA(multPayloadA.Bytes())
	testMsg.SetDecryptedPayloadB(multPayloadB.Bytes())

	if !reflect.DeepEqual(encMsg.GetPayloadA(), testMsg.GetPayloadA()) {
		t.Errorf("EncryptDecrypt("+
			") did not produce the correct payload\n\treceived: %d\n"+
			"\texpected: %d", encMsg.GetPayloadA(), testMsg.GetPayloadA())
	}

	if !reflect.DeepEqual(encMsg.GetPayloadB(), testMsg.GetPayloadB()) {
		t.Errorf("EncryptDecrypt("+
			") did not produce the correct associated data\n\treceived: %d\n"+
			"\texpected: %d", encMsg.GetPayloadB(), testMsg.GetPayloadB())
	}
}

// Shows that ClientEncryptDecrypt() correctly decrypts the message,
// and doesn't change associated data
func TestDecrypt(t *testing.T) {
	msg := makeMsg()

	// Get encrypted message
	size := 10
	baseKeys := makeBaseKeys(size)

	decMsg := ClientEncryptDecrypt(false, grp, msg, salt, baseKeys)

	// Get encryption key
	keyEnc := ClientKeyGen(grp, salt, baseKeys)

	multPayload := grp.NewInt(1)
	grp.Mul(keyEnc, grp.NewIntFromBytes(msg.GetPayloadA()), multPayload)

	testMsg := format.NewMessage()
	testMsg.SetPayloadA(multPayload.Bytes())
	testMsg.SetPayloadB(msg.GetPayloadB())

	if !reflect.DeepEqual(decMsg.GetPayloadA(), testMsg.GetPayloadA()) {
		t.Errorf("EncryptDecrypt("+
			") did not produce the correct payload\n\treceived: %d\n"+
			"\texpected: %d", decMsg.GetPayloadA(), testMsg.GetPayloadA())
	}

	if !reflect.DeepEqual(decMsg.GetPayloadB(), testMsg.GetPayloadB()) {
		t.Errorf("EncryptDecrypt() did not produce the correct associated data\n\treceived: %d\n\texpected: %d", decMsg.GetPayloadB(), testMsg.GetPayloadB())
	}
}

// Tests the consistency of ClientEncryptDecrypt() to correctly encrypt the
// message.
func TestEncrypt_Consistency(t *testing.T) {
	// Create expected values
	// So, because the input message changed length, these will also fail
	expectPL := []byte{5, 112, 143, 31, 21, 42, 251, 144, 198, 255, 122, 132, 9, 124, 114, 156, 174, 6, 84, 44, 138,
		26, 243, 1, 72, 246, 99, 218, 160, 55, 65, 202, 85, 60, 237, 8, 127, 45, 32, 30, 65, 145, 43, 252, 78, 139,
		135, 37, 245, 193, 216, 29, 183, 215, 91, 124, 172, 38, 104, 245, 38, 56, 81, 242, 44, 197, 53, 227, 100, 254,
		54, 52, 246, 115, 155, 91, 76, 84, 22, 178, 40, 62, 248, 199, 244, 49, 159, 48, 205, 19, 213, 220, 15, 184,
		107, 91, 197, 181, 184, 59, 17, 242, 120, 214, 81, 168, 166, 5, 139, 160, 182, 154, 220, 215, 40, 201, 223,
		168, 147, 166, 20, 26, 155, 17, 246, 166, 47, 237, 79, 253, 178, 194, 206, 56, 153, 240, 145, 233, 253, 66, 42,
		2, 66, 243, 119, 125, 219, 235, 128, 31, 7, 249, 60, 55, 12, 158, 175, 52, 207, 200, 231, 1, 98, 11, 99, 145,
		189, 147, 178, 9, 126, 239, 60, 79, 168, 61, 86, 189, 102, 161, 175, 172, 145, 168, 145, 189, 135, 192, 86, 27,
		85, 106, 88, 75, 228, 97, 139, 112, 28, 241, 12, 250, 137, 159, 36, 1, 60, 120, 45, 203, 212, 237, 116, 14, 181,
		236, 0, 164, 65, 79, 238, 141, 176, 240, 91, 219, 198, 72, 183, 190, 211, 20, 204, 175, 209, 114, 130, 141, 20,
		105, 30, 109, 235, 124, 191, 19, 67, 239, 239, 198, 25, 45, 239, 148, 40, 176}
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
	encMsg := ClientEncryptDecrypt(true, grp, makeMsg(), salt, makeBaseKeys(10))

	if !reflect.DeepEqual(encMsg.GetPayloadA(), expectPL) {
		t.Errorf("EncryptDecrypt() did not produce the correct payload in consistency test"+
			"\n\treceived: %d\n\texpected: %d",
			encMsg.GetPayloadA(), expectPL)
	}

	if !reflect.DeepEqual(encMsg.GetPayloadB(), expectAD) {
		t.Errorf("EncryptDecrypt() did not produce the correct associated data in consistency test"+
			"\n\treceived: %d\n\texpected: %d",
			encMsg.GetPayloadB(), expectAD)
	}
}

// Tests the consistency of ClientEncryptDecrypt() to correctly decrypt the
// message and not changing associated data
func TestDecrypt_Consistency(t *testing.T) {
	// Create expected values
	expectPL := []byte{5, 112, 143, 31, 21, 42, 251, 144, 198, 255, 122, 132, 9, 124, 114, 156, 174, 6, 84, 44, 138,
		26, 243, 1, 72, 246, 99, 218, 160, 55, 65, 202, 85, 60, 237, 8, 127, 45, 32, 30, 65, 145, 43, 252, 78, 139,
		135, 37, 245, 193, 216, 29, 183, 215, 91, 124, 172, 38, 104, 245, 38, 56, 81, 242, 44, 197, 53, 227, 100, 254,
		54, 52, 246, 115, 155, 91, 76, 84, 22, 178, 40, 62, 248, 199, 244, 49, 159, 48, 205, 19, 213, 220, 15, 184,
		107, 91, 197, 181, 184, 59, 17, 242, 120, 214, 81, 168, 166, 5, 139, 160, 182, 154, 220, 215, 40, 201, 223,
		168, 147, 166, 20, 26, 155, 17, 246, 166, 47, 237, 79, 253, 178, 194, 206, 56, 153, 240, 145, 233, 253, 66, 42,
		2, 66, 243, 119, 125, 219, 235, 128, 31, 7, 249, 60, 55, 12, 158, 175, 52, 207, 200, 231, 1, 98, 11, 99, 145,
		189, 147, 178, 9, 126, 239, 60, 79, 168, 61, 86, 189, 102, 161, 175, 172, 145, 168, 145, 189, 135, 192, 86, 27,
		85, 106, 88, 75, 228, 97, 139, 112, 28, 241, 12, 250, 137, 159, 36, 1, 60, 120, 45, 203, 212, 237, 116, 14, 181,
		236, 0, 164, 65, 79, 238, 141, 176, 240, 91, 219, 198, 72, 183, 190, 211, 20, 204, 175, 209, 114, 130, 141, 20,
		105, 30, 109, 235, 124, 191, 19, 67, 239, 239, 198, 25, 45, 239, 148, 40, 176}

	msg := makeMsg()
	// Encrypt message
	encMsg := ClientEncryptDecrypt(false, grp, msg, salt, makeBaseKeys(10))
	fmt.Print("payloadA: ")
	fmt.Println(msg.GetPayloadA())

	fmt.Print("PayuloadB: ")
	fmt.Println(msg.GetPayloadB())
	if !reflect.DeepEqual(encMsg.GetPayloadA(), expectPL) {
		t.Errorf("EncryptDecrypt() did not produce the correct payloadA in consistency test"+
			"\n\treceived: %d\n\texpected: %d",
			encMsg.GetPayloadA(), expectPL)
	}

	if !reflect.DeepEqual(encMsg.GetPayloadB(), msg.GetPayloadB()) {
		t.Errorf("EncryptDecrypt() did not produce the correct payloadB in consistency test"+
			"\n\treceived: %d\n\texpected: %d",
			encMsg.GetPayloadB(), msg.GetPayloadB())
	}
}

// Shows that multiplying the encrypted message by the inverse key decrypts it.
func TestEncrypt_Invert(t *testing.T) {
	msg := makeMsg()
	fmt.Println(msg.GetPayloadB())
	// Get encrypted message
	size := 10
	baseKeys := makeBaseKeys(size)

	encMsg := ClientEncryptDecrypt(true, grp, msg, salt, baseKeys)

	// Get encryption key

	keyEncInv := ClientKeyGen(grp, salt, baseKeys)
	grp.Inverse(keyEncInv, keyEncInv)
	fmt.Println(encMsg.GetPayloadB())
	multPayload := grp.NewInt(1)
	multPayloadB := grp.NewInt(1)
	grp.Mul(keyEncInv, grp.NewIntFromBytes(encMsg.GetPayloadA()), multPayload)
	grp.Mul(keyEncInv, grp.NewIntFromBytes(encMsg.GetPayloadBForEncryption()),
		multPayloadB)

	testMsg := format.NewMessage()
	testMsg.SetPayloadA(multPayload.Bytes())
	testMsg.SetDecryptedPayloadB(multPayloadB.Bytes())

	if !reflect.DeepEqual(testMsg.GetPayloadA(), msg.GetPayloadA()) {
		t.Errorf("EncryptDecrypt() did not produce the correct payload\n\treceived: %d\n\texpected: %d", testMsg.GetPayloadA(), msg.GetPayloadA())
	}

	if !reflect.DeepEqual(testMsg.GetPayloadB(), msg.GetPayloadB()) {
		t.Errorf("EncryptDecrypt() did not produce the correct associated data\n\treceived: %d\n\texpected: %d", testMsg.GetPayloadB(), msg.GetPayloadB())
	}
}
