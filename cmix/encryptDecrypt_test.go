////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package cmix

import (
	"gitlab.com/elixxir/primitives/format"
	"golang.org/x/crypto/blake2b"
	"math/rand"
	"reflect"
	"testing"
)

// Fill part of message with random payload and associated data
func makeMsg() *format.Message {
	rng := rand.New(rand.NewSource(21))
	payloadA := make([]byte, format.PayloadLen)
	payloadB := make([]byte, format.PayloadLen)
	rng.Read(payloadA)
	rng.Read(payloadB)
	msg := format.NewMessage()
	msg.SetPayloadA(payloadA)
	msg.SetDecryptedPayloadB(payloadB)

	return msg
}

// Shows that ClientEncrypt() correctly encrypts the message. This proves
// the multiplicative properties used for encryption.
func TestEncrypt(t *testing.T) {
	msg := makeMsg()

	// Get encrypted message
	size := 10
	baseKeys := makeBaseKeys(size)

	encMsg := ClientEncrypt(grp, msg, salt, baseKeys)

	// Get encryption key
	//general local keys
	hash, err := blake2b.New256(nil)
	if err != nil {
		t.Error("E2E Client Encrypt could not get blake2b Hash")
	}

	hash.Reset()
	hash.Write(salt)

	keyEcrA := ClientKeyGen(grp, salt, baseKeys)
	keyEcrB := ClientKeyGen(grp, hash.Sum(nil), baseKeys)
	multPayloadA := grp.NewInt(1)
	multPayloadB := grp.NewInt(1)
	grp.Mul(keyEcrA, grp.NewIntFromBytes(msg.GetPayloadA()), multPayloadA)
	grp.Mul(keyEcrB, grp.NewIntFromBytes(msg.GetPayloadBForEncryption()), multPayloadB)

	testMsg := format.NewMessage()
	testMsg.SetPayloadA(multPayloadA.Bytes())
	testMsg.SetPayloadB(multPayloadB.Bytes())

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

// Tests the consistency of ClientEncrypt() to correctly encrypt the
// message.
func TestEncrypt_Consistency(t *testing.T) {
	expectPayloadA := []byte{189, 89, 201, 101, 241, 173, 228, 131, 173, 153, 87, 13, 176, 253, 17, 232, 2, 30, 65, 21,
		109, 133, 80, 155, 196, 145, 47, 93, 245, 29, 0, 181, 181, 126, 181, 124, 115, 62, 161, 69, 246, 134, 35, 153,
		39, 193, 43, 124, 165, 62, 77, 213, 136, 190, 182, 138, 172, 238, 129, 232, 118, 106, 182, 65, 138, 211, 12, 46,
		252, 148, 226, 43, 154, 233, 46, 55, 215, 188, 89, 181, 92, 172, 237, 15, 13, 127, 114, 127, 169, 18, 89, 127,
		235, 143, 22, 208, 60, 31, 57, 225, 99, 72, 26, 172, 103, 195, 93, 78, 210, 244, 215, 156, 218, 189, 188, 248,
		246, 184, 20, 235, 115, 46, 29, 227, 152, 76, 176, 53, 247, 42, 5, 117, 197, 178, 199, 112, 83, 78, 239, 123,
		121, 109, 5, 83, 141, 97, 72, 209, 189, 149, 0, 192, 245, 19, 72, 246, 31, 212, 76, 140, 144, 151, 249, 99, 104,
		239, 147, 116, 181, 136, 194, 197, 76, 241, 129, 36, 142, 58, 174, 255, 84, 93, 82, 69, 179, 19, 198, 39, 45,
		160, 81, 107, 128, 215, 121, 205, 157, 16, 151, 247, 129, 103, 148, 90, 168, 20, 26, 214, 69, 46, 22, 231, 128,
		22, 119, 18, 158, 222, 142, 66, 219, 55, 179, 41, 102, 124, 182, 49, 40, 118, 233, 144, 3, 233, 78, 21, 9, 157,
		49, 52, 16, 252, 109, 225, 87, 212, 127, 196, 198, 69, 108, 207, 53, 199, 224, 137}

	expectPLB := []byte{185, 69, 162, 185, 68, 161, 5, 220, 149, 170, 207, 182, 212, 192, 254, 121, 209, 185, 184, 142,
		227, 187, 144, 242, 222, 59, 17, 248, 6, 120, 149, 151, 2, 7, 53, 211, 1, 197, 221, 237, 65, 46, 80, 45, 216,
		52, 202, 164, 73, 29, 14, 143, 61, 11, 138, 83, 217, 163, 22, 65, 121, 221, 24, 154, 163, 102, 88, 112, 234,
		164, 32, 199, 167, 221, 89, 29, 105, 101, 97, 244, 136, 230, 162, 34, 27, 38, 126, 15, 214, 43, 12, 79, 207, 91,
		48, 174, 183, 45, 72, 181, 150, 37, 212, 180, 196, 55, 49, 228, 37, 116, 198, 123, 95, 231, 135, 135, 150, 238,
		208, 224, 232, 229, 195, 136, 4, 164, 194, 188, 8, 61, 225, 203, 238, 31, 128, 250, 164, 229, 129, 93, 41, 168,
		88, 54, 251, 180, 112, 138, 137, 153, 155, 225, 88, 119, 133, 95, 22, 202, 192, 166, 88, 195, 117, 118, 117,
		109, 213, 184, 214, 32, 96, 150, 174, 231, 27, 30, 28, 91, 159, 193, 199, 197, 223, 169, 119, 6, 114, 30, 111,
		138, 34, 230, 215, 135, 90, 220, 193, 198, 19, 207, 36, 186, 134, 97, 131, 80, 44, 55, 136, 159, 242, 223, 218,
		85, 188, 163, 13, 198, 36, 173, 198, 228, 206, 243, 173, 52, 51, 226, 253, 130, 255, 106, 254, 33, 132, 15, 96,
		89, 220, 125, 20, 70, 234, 191, 219, 126, 204, 31, 103, 30, 133, 123, 241, 145, 40, 90}

	// Encrypt message
	encMsg := ClientEncrypt(grp, makeMsg(), salt, makeBaseKeys(10))

	if !reflect.DeepEqual(encMsg.GetPayloadA(), expectPayloadA) {
		t.Errorf("EncryptDecrypt() did not produce the correct payload in consistency test"+
			"\n\treceived: %d\n\texpected: %d",
			encMsg.GetPayloadA(), expectPayloadA)
	}

	if !reflect.DeepEqual(encMsg.GetPayloadB(), expectPLB) {
		t.Errorf("EncryptDecrypt() did not produce the correct associated data in consistency test"+
			"\n\treceived: %d\n\texpected: %d",
			encMsg.GetPayloadB(), expectPLB)
	}
}

// Shows that multiplying the encrypted message by the inverse key decrypts it.
func TestDecrypt(t *testing.T) {
	//make and encrypt the message
	msg := makeMsg()
	size := 10
	baseKeys := makeBaseKeys(size)

	encMsg := ClientEncrypt(grp, msg, salt, baseKeys)

	//general local keys
	hash, err := blake2b.New256(nil)
	if err != nil {
		t.Error("E2E Client Encrypt could not get blake2b Hash")
	}

	hash.Reset()
	hash.Write(salt)

	//Generate encryption keys
	keyEcrA := ClientKeyGen(grp, salt, baseKeys)
	keyEcrB := ClientKeyGen(grp, hash.Sum(nil), baseKeys)

	//Generate the inverse of the keys
	keyEcrA_Inv := grp.Inverse(keyEcrA, grp.NewInt(1))
	keyEcrB_Inv := grp.Inverse(keyEcrB, grp.NewInt(1))

	//Simulate decryption by multiplying the encrypted message with the inverse of the encryption keys
	DecPayloadA := grp.Mul(keyEcrA_Inv, grp.NewIntFromBytes(encMsg.GetPayloadA()), grp.NewInt(1))
	DecPayloadB := grp.Mul(keyEcrB_Inv, grp.NewIntFromBytes(encMsg.GetPayloadB()), grp.NewInt(1))

	//Set decrypted messages to the above payloads
	decMsg := format.NewMessage()
	decMsg.SetPayloadA(DecPayloadA.Bytes())
	decMsg.SetDecryptedPayloadB(DecPayloadB.LeftpadBytes(format.PayloadLen))

	//Compare decrypted message with the original message
	if !reflect.DeepEqual(decMsg.GetPayloadA(), msg.GetPayloadA()) {
		t.Errorf("EncryptDecrypt() did not produce the correct payload\n\treceived: %d\n\texpected: %d", decMsg.GetPayloadA(), msg.GetPayloadA())
	}

	if !reflect.DeepEqual(decMsg.GetPayloadB(), msg.GetPayloadB()) {
		t.Errorf("EncryptDecrypt() did not produce the correct associated data\n\treceived: %d\n\texpected: %d", decMsg.GetPayloadB(), msg.GetPayloadB())
	}
}
