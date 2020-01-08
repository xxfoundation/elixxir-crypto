////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

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
	expectPayloadA := []byte{226, 222, 67, 222, 255, 124, 97, 243, 80, 71, 244, 142, 251, 152, 192, 195, 85, 39, 39,
		177, 88, 2, 2, 23, 75, 65, 208, 108, 57, 228, 122, 229, 93, 193, 187, 225, 40, 48, 32, 163, 233, 79, 115, 244,
		179, 231, 3, 7, 38, 60, 249, 204, 159, 35, 143, 180, 61, 79, 153, 109, 245, 221, 192, 119, 130, 87, 56, 34, 228,
		192, 4, 220, 90, 82, 166, 97, 55, 101, 107, 214, 207, 95, 119, 246, 154, 80, 127, 51, 160, 49, 101, 197, 165,
		54, 51, 247, 92, 88, 118, 145, 119, 240, 227, 20, 126, 109, 158, 15, 32, 192, 160, 69, 191, 66, 106, 24, 174,
		170, 198, 203, 39, 11, 178, 232, 193, 184, 195, 93, 64, 178, 195, 189, 23, 108, 197, 131, 111, 71, 200, 198,
		152, 10, 70, 150, 161, 180, 239, 215, 156, 148, 145, 192, 157, 132, 217, 52, 82, 121, 29, 24, 247, 20, 190, 105,
		4, 222, 50, 84, 77, 233, 70, 39, 100, 142, 79, 251, 42, 8, 113, 38, 204, 18, 51, 232, 93, 102, 249, 113, 8, 225,
		104, 102, 236, 196, 226, 136, 113, 217, 86, 33, 105, 159, 25, 93, 205, 224, 156, 6, 145, 236, 233, 161, 187,
		169, 188, 62, 20, 194, 139, 15, 144, 112, 104, 254, 53, 112, 139, 96, 39, 225, 113, 227, 208, 247, 184, 234,
		164, 29, 202, 47, 126, 140, 90, 112, 94, 100, 118, 77, 87, 193, 65, 6, 103, 119, 73, 242}

	expectPLB := []byte{87, 205, 233, 225, 75, 64, 227, 223, 90, 106, 173, 83, 26, 62, 80, 147, 74, 95, 110, 244, 187,
		29, 54, 32, 222, 89, 149, 131, 245, 156, 17, 241, 9, 95, 70, 131, 151, 204, 63, 191, 220, 158, 144, 25, 180,
		145, 235, 202, 134, 181, 79, 179, 163, 96, 179, 54, 162, 67, 200, 254, 6, 165, 75, 23, 246, 204, 80, 155, 22,
		48, 174, 252, 166, 34, 113, 125, 201, 35, 30, 82, 143, 148, 183, 0, 249, 76, 0, 94, 111, 0, 218, 63, 109, 185,
		63, 72, 139, 1, 39, 174, 68, 117, 136, 122, 78, 231, 1, 126, 3, 72, 140, 234, 226, 91, 13, 157, 146, 59, 82, 14,
		210, 215, 37, 149, 233, 115, 165, 2, 117, 225, 17, 111, 65, 8, 15, 99, 67, 188, 158, 193, 40, 181, 73, 45, 124,
		224, 48, 72, 201, 229, 123, 124, 182, 212, 249, 13, 99, 58, 233, 61, 102, 219, 194, 105, 112, 223, 81, 9, 56,
		186, 214, 143, 117, 25, 144, 221, 24, 115, 196, 253, 32, 83, 143, 129, 163, 254, 230, 173, 88, 149, 215, 209,
		253, 44, 198, 126, 193, 184, 194, 181, 70, 53, 148, 246, 114, 121, 213, 105, 17, 233, 217, 48, 113, 110, 7, 246,
		91, 231, 200, 202, 195, 15, 72, 25, 148, 180, 110, 235, 198, 58, 248, 223, 179, 73, 94, 250, 220, 91, 198, 8,
		198, 26, 63, 234, 40, 107, 83, 61, 198, 31, 175, 131, 67, 210, 79, 3}

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
