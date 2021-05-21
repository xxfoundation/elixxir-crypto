////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package cmix

import (
	"gitlab.com/elixxir/primitives/format"
	"gitlab.com/xx_network/primitives/id"
	"golang.org/x/crypto/blake2b"
	"math/rand"
	"reflect"
	"testing"
)

// Fill part of message with random payload and associated data
func makeMsg() format.Message {
	rng := rand.New(rand.NewSource(21))
	payloadA := make([]byte, primeLength)
	payloadB := make([]byte, primeLength)
	rng.Read(payloadA)
	rng.Read(payloadB)
	msg := format.NewMessage(primeLength)
	msg.SetPayloadA(payloadA)
	msg.SetPayloadB(payloadB)

	return msg
}

// Shows that ClientEncrypt() correctly encrypts the message. This proves
// the multiplicative properties used for encryption.
func TestEncrypt(t *testing.T) {
	msg := makeMsg()

	// Get encrypted message
	size := 10
	baseKeys := makeBaseKeys(size)

	rid := id.Round(42)

	encMsg := ClientEncrypt(grp, msg, salt, baseKeys, rid)

	// Get encryption key
	//general local keys
	hash, err := blake2b.New256(nil)
	if err != nil {
		t.Fatalf("E2E Client Encrypt could not get blake2b Hash: %+v", err)
	}

	hash.Reset()
	hash.Write(salt)

	keyEcrA := ClientKeyGen(grp, salt, rid, baseKeys)
	keyEcrB := ClientKeyGen(grp, hash.Sum(nil), rid, baseKeys)
	multPayloadA := grp.NewInt(1)
	multPayloadB := grp.NewInt(1)
	grp.Mul(keyEcrA, grp.NewIntFromBytes(msg.GetPayloadA()), multPayloadA)
	grp.Mul(keyEcrB, grp.NewIntFromBytes(msg.GetPayloadB()), multPayloadB)

	testMsg := format.NewMessage(primeLength)
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
	rid := id.Round(42)
	expectPayloadA := []byte{179, 111, 177, 171, 63, 203, 57, 207, 241, 239, 47, 125, 38, 161, 27, 224, 25, 149, 1, 168,
		181, 67, 36, 50, 192, 10, 36, 221, 145, 254, 17, 20, 168, 117, 236, 195, 166, 105, 239, 63, 161, 29, 160, 14,
		101, 192, 127, 245, 73, 194, 148, 94, 204, 178, 154, 94, 210, 5, 89, 56, 119, 138, 251, 101, 24, 84, 44, 84, 65,
		81, 210, 179, 4, 222, 51, 24, 92, 55, 252, 189, 124, 206, 84, 92, 175, 254, 217, 110, 77, 54, 60, 111, 234, 0,
		26, 53, 204, 75, 118, 123, 127, 181, 161, 11, 181, 58, 59, 160, 18, 89, 37, 94, 156, 228, 215, 5, 80, 108, 123,
		62, 28, 180, 35, 228, 57, 10, 77, 216, 80, 123, 115, 55, 50, 112, 43, 247, 100, 73, 174, 6, 145, 104, 7, 82, 22,
		193, 75, 33, 47, 156, 50, 146, 110, 98, 152, 185, 170, 210, 54, 135, 132, 29, 179, 100, 210, 159, 242, 104, 101,
		84, 145, 114, 75, 165, 147, 65, 190, 77, 244, 56, 207, 29, 80, 192, 147, 136, 153, 117, 238, 13, 102, 59, 97,
		149, 31, 72, 28, 28, 145, 39, 166, 241, 89, 42, 36, 137, 94, 162, 104, 208, 12, 251, 245, 52, 193, 21, 143, 7,
		200, 78, 119, 228, 59, 224, 187, 89, 72, 87, 248, 162, 133, 79, 233, 255, 253, 29, 52, 226, 150, 253, 132, 196,
		143, 143, 162, 6, 12, 147, 85, 86, 123, 246, 22, 251, 124, 182}

	expectPayloadB := []byte{88, 146, 28, 156, 13, 105, 245, 124, 138, 145, 1, 253, 87, 206, 2, 66, 81, 247, 138, 106,
		178, 204, 228, 100, 67, 86, 45, 9, 118, 4, 154, 37, 50, 233, 79, 200, 219, 75, 204, 199, 223, 138, 72, 209, 173,
		30, 42, 251, 55, 85, 161, 211, 77, 226, 90, 208, 24, 61, 9, 74, 185, 127, 203, 241, 253, 69, 233, 67, 225, 173,
		245, 153, 49, 63, 250, 157, 76, 31, 86, 87, 150, 98, 233, 174, 187, 241, 97, 67, 193, 0, 106, 103, 10, 35, 54,
		8, 57, 35, 248, 229, 203, 13, 87, 10, 127, 42, 7, 188, 135, 89, 245, 193, 217, 79, 129, 248, 87, 129, 157, 44,
		247, 151, 19, 157, 54, 13, 41, 152, 61, 145, 172, 225, 163, 176, 163, 11, 94, 85, 153, 72, 222, 192, 143, 44,
		223, 201, 226, 74, 146, 250, 250, 77, 69, 151, 127, 249, 224, 249, 60, 241, 186, 221, 214, 251, 69, 126, 249,
		17, 0, 156, 61, 137, 4, 87, 237, 157, 1, 63, 213, 211, 6, 136, 195, 148, 212, 65, 151, 90, 204, 107, 212, 89,
		119, 71, 184, 36, 127, 163, 222, 131, 42, 169, 99, 128, 105, 73, 178, 23, 239, 50, 25, 68, 158, 138, 53, 170,
		197, 200, 213, 135, 208, 54, 108, 194, 61, 3, 18, 76, 85, 170, 31, 87, 217, 240, 0, 192, 164, 172, 70, 104, 79,
		239, 33, 208, 254, 226, 246, 52, 243, 46, 152, 99, 3, 149, 230, 77}

	// Encrypt message
	encMsg := ClientEncrypt(grp, makeMsg(), salt, makeBaseKeys(10), rid)

	if !reflect.DeepEqual(encMsg.GetPayloadA(), expectPayloadA) {
		t.Errorf("EncryptDecrypt() did not produce the correct payload "+
			"A in consistency test\n\treceived: %d\n\texpected: %d",
			encMsg.GetPayloadA(), expectPayloadA)
	}

	if !reflect.DeepEqual(encMsg.GetPayloadB(), expectPayloadB) {
		t.Errorf("EncryptDecrypt() did not produce the correct payload "+
			"B in consistency test \n\treceived: %d\n\texpected: %d",
			encMsg.GetPayloadB(), expectPayloadB)
	}
}

// Shows that multiplying the encrypted message by the inverse key decrypts it.
func TestDecrypt(t *testing.T) {
	//make and encrypt the message
	msg := makeMsg()
	size := 10
	baseKeys := makeBaseKeys(size)

	encMsg := ClientEncrypt(grp, msg, salt, baseKeys, rid)

	//general local keys
	hash, err := blake2b.New256(nil)
	if err != nil {
		t.Fatalf("E2E Client Encrypt could not get blake2b Hash: %+v", err)
	}

	hash.Reset()
	hash.Write(salt)

	//Generate encryption keys
	keyEcrA := ClientKeyGen(grp, salt, rid, baseKeys)
	keyEcrB := ClientKeyGen(grp, hash.Sum(nil), rid, baseKeys)

	//Generate the inverse of the keys
	keyEcrA_Inv := grp.Inverse(keyEcrA, grp.NewInt(1))
	keyEcrB_Inv := grp.Inverse(keyEcrB, grp.NewInt(1))

	//Simulate decryption by multiplying the encrypted message with the inverse of the encryption keys
	DecPayloadA := grp.Mul(keyEcrA_Inv, grp.NewIntFromBytes(encMsg.GetPayloadA()), grp.NewInt(1))
	DecPayloadB := grp.Mul(keyEcrB_Inv, grp.NewIntFromBytes(encMsg.GetPayloadB()), grp.NewInt(1))

	//Set decrypted messages to the above payloads
	decMsg := format.NewMessage(primeLength)
	decMsg.SetPayloadA(DecPayloadA.Bytes())
	decMsg.SetPayloadB(DecPayloadB.LeftpadBytes(uint64(primeLength)))

	//Compare decrypted message with the original message
	if !reflect.DeepEqual(decMsg.GetPayloadA(), msg.GetPayloadA()) {
		t.Errorf("EncryptDecrypt() did not produce the correct payload\n\treceived: %d\n\texpected: %d", decMsg.GetPayloadA(), msg.GetPayloadA())
	}

	if !reflect.DeepEqual(decMsg.GetPayloadB(), msg.GetPayloadB()) {
		t.Errorf("EncryptDecrypt() did not produce the correct associated data\n\treceived: %d\n\texpected: %d", decMsg.GetPayloadB(), msg.GetPayloadB())
	}
}
