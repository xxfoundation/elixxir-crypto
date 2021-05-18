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
		t.Error("E2E Client Encrypt could not get blake2b Hash")
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
	expectPayloadA := []byte{69, 87, 37, 169, 22, 249, 49, 209, 42, 157, 253, 162, 167, 248, 50, 219, 86, 17, 50, 206,
		181, 56, 229, 155, 36, 78, 55, 123, 60, 180, 157, 188, 199, 22, 63, 129, 101, 245, 17, 117, 190, 177, 180, 113,
		132, 74, 4, 86, 209, 241, 116, 218, 200, 149, 174, 250, 85, 237, 218, 132, 177, 186, 14, 197, 103, 206, 11, 252,
		82, 249, 85, 111, 135, 141, 150, 78, 71, 243, 44, 208, 153, 141, 61, 183, 238, 214, 73, 254, 84, 116, 144, 71,
		47, 234, 87, 59, 174, 84, 125, 177, 174, 70, 69, 254, 60, 127, 147, 72, 242, 125, 87, 223, 151, 80, 10, 249, 33,
		255, 203, 153, 131, 72, 129, 115, 206, 143, 196, 20, 132, 235, 194, 237, 225, 159, 70, 127, 113, 232, 178, 32,
		235, 45, 224, 102, 198, 200, 120, 58, 187, 110, 27, 94, 251, 27, 255, 144, 134, 109, 152, 13, 198, 188, 93, 105,
		13, 47, 164, 83, 95, 170, 71, 232, 163, 134, 32, 122, 134, 113, 124, 15, 26, 166, 56, 159, 235, 95, 162, 244,
		102, 216, 76, 218, 144, 170, 159, 114, 127, 228, 62, 65, 54, 100, 215, 148, 11, 24, 13, 28, 111, 103, 252, 152,
		224, 31, 208, 204, 201, 15, 58, 9, 69, 231, 6, 47, 195, 224, 111, 147, 247, 4, 50, 17, 0, 238, 171, 183, 213,
		41, 163, 38, 237, 202, 141, 123, 200, 242, 30, 22, 156, 125, 63, 12, 27, 100, 173, 170}

	expectPayloadB := []byte{90, 218, 196, 213, 99, 76, 26, 192, 94, 91, 91, 244, 1, 16, 3, 249, 2, 234, 108, 233, 248,
		149, 215, 11, 139, 209, 79, 171, 228, 150, 35, 213, 102, 79, 75, 83, 43, 70, 11, 221, 134, 255, 152, 163, 87,
		117, 64, 52, 49, 212, 204, 178, 229, 171, 5, 165, 193, 38, 254, 112, 114, 5, 185, 218, 149, 87, 1, 229, 177, 86,
		61, 6, 147, 164, 68, 109, 237, 150, 236, 230, 84, 47, 109, 58, 79, 183, 108, 75, 21, 133, 119, 69, 173, 87, 68,
		235, 232, 38, 105, 197, 173, 11, 56, 171, 242, 243, 130, 186, 206, 224, 47, 224, 60, 169, 177, 33, 77, 72, 122,
		33, 9, 96, 205, 198, 9, 108, 90, 173, 186, 107, 63, 131, 21, 90, 224, 105, 66, 116, 203, 107, 48, 95, 34, 122,
		255, 201, 241, 155, 171, 203, 121, 223, 112, 189, 138, 229, 18, 121, 34, 43, 231, 211, 107, 117, 149, 106, 45,
		119, 74, 69, 141, 7, 248, 68, 83, 171, 54, 204, 40, 74, 106, 181, 41, 223, 34, 241, 2, 23, 103, 70, 153, 172,
		73, 244, 153, 29, 138, 51, 2, 226, 35, 32, 184, 94, 189, 44, 20, 27, 152, 39, 205, 97, 71, 8, 8, 76, 235, 117,
		20, 211, 141, 50, 163, 217, 234, 242, 56, 126, 214, 88, 119, 59, 39, 233, 204, 95, 142, 230, 176, 101, 52, 29,
		84, 193, 67, 29, 56, 178, 203, 54, 81, 212, 171, 171, 134, 170}

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
		t.Error("E2E Client Encrypt could not get blake2b Hash")
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
