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
	expectPayloadA := []byte{138, 3, 6, 246, 237, 200, 193, 179, 155, 223, 231, 145, 21, 56, 216, 129, 219, 12, 163, 45,
		14, 216, 222, 52, 126, 59, 239, 65, 255, 91, 35, 35, 248, 37, 246, 108, 101, 62, 252, 13, 123, 205, 235, 227,
		145, 189, 127, 197, 36, 200, 157, 171, 136, 192, 230, 158, 88, 7, 167, 138, 181, 47, 241, 108, 165, 125, 164,
		76, 146, 99, 246, 155, 66, 35, 90, 247, 226, 184, 123, 250, 30, 9, 112, 24, 146, 32, 114, 152, 230, 44, 253,
		201, 169, 64, 128, 113, 64, 148, 34, 121, 214, 178, 60, 232, 202, 190, 253, 209, 211, 237, 36, 114, 53, 81, 60,
		105, 232, 177, 193, 0, 188, 111, 81, 195, 168, 56, 237, 165, 237, 254, 19, 223, 170, 132, 218, 228, 111, 77,
		176, 17, 215, 197, 100, 74, 79, 240, 47, 231, 17, 236, 57, 37, 44, 53, 72, 173, 134, 184, 13, 212, 134, 26, 236,
		213, 121, 82, 204, 139, 248, 58, 189, 108, 228, 228, 11, 19, 93, 164, 242, 128, 45, 97, 14, 131, 33, 220, 5,
		241, 168, 219, 131, 65, 125, 81, 171, 251, 13, 103, 59, 66, 32, 44, 103, 181, 51, 115, 180, 173, 52, 63, 143,
		206, 117, 245, 134, 159, 92, 225, 242, 89, 65, 127, 29, 184, 27, 93, 54, 241, 87, 46, 127, 100, 98, 142, 233,
		64, 220, 120, 89, 72, 129, 134, 45, 5, 112, 232, 252, 194, 34, 136, 207, 153, 112, 228, 119, 29}

	expectPayloadB := []byte{52, 176, 178, 247, 133, 16, 100, 130, 232, 96, 232, 38, 210, 162, 223, 252, 207, 189,
		208, 0, 195, 49, 197, 179, 50, 72, 194, 151, 99, 10, 249, 46, 43, 1, 134, 199, 199, 182, 192, 226, 91, 77,
		96, 174, 108, 223, 88, 33, 51, 46, 47, 176, 25, 0, 28, 69, 74, 22, 61, 63, 194, 47, 104, 2, 163, 152, 192,
		11, 41, 149, 167, 155, 109, 228, 181, 130, 159, 74, 69, 228, 43, 220, 117, 241, 215, 73, 94, 63, 36, 254,
		103, 46, 16, 23, 80, 34, 10, 35, 27, 144, 101, 181, 11, 89, 104, 150, 229, 65, 16, 117, 255, 145, 164, 212,
		57, 96, 220, 152, 219, 177, 131, 154, 150, 95, 78, 111, 104, 237, 214, 143, 162, 33, 226, 104, 20, 132, 46,
		133, 231, 68, 172, 6, 235, 197, 165, 162, 235, 185, 4, 210, 124, 107, 213, 203, 179, 186, 254, 192, 217,
		254, 95, 95, 76, 112, 128, 123, 34, 62, 163, 188, 59, 167, 158, 161, 19, 129, 28, 105, 132, 151, 66, 64,
		234, 253, 8, 30, 80, 19, 184, 39, 197, 112, 58, 73, 63, 58, 229, 33, 39, 167, 8, 89, 216, 102, 190, 77, 15,
		169, 42, 24, 160, 42, 186, 137, 204, 53, 188, 197, 174, 148, 198, 217, 68, 208, 30, 27, 25, 167, 228, 156,
		72, 92, 137, 64, 99, 90, 141, 121, 67, 151, 52, 129, 97, 104, 27, 154, 161, 233, 8, 126, 179, 123, 209, 162,
		115, 120}

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
