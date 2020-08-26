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
func makeMsg() format.Message {
	rng := rand.New(rand.NewSource(21))
	payloadA := make([]byte, grp.GetP().ByteLen())
	payloadB := make([]byte, grp.GetP().ByteLen())
	rng.Read(payloadA)
	rng.Read(payloadB)
	msg := format.NewMessage(grp.GetP().ByteLen())
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
	grp.Mul(keyEcrB, grp.NewIntFromBytes(msg.GetPayloadB()), multPayloadB)

	testMsg := format.NewMessage(grp.GetP().ByteLen())
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

	expectPLB := []byte{204, 47, 167, 175, 197, 191, 173, 43, 192, 50, 98, 5, 203, 129, 99, 127, 29, 81, 150, 174, 174,
		101, 93, 228, 139, 239, 137, 24, 217, 91, 121, 116, 130, 249, 66, 173, 236, 44, 102, 36, 118, 242, 108, 5, 185,
		143, 101, 182, 172, 152, 11, 204, 115, 155, 236, 154, 90, 254, 125, 146, 188, 193, 20, 180, 117, 143, 65, 125,
		25, 11, 71, 144, 51, 0, 30, 105, 17, 210, 97, 199, 79, 4, 81, 178, 150, 88, 255, 111, 218, 212, 78, 179, 197,
		237, 119, 149, 52, 34, 55, 240, 1, 219, 84, 173, 77, 123, 60, 49, 177, 5, 108, 204, 155, 52, 1, 16, 192, 125,
		69, 152, 50, 217, 223, 170, 210, 136, 228, 155, 145, 214, 81, 45, 237, 77, 13, 236, 80, 250, 248, 111, 91, 81,
		94, 71, 241, 159, 66, 82, 237, 24, 75, 241, 21, 235, 67, 134, 124, 18, 143, 177, 139, 250, 126, 250, 28, 139,
		102, 243, 136, 86, 123, 141, 124, 166, 214, 31, 75, 74, 63, 245, 224, 168, 221, 161, 167, 130, 61, 246, 208,
		108, 184, 222, 71, 135, 0, 9, 110, 47, 153, 193, 49, 136, 136, 249, 211, 239, 164, 37, 220, 140, 34, 131, 21,
		202, 248, 54, 182, 39, 60, 136, 37, 118, 24, 0, 79, 214, 127, 164, 225, 100, 123, 247, 6, 226, 254, 242, 210,
		136, 18, 102, 227, 190, 100, 232, 3, 75, 149, 36, 251, 65, 38, 234, 249, 95, 94, 245}

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
	decMsg := format.NewMessage(grp.GetP().ByteLen())
	decMsg.SetPayloadA(DecPayloadA.Bytes())
	decMsg.SetPayloadB(DecPayloadB.LeftpadBytes(uint64(grp.GetP().ByteLen())))

	//Compare decrypted message with the original message
	if !reflect.DeepEqual(decMsg.GetPayloadA(), msg.GetPayloadA()) {
		t.Errorf("EncryptDecrypt() did not produce the correct payload\n\treceived: %d\n\texpected: %d", decMsg.GetPayloadA(), msg.GetPayloadA())
	}

	if !reflect.DeepEqual(decMsg.GetPayloadB(), msg.GetPayloadB()) {
		t.Errorf("EncryptDecrypt() did not produce the correct associated data\n\treceived: %d\n\texpected: %d", decMsg.GetPayloadB(), msg.GetPayloadB())
	}
}
