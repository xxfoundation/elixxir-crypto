////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package e2e

import (
	"bytes"
	"encoding/hex"
	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/crypto/large"
	"testing"
)

//------------------------------------------------------------------------------------------------//
//-------------------------- Consistency tests for not exported functions ------------------------//
//------------------------------------------------------------------------------------------------//

// Test Vectors taken from section F.2.5 of NIST SP 800-38A
const (
	TEST_VECTOR_IV  = "000102030405060708090a0b0c0d0e0f"
	TEST_VECTOR_KEY = "603deb1015ca71be2b73aef0857d7781" +
		"1f352c073b6108d72d9810a30914dff4"
	TEST_VECTOR_PLAINTEXT = "6bc1bee22e409f96e93d7e117393172a" +
		"ae2d8a571e03ac9c9eb76fac45af8e51" +
		"30c81c46a35ce411e5fbc1191a0a52ef" +
		"f69f2445df4f9b17ad2b417be66c3710"
	TEST_VECTOR_CIPHERTEXT = "f58c4c04d6e5f1ba779eabfb5f7bfbd6" +
		"9cfc4e967edb808d679f777bc6702c7d" +
		"39f23369a9d9bacfa530e26304231461" +
		"b2eb05e2c39be9fcda6c19078c6a9d1b"
)

func TestErrorCases(t *testing.T) {
	_, err := pkcs7PadAES(nil)
	if err == nil {
		t.Error("Failed to detect a nil pad")
	}

	_, err = pkcs7UnpadAES(nil)
	if err == nil {
		t.Error("Failed to detect a nil pad")
	}

}

// Test Encryption core against test vectors
func TestEncryptCore(t *testing.T) {
	iv, _ := hex.DecodeString(TEST_VECTOR_IV)
	key, _ := hex.DecodeString(TEST_VECTOR_KEY)
	ptext, _ := hex.DecodeString(TEST_VECTOR_PLAINTEXT)
	ctext, _ := hex.DecodeString(TEST_VECTOR_CIPHERTEXT)

	var key_arr [AES256KeyLen]byte
	copy(key_arr[:], key)
	var iv_arr [AESBlockSize]byte
	copy(iv_arr[:], iv)

	result, err := encryptCore(key_arr, iv_arr, ptext)

	if err != nil {
		t.Errorf("AES Encryption Core returned error: %s", err.Error())
	}

	if !bytes.Equal(result, ctext) {
		t.Errorf("Ciphertext after encryption doesn't match with test vector")
	}
}

// Test Decryption core against test vectors
func TestDecryptCore(t *testing.T) {
	iv, _ := hex.DecodeString(TEST_VECTOR_IV)
	key, _ := hex.DecodeString(TEST_VECTOR_KEY)
	ptext, _ := hex.DecodeString(TEST_VECTOR_PLAINTEXT)
	ctext, _ := hex.DecodeString(TEST_VECTOR_CIPHERTEXT)

	var key_arr [AES256KeyLen]byte
	copy(key_arr[:], key)
	var iv_arr [AESBlockSize]byte
	copy(iv_arr[:], iv)

	result, err := decryptCore(key_arr, iv_arr, ctext)

	if err != nil {
		t.Errorf("AES Decryption Core returned error: %s", err.Error())
	}

	if !bytes.Equal(result, ptext) {
		t.Errorf("Plaintext after decryption doesn't match with test vector")
	}
}

//------------------------------------------------------------------------------------------------//
//--------------------------- Normal tests for not exported functions ----------------------------//
//------------------------------------------------------------------------------------------------//

// Test Encryption core with bad arguments
func TestEncryptCore_BadArgs(t *testing.T) {
	key, _ := hex.DecodeString(TEST_VECTOR_KEY)
	iv, _ := hex.DecodeString(TEST_VECTOR_IV)
	ptext := [][]byte{
		[]byte("0123456789ABCDEF"),
		[]byte("01234"),
		[]byte(""),
		nil,
	}

	var key_arr [AES256KeyLen]byte
	copy(key_arr[:], key)
	var iv_arr [AESBlockSize]byte
	copy(iv_arr[:], iv)

	tests := len(ptext)
	pass := 0

	for i := 0; i < tests; i++ {
		result, err := encryptCore(key_arr, iv_arr, ptext[i])

		if i == 0 {
			if err != nil {
				t.Errorf("AES Encryption Core returned error: %s", err.Error())
			} else {
				pass++
			}
		} else {
			if result != nil || err == nil {
				t.Errorf("AES Encryption should have returned error")
			} else {
				pass++
			}
		}
	}
	println("TestEncryptCore_BadArgs()", pass, "out of", tests, "tests passed.")
}

// Test Decryption core with bad arguments
func TestDecryptCore_BadArgs(t *testing.T) {
	key, _ := hex.DecodeString(TEST_VECTOR_KEY)
	iv, _ := hex.DecodeString(TEST_VECTOR_IV)
	ptext := [][]byte{
		[]byte("0123456789ABCDEF"),
		[]byte("01234"),
		[]byte(""),
		nil,
	}

	var key_arr [AES256KeyLen]byte
	copy(key_arr[:], key)
	var iv_arr [AESBlockSize]byte
	copy(iv_arr[:], iv)

	tests := len(ptext)
	pass := 0

	for i := 0; i < tests; i++ {
		result, err := decryptCore(key_arr, iv_arr, ptext[i])

		if i == 0 {
			if err != nil {
				t.Errorf("AES Decryption Core returned error: %s", err.Error())
			} else {
				pass++
			}
		} else {
			if result != nil || err == nil {
				t.Errorf("AES Decryption should have returned error")
			} else {
				pass++
			}
		}
	}
	println("TestEncryptCore_BadArgs()", pass, "out of", tests, "tests passed.")
}

//------------------------------------------------------------------------------------------------//
//--------------------------------- Tests for exported functions ---------------------------------//
//------------------------------------------------------------------------------------------------//
const (
	TEST_MSG      = "The quick brown fox jumps over the lazy dog"
	TEST_KEY_2048 = "4851871933b715040372862bbddc4bfcae7607f9a392172496b585534533e2ce" +
		"b09729d6a6e76303398c5ad633fb891fb7edd73c8be869cce5b6fcf58283be60" +
		"6e0ddf1abf68e653a853530862e4caefcc2206da5791d456eb4ec58f5b9ac0c6" +
		"979b2283709d2edb6aef710d64f35258c7f9e81b4dd774f7cbda371596a30530" +
		"f75d7faad055803f414691f4bd542c0f4e86e91d0b1f0566f07e3ad91b248c62" +
		"ed0b11c09f82c4c7efadef0db3b00520276123004be72f8590383e1aefada620" +
		"48da9b9875de4892c8551d879f770f4d884e59cdf9946523d61e6563318dd402" +
		"624092d6f633fb244bfaf96a9b92dd9e128504ce915b6ed0b5154750b9df4fed"
	TEST_KEY_256 = "386ac152fb0234d7e7b76d69bd13e92734e299c6f07db78112ac37e4ef4d8605"
	TEST_KEY_248 = "fe6cd9428ecd3b7b91c01e26eb8429f53d71418f01e5d96068a6f443efd55c"
	TEST_KEY_128 = "636fc269a3346655ed376756e1533009"
	TEST_IV      = "0123456789ABCDEF"
	TEST_CIPHER  = "0123456789ABCDEFabcdefghijklmno"
	NUM_TESTS    = int(10000)
)

//----------------------------------- Simple enc/dec tests ---------------------------------------//

// Test AES encryption/decryption with 256bit key
func TestEncDecAES_256Key(t *testing.T) {
	key, _ := hex.DecodeString(TEST_KEY_256)
	plaintext := []byte(TEST_MSG)
	ciphertext, err := EncryptAES256(key, plaintext)

	if err != nil {
		t.Errorf("AES Encryption returned error: %s", err.Error())
	}

	result, err := DecryptAES256(key, ciphertext)

	if err != nil {
		t.Errorf("AES Decryption returned error: %s", err.Error())
	}

	if !bytes.Equal(plaintext, result) {
		t.Errorf("Plaintext after encryption/decryption doesn't match with original!")
	}
}

// Test AES encryption/decryption with 2048bit key
func TestEncDecAES_2048Key(t *testing.T) {
	key, _ := hex.DecodeString(TEST_KEY_2048)
	plaintext := []byte(TEST_MSG)
	ciphertext, err := EncryptAES256(key, plaintext)

	if err != nil {
		t.Errorf("AES Encryption returned error: %s", err.Error())
	}

	result, err := DecryptAES256(key, ciphertext)

	if err != nil {
		t.Errorf("AES Decryption returned error: %s", err.Error())
	}

	if !bytes.Equal(plaintext, result) {
		t.Errorf("Plaintext after encryption/decryption doesn't match with original!")
	}
}

// Test AES encryption/decryption with different keys
func TestEncDecAES_BadKey(t *testing.T) {
	key, _ := hex.DecodeString(TEST_KEY_2048)
	plaintext := []byte(TEST_MSG)
	ciphertext, err := EncryptAES256(key, plaintext)

	if err != nil {
		t.Errorf("AES Encryption returned error: %s", err.Error())
	}

	badkey, _ := hex.DecodeString(TEST_KEY_256)
	result, err := DecryptAES256(badkey, ciphertext)

	if result != nil || err == nil {
		t.Errorf("AES Decryption should have returned error")
	}
}

//---------------------------------- Test various arguments --------------------------------------//

// Test AES encryption with various arguments
func TestEncAES_Args(t *testing.T) {
	keys := [][]byte{
		large.NewIntFromString(TEST_KEY_256, 16).Bytes(),
		large.NewIntFromString(TEST_KEY_248, 16).Bytes(),
		large.NewIntFromString(TEST_KEY_128, 16).Bytes(),
		[]byte(""),
		nil,
	}

	ptext := [][]byte{
		[]byte(TEST_MSG),
		[]byte(""),
		nil,
	}

	tests := len(ptext) * len(keys)
	pass := 0

	for i := 0; i < tests; i++ {
		ciphertext, err := EncryptAES256(keys[i%len(keys)], ptext[i/len(keys)])

		if i%len(keys) == 4 || i/len(keys) > 0 {
			if ciphertext != nil || err == nil {
				t.Errorf("AES Encryption should have returned error")
			} else {
				pass++
			}
		} else {
			if err != nil {
				t.Errorf("AES Encryption returned error: %s", err.Error())
			} else {
				pass++
			}
		}
	}
	println("TestEncAES_Args()", pass, "out of", tests, "tests passed.")
}

// Test AES decryption with various arguments
func TestDecAES_Args(t *testing.T) {
	key, _ := hex.DecodeString(TEST_KEY_256)
	plaintext := []byte(TEST_MSG)
	ciphertext, err := EncryptAES256(key, plaintext)

	if err != nil {
		t.Errorf("AES Encryption returned error: %s", err.Error())
	}

	keys := [][]byte{
		large.NewIntFromString(TEST_KEY_256, 16).Bytes(),
		[]byte(""),
		nil}

	ctext := [][]byte{
		ciphertext,
		[]byte(TEST_CIPHER),
		[]byte(""),
		nil,
	}

	tests := len(ctext) * len(keys)
	pass := 0

	for i := 0; i < tests; i++ {
		result, err := DecryptAES256(keys[i%len(keys)], ctext[i/len(keys)])

		if i == 0 {
			if err != nil {
				t.Errorf("AES Decryption returned error: %s", err.Error())
			} else {
				pass++
			}
		} else {
			if result != nil || err == nil {
				t.Errorf("AES Decryption should have returned error")
			} else {
				pass++
			}
		}
	}
	println("TestDecAES_Keys()", pass, "out of", tests, "tests passed.")
}

// Test AES encryption/decryption with fixed IV
func TestEncAES_IVs(t *testing.T) {
	key, _ := hex.DecodeString(TEST_KEY_2048)
	iv := []byte(TEST_IV)
	ptext := []byte(TEST_MSG)

	var iv_arr [AESBlockSize]byte
	copy(iv_arr[:], iv)

	ciphertext, err := EncryptAES256WithIV(key, iv_arr, ptext)

	if err != nil {
		t.Errorf("AES EncryptionWithIV returned error: %s", err.Error())
	}

	result, err := DecryptAES256WithIV(key, iv_arr, ciphertext)

	if err != nil {
		t.Errorf("AES DecryptionWithIV returned error: %s", err.Error())
	}

	if !bytes.Equal(ptext, result) {
		t.Errorf("Plaintext after encryption/decryption doesn't match with original!")
	}
}

// Test that AES encryption is hashing the key correctly internally
// Note that if AES decryption is doing the hash wrong, any other test
// that does encrypt/decrypt will fail because the wrong key will be used
// on decryption, resulting in an error
func TestAESEnc_Hash(t *testing.T) {
	key, _ := hex.DecodeString(TEST_KEY_2048)
	iv := []byte(TEST_IV)
	ptext := []byte(TEST_MSG)
	ptext, _ = pkcs7PadAES(ptext)

	var iv_arr [AESBlockSize]byte
	copy(iv_arr[:], iv)

	var badKey [AES256KeyLen]byte
	copy(badKey[:], key)

	// If the hash is broken internally, the key used will be simply the
	// truncated key, so use that in encrypt core to set target
	// wrong ciphertext
	badCiphertext, err := encryptCore(badKey, iv_arr, ptext)
	if err != nil {
		t.Errorf("AES Encryption Core returned error: %s", err.Error())
	}

	ciphertext, err := EncryptAES256WithIV(key, iv_arr, ptext)

	if err != nil {
		t.Errorf("AES EncryptionWithIV returned error: %s", err.Error())
	}

	if bytes.Contains(ciphertext, badCiphertext) {
		t.Errorf("AES EncryptionWithIV is not correctly hashing the key")
	}
}

//---------------------------------- Test random inputs ------------------------------------------//

// Loop test AES encryption/decryption with random inputs
func TestEncDecAES_Random(t *testing.T) {
	rng := csprng.NewSystemRNG()
	key := make([]byte, 256)
	plaintext := make([]byte, 2048)

	tests := NUM_TESTS
	pass := 0

	for i := 0; i < tests; i++ {
		rng.Read(key)
		rng.Read(plaintext)

		ciphertext, err := EncryptAES256(key, plaintext)

		if err != nil {
			t.Errorf("AES Encryption returned error: %s", err.Error())
		}

		result, err := DecryptAES256(key, ciphertext)

		if err != nil {
			t.Errorf("AES Decryption returned error: %s", err.Error())
		} else if !bytes.Equal(plaintext, result) {
			t.Errorf("Plaintext after encryption/decryption doesn't match with original!")
		} else {
			pass++
		}
	}
	println("TestEncDecAES_Random()", pass, "out of", tests, "tests passed.")
}

// Loop test AES encryption/decryption with increasing plaintext sizes to test all paddings
func TestEncDecAES_AllPaddings(t *testing.T) {
	key, _ := hex.DecodeString(TEST_KEY_2048)

	tests := NUM_TESTS
	pass := 0

	rng := csprng.NewSystemRNG()

	for i := 1; i <= NUM_TESTS; i++ {

		plaintext := make([]byte, i)
		rng.Read(plaintext)

		ciphertext, err := EncryptAES256(key, plaintext)

		if err != nil {
			t.Errorf("AES Encryption returned error: %s", err.Error())
		}

		result, err := DecryptAES256(key, ciphertext)

		if err != nil {
			t.Errorf("AES Decryption returned error: %s", err.Error())
		} else if !bytes.Equal(plaintext, result) {
			t.Errorf("Plaintext after encryption/decryption doesn't match with original!")
		} else {
			pass++
		}
	}
	println("TestEncDecAES_AllPaddings()", pass, "out of", tests, "tests passed.")
}
