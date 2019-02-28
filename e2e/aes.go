////////////////////////////////////////////////////////////////////////////////
// Copyright © 2019 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package e2e

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"gitlab.com/elixxir/crypto/csprng"
	"gitlab.com/elixxir/crypto/cyclic"
)

const AES256KeyLen = 32
const AESBlockSize = aes.BlockSize

// Helper function to apply PKCS #7 padding to plaintext
func pkcs7PadAES(ptext []byte) []byte {
	size := len(ptext)
	if ptext == nil || size == 0 {
		return nil
	}

	npad := AESBlockSize - (size % AESBlockSize)
	paddedText := make([]byte, size+npad)
	copy(paddedText, ptext)
	copy(paddedText[size:], bytes.Repeat([]byte{byte(npad)}, npad))

	return paddedText
}

// Helper function to remove PKCS #7 padding from decrypted text
func pkcs7UnpadAES(padtext []byte) []byte {
	size := len(padtext)
	if padtext == nil || size == 0 {
		return nil
	}

	padByte := padtext[size-1]
	nPads := int(padByte)
	if nPads == 0 || nPads > size {
		return nil
	}

	for i := 0; i < nPads; i++ {
		if padtext[size-nPads+i] != padByte {
			return nil
		}
	}

	return padtext[:size-nPads]
}

// Internal function with AES Encryption core
// key must have the size needed, and if it is bigger, the MSBs are used
// IV must be 16 bytes
// plaintext must be padded correctly
func encryptCore(key []byte, iv [AESBlockSize]byte, plaintext []byte) ([]byte, error) {
	if len(key) < AES256KeyLen {
		return nil, errors.New("Key is too small")
	}

	actualKey := key[:AES256KeyLen]

	size := len(plaintext)
	if plaintext == nil || size == 0 || size%AESBlockSize != 0 {
		return nil, errors.New("Plaintext is nil, empty or is not padded to blocksize")
	}

	block, err := aes.NewCipher(actualKey)
	if err != nil {
		return nil, errors.New("Error creating AES block cipher")
	}

	ciphertext := make([]byte, len(plaintext))

	encrypter := cipher.NewCBCEncrypter(block, iv[:])
	encrypter.CryptBlocks(ciphertext, plaintext)

	return ciphertext, nil
}

// Internal function with AES Decryption core
// key must have the size needed, and if it is bigger, the MSBs are used
// IV must be 16 bytes
// Padding is not removed from plaintext, caller should be in charge of that
func decryptCore(key []byte, iv [AESBlockSize]byte, ciphertext []byte) ([]byte, error) {
	if len(key) < AES256KeyLen {
		return nil, errors.New("Key is too small")
	}

	actualKey := key[:AES256KeyLen]

	size := len(ciphertext)
	if ciphertext == nil || size == 0 || size%AESBlockSize != 0 {
		return nil, errors.New("Ciphertext is nil, empty or is not multiple of blocksize")
	}

	block, err := aes.NewCipher(actualKey)
	if err != nil {
		return nil, errors.New("Error creating AES block cipher")
	}

	decryptor := cipher.NewCBCDecrypter(block, iv[:])
	decryptor.CryptBlocks(ciphertext, ciphertext)

	return ciphertext, nil
}

// Encrypt the plaintext using AES256 with the passed key and IV
// Plaintext is assumed to be unpadded, as padding is added internally
// Key should be 256bits or bigger. If bigger, the 256 MSBs are taken
// as the key
// IV must be 16 bytes, and it is recommended to be the MSBs of the
// key fingerprint
// Key and plaintext can't be nil nor empty
// Returns ciphertext if no error, otherwise nil and err
func EncryptAES256WithIV(key *cyclic.Int, iv [AESBlockSize]byte, plaintext []byte) ([]byte, error) {
	if key == nil || plaintext == nil {
		return nil, errors.New("Key and/or plaintext are nil")
	}

	kBytes := key.Bytes()
	plaintext = pkcs7PadAES(plaintext)
	if plaintext == nil {
		return nil, errors.New("Error padding plaintext")
	}

	return encryptCore(kBytes, iv, plaintext)
}

// Decrypt a ciphertext using AES256 with the passed key and IV
// Ciphertext is assumed to not have the IV, and to be padded
// Key should be 256bits or bigger. If bigger, the 256 MSBs are taken
// as the key
// IV must be 16 bytes, and it is recommended to be the MSBs of the
// key fingerprint
// Key and ciphertext can't be nil nor empty
// Padding is removed internally
// Returns decrypted plaintext if no error, otherwise nil and err
func DecryptAES256WithIV(key *cyclic.Int, iv [AESBlockSize]byte, ciphertext []byte) ([]byte, error) {
	if key == nil || ciphertext == nil {
		return nil, errors.New("Key and/or ciphertext are nil")
	}

	kBytes := key.Bytes()
	plaintext, err := decryptCore(kBytes, iv, ciphertext)
	if err != nil {
		return nil, err
	}

	plaintext = pkcs7UnpadAES(plaintext)
	if plaintext == nil {
		return nil, errors.New("Error unpadding plaintext")
	}

	return plaintext, nil
}

// Encrypt the plaintext using AES256 with the passed key
// Plaintext is assumed to be unpadded, as padding is added internally
// Key should be 256bits or bigger. If bigger, the 256 MSBs are taken
// as the key
// Key and plaintext can't be nil nor empty
// IV is generated internally and returned as first 16 bytes of the ciphertext
// Returns ciphertext if no error, otherwise nil and err
func EncryptAES256(key *cyclic.Int, plaintext []byte) ([]byte, error) {
	// Generate IV
	iv := make([]byte, AESBlockSize)
	randGen := csprng.SystemRNG{}
	size, err := randGen.Read(iv)
	if err != nil || size != len(iv) {
		return nil, errors.New("Error generating IV")
	}

	var iv_arr [AESBlockSize]byte
	copy(iv_arr[:], iv)

	// Simply call encrypt with IV
	ciphertext, err := EncryptAES256WithIV(key, iv_arr, plaintext)
	if err != nil {
		return nil, err
	}

	// Prepend IV to ciphertext
	ciphertext = append(iv, ciphertext...)
	return ciphertext, nil
}

// Decrypt a ciphertext using AES256 with the passed key
// Ciphertext is assumed to start with the IV
// Key should be 256bits or bigger. If bigger, the 256 MSBs are taken
// as the key
// key and ciphertext can't be nil nor empty
// Padding and IV are removed internally
// Returns decrypted plaintext if no error, otherwise nil and err
func DecryptAES256(key *cyclic.Int, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 2*AESBlockSize {
		return nil, errors.New("Ciphertext minimum length not met")
	}

	var iv_arr [AESBlockSize]byte
	copy(iv_arr[:], ciphertext[:AESBlockSize])

	return DecryptAES256WithIV(key, iv_arr, ciphertext[AESBlockSize:])
}
