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

// Helper function to apply PKCS #7 padding to plaintext
func pkcs7PadAES(ptext []byte) []byte {
	size := len(ptext)
	if ptext == nil || size == 0 {
		return nil
	}

	npad := aes.BlockSize - (size % aes.BlockSize)
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
func encryptCore(key, iv, plaintext []byte) ([]byte, error) {
	if len(key) < AES256KeyLen {
		return nil, errors.New("Key is too small")
	}

	actualKey := key[:AES256KeyLen]

	if iv == nil || len(iv) != aes.BlockSize {
		return nil, errors.New("IV is nil or its size is not 16 bytes")
	}

	size := len(plaintext)
	if plaintext == nil || size == 0 || size%aes.BlockSize != 0 {
		return nil, errors.New("Plaintext is nil, empty or is not padded to blocksize")
	}

	block, err := aes.NewCipher(actualKey)
	if err != nil {
		return nil, errors.New("Error creating AES block cipher")
	}

	ciphertext := make([]byte, len(plaintext))

	encrypter := cipher.NewCBCEncrypter(block, iv)
	encrypter.CryptBlocks(ciphertext, plaintext)

	return ciphertext, nil
}

// Internal function with AES Decryption core
// key must have the size needed, and if it is bigger, the MSBs are used
// IV must be 16 bytes
// Padding is not removed from plaintext, caller should be in charge of that
func decryptCore(key, iv, ciphertext []byte) ([]byte, error) {
	if len(key) < AES256KeyLen {
		return nil, errors.New("Key is too small")
	}

	actualKey := key[:AES256KeyLen]

	if iv == nil || len(iv) != aes.BlockSize {
		return nil, errors.New("IV is nil or its size is not 16 bytes")
	}

	size := len(ciphertext)
	if ciphertext == nil || size == 0 || size%aes.BlockSize != 0 {
		return nil, errors.New("Ciphertext is nil, empty or is not multiple of blocksize")
	}

	block, err := aes.NewCipher(actualKey)
	if err != nil {
		return nil, errors.New("Error creating AES block cipher")
	}

	decryptor := cipher.NewCBCDecrypter(block, iv)
	decryptor.CryptBlocks(ciphertext, ciphertext)

	return ciphertext, nil
}

// Encrypt the plaintext using AES256 with the passed key
// Plaintext is assumed to be unpadded, as padding is added internally
// Key should be 256bits or bigger. If bigger, the 256 MSBs are taken
// as the key
// Key and plaintext can't be nil
// IV is returned as first 16 bytes of the ciphertext
// Returns ciphertext if no error, otherwise nil and err
func EncryptAES256(key *cyclic.Int, plaintext []byte) ([]byte, error) {
	if key == nil || plaintext == nil {
		return nil, errors.New("Key and/or plaintext are nil")
	}

	kBytes := key.Bytes()
	iv := make([]byte, aes.BlockSize)
	randGen := csprng.SystemRNG{}
	size, err := randGen.Read(iv)
	if err != nil || size != len(iv) {
		return nil, errors.New("Error generating IV")
	}

	plaintext = pkcs7PadAES(plaintext)
	if plaintext == nil {
		return nil, errors.New("Error padding plaintext")
	}

	ciphertext, err := encryptCore(kBytes, iv, plaintext)
	if err != nil {
		return nil, err
	}

	ciphertext = append(iv, ciphertext...)
	return ciphertext, nil
}

// Decrypt a ciphertext using AES256 with the passed key
// Ciphertext is assumed to start with the IV
// Key should be 256bits or bigger. If bigger, the 256 MSBs are taken
// as the key
// key and ciphertext can't be nil
// Padding and IV are removed internally
// Returns decrypted plaintext if no error, otherwise nil and err
func DecryptAES256(key *cyclic.Int, ciphertext []byte) ([]byte, error) {
	if key == nil || ciphertext == nil {
		return nil, errors.New("Key and/or ciphertext are nil")
	}

	if len(ciphertext) == 0 {
		return nil, errors.New("Ciphertext is empty")
	}

	kBytes := key.Bytes()
	plaintext, err := decryptCore(kBytes, ciphertext[:aes.BlockSize], ciphertext[aes.BlockSize:])
	if err != nil {
		return nil, err
	}

	plaintext = pkcs7UnpadAES(plaintext)
	if plaintext == nil {
		return nil, errors.New("Error unpadding plaintext")
	}

	return plaintext, nil
}
