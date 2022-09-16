package rsa

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"gitlab.com/elixxir/crypto/hash"
	"strconv"
	"testing"
)

// Smoke test. Ensure that DecryptOAEP can decrypt the output from EncryptOAEP.
// Also ensure decryption returns original input to EncryptOAEP.
func TestEncryptDectyptOAEP(t *testing.T) {
	// Generate keys
	sLocal := GetScheme()
	rng := rand.Reader

	privKey, err := sLocal.GenerateDefault(rng)
	if err != nil {
		t.Errorf("GenerateDefault: %v", err)
	}

	pubKey := privKey.Public()

	// Generate encryption hashing functions
	hashFunc := hash.DefaultHash()

	for i := 0; i < numTest; i++ {
		// Construct encryption parameters
		data := []byte("hello user" + strconv.Itoa(i) + "!")
		label := []byte(strconv.Itoa(i + 1))

		// Encrypt data
		encrypted, err := pubKey.EncryptOAEP(hashFunc, rng, data, label)
		if err != nil {
			t.Fatalf("EncryptOAEP error: %+v", err)
		}

		// Decrypt data
		decrypted, err := privKey.DecryptOAEP(hashFunc, rng, encrypted, label)
		if err != nil {
			t.Fatalf("DecryptOAEP error: %+v", err)
		}

		// Check that decrypted text matches the original plaintext
		if !bytes.Equal(decrypted, data) {
			t.Fatalf("Decrypted data does not match original plaintext."+
				"\nExpected: %+v"+
				"\nReceived: %v", data, decrypted)
		}
	}
}

// Consistency test. Given pre-canned deterministic input to generate a
// PrivateKey, check that the output for EncryptOAEP is deterministic.
func TestPrivate_EncryptOAEP_Consistency(t *testing.T) {

	// Using a PRNG with same source so the output is the same on each run
	prng := &CountingReader{}

	// Generate keys
	sLocal := GetScheme()

	privKey, err := sLocal.Generate(prng, 1024)
	if err != nil {
		t.Errorf("GenerateDefault: %v", err)
	}

	pubKey := privKey.Public()

	// Encryption hashing functions
	hashFunc := hash.DefaultHash()

	// Expected output
	expectedOutput := []string{
		"G5+YcK/mo9npEZIhXbxRpQykuxLGhuu7abxvZ0VGiDSc348WoKmNrxWbjCRzJ7boOTx6grCVXSVJsljwF+YoXLbIxEqJGMjMqWnmVJAxGj0D2V8J0EBeYCfbJ/gcVuq8lybXHXlidTdI0J+TQMCydqgdqUANnvKttst2XTgPJT8=",
		"c9kBM9Xd3zI502daeJNGKNr0Am0B85waD9Z28pILN3xoetFwek+U+ViKx+q7iZBiGL64m4h9suR4J9FA/xfvzm7xtZeUi+oLIwtwLw/zNfEZf1K5RbgqDhtNJ+uX9zwp5g/xR59/KFtkCoeFb4iCwGw+5AqOuc+gGqiXpnh/pW0=",
		"saa60bG6AisGuA3Ev+oLP55KEF9664T8mt+mi8vhw44je+ThpfZjiO1TMfPd1VBDPW63AG3LnYd6XQYgnP5OyXlhCaj1JNrE0n2jJiVuQ6m1Wo/g6t2ubokO1rD4WbUfktGNObXkqDx57alla0RlbHT4RWWeSnRyRpYXjQRlPCQ=",
		"lpdYLK7pVwp6RMOWrmQZj+BbMpBrys10J9wGjgu0QvGkQmcmPE2tnOIEF770l95lnS6+k+UslHnXMrAE+5fyJvv2tqmJTEaTwgla0wIljHAKZAyKGORNuz4uexwREcbqthQITVyb4M5kwiQsCIKXyNacMuUcEQez9hAOYdQhkCo=",
		"AsDYBlrd2QacDGsn7KYn4+m2O4Vio2Y13RTK47QxHLnI5bgLKVhLxrFR7vcQMP8kvoDt9q8KEesMDleHkdke2SYDCqxMuYmqE89WdKc/U8PIoexFpb5AP+2eKDzBDuJsgLre9v04A7qWVqdMeiToRCuV5fWc/H5/IO/e+lETNmU=",
	}
	for i := 0; i < numTest; i++ {

		// Construct plaintext
		plaintext := []byte("hello user" + strconv.Itoa(i) + "!")
		label := []byte(strconv.Itoa(i + 1))

		// Encrypt data
		encrypted, err := pubKey.EncryptOAEP(hashFunc, prng, plaintext, label)
		if err != nil {
			t.Fatalf("EncryptOAEP error: %+v", err)
		}

		// Check that encrypted data is consistent
		received := base64.StdEncoding.EncodeToString(encrypted)
		if expectedOutput[i] != received {
			t.Errorf("EncryptOAEP did not produce consistent output with "+
				"precanned values."+
				"\nExpected: %s"+
				"\nReceived: %s", expectedOutput[i], received)
		}

	}

}

// Smoke test. Ensure that DecryptPKCS1v15 can decrypt the output from
// EncryptPKCS1v15. Also ensure decryption returns original input to
// EncryptPKCS1v15.
func TestEncryptDecryptPKCS1v15(t *testing.T) {
	sLocal := GetScheme()
	rng := rand.Reader

	// Construct keys
	privKey, err := sLocal.GenerateDefault(rng)
	if err != nil {
		t.Errorf("GenerateDefault: %v", err)
	}

	pubKey := privKey.Public()

	for i := 0; i < numTest; i++ {
		// Construct plaintext
		plaintext := []byte("hello user" + strconv.Itoa(i) + "!")

		// Encrypt data
		encrypted, err := pubKey.EncryptPKCS1v15(rng, plaintext)
		if err != nil {
			t.Fatalf("EncryptOAEP error: %+v", err)
		}

		// Decrypt data
		decrypted, err := privKey.DecryptPKCS1v15(rng, encrypted)
		if err != nil {
			t.Fatalf("DecryptOAEP error: %+v", err)
		}

		// Check that decrypted data matches the original plaintext.
		if !bytes.Equal(decrypted, plaintext) {
			t.Fatalf("Decrypted plaintext does not match original plaintext."+
				"\nExpected: %+v"+
				"\nReceived: %v", plaintext, decrypted)
		}
	}

}
