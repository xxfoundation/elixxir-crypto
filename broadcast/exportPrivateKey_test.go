////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package broadcast

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"gitlab.com/elixxir/crypto/backup"
	"gitlab.com/xx_network/crypto/csprng"
	"reflect"
	"strings"
	"testing"
)

// Tests that a message signed with the private key can be verified with the
// same key once is has been exported and imported.
func Test_portablePrivKey_export_ImportPrivateKey_KeySign(t *testing.T) {
	rng := csprng.NewSystemRNG()
	ppk := newPPK(256, rng, t)

	hashFunc := crypto.SHA256
	h := hashFunc.New()
	h.Write([]byte("message"))
	hashed := h.Sum(nil)

	// Construct signature
	signed, err := ppk.privKey.SignPKCS1v15(rng, hashFunc, hashed)
	if err != nil {
		t.Errorf("Failed to sign: %+v", err)
	}

	password := "hunter2"
	exported, err := ExportPrivateKey(ppk.channelID, ppk.privKey, password, rng)
	if err != nil {
		t.Errorf("Failed to export portablePrivKey: %+v", err)
	}

	_, privKey, err := ImportPrivateKey(password, exported)
	if err != nil {
		t.Errorf("Failed to import portablePrivKey: %+v", err)
	}

	// Verify signature
	err = privKey.Public().VerifyPKCS1v15(hashFunc, hashed, signed)
	if err != nil {
		t.Fatalf("VerifyPKCS1v15 error: %+v", err)
	}
}

// Tests that a portablePrivKey exported with custom Argon2 parameters via
// ExportPrivateKeyCustomParams and can be imported using ImportPrivateKey.
func Test_ExportPrivateKeyCustomParams_ImportPrivateKey(t *testing.T) {
	rng := csprng.NewSystemRNG()
	ppk := newPPK(18, rng, t)

	password := "hunter2"
	exported, err := ExportPrivateKeyCustomParams(ppk.channelID, ppk.privKey,
		password, backup.Params{Time: 1, Memory: 2, Threads: 3}, rng)
	if err != nil {
		t.Errorf("Failed to export portablePrivKey: %+v", err)
	}

	channelID, privKey, err := ImportPrivateKey(password, exported)
	if err != nil {
		t.Errorf("Failed to import portablePrivKey: %+v", err)
	}

	if !channelID.Cmp(ppk.channelID) {
		t.Errorf("Incorrect channel ID.\nexpected: %s\nreceived: %s",
			ppk.channelID, channelID)
	}

	if !privKey.GetGoRSA().Equal(ppk.privKey.GetGoRSA()) {
		t.Errorf("Incorrect RSA private key.\nexpected: %s\nreceived: %s",
			ppk.privKey, privKey)
	}
}

// Tests that a portablePrivKey exported via portablePrivKey.export and imported
// using ImportPrivateKey matches the original.
func Test_portablePrivKey_export_ImportPrivateKey(t *testing.T) {
	rng := csprng.NewSystemRNG()
	ppk := newPPK(18, rng, t)

	password := "hunter2"
	exported, err := ppk.export(password, testParams(), rng)
	if err != nil {
		t.Errorf("Failed to export portablePrivKey: %+v", err)
	}

	channelID, privKey, err := ImportPrivateKey(password, exported)
	if err != nil {
		t.Errorf("Failed to import portablePrivKey: %+v", err)
	}

	if !channelID.Cmp(ppk.channelID) {
		t.Errorf("Incorrect channel ID.\nexpected: %s\nreceived: %s",
			ppk.channelID, channelID)
	}

	if !privKey.GetGoRSA().Equal(ppk.privKey.GetGoRSA()) {
		t.Errorf("Incorrect RSA private key.\nexpected: %s\nreceived: %s",
			ppk.privKey, privKey)
	}
}

// Error path: Tests that portablePrivKey.export returns an error when
// encryption fails due to the RNG being empty.
func Test_portablePrivKey_export_EncryptError(t *testing.T) {
	rng := bytes.NewBuffer([]byte{})
	ppk := newPPK(18, csprng.NewSystemRNG(), t)
	expectedErr := strings.Split(encryptErr, "%")[0]

	_, err := ppk.export("", backup.DefaultParams(), rng)
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("Unexpected error when RNG returns a read error."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Error path: Tests that various invalid exported strings return the expected
// errors.
func TestImportPrivateKey_MalformedImportsError(t *testing.T) {
	type test struct {
		data []byte
		err  string
	}

	tests := []test{
		{[]byte{}, noDataErr},
		{[]byte(headTag + openVerTag + "5" + closeVerTag + "xx>"),
			fmt.Sprintf(noHeadFootTagsErr, noCloseTagErr)},
		{[]byte(headTag + ")stuff " + footTag),
			fmt.Sprintf(noVersionTagErr, noOpenTagErr)},
		{[]byte(headTag + openVerTag + closeVerTag + " stuff " + footTag), noVersionErr},
		{[]byte(headTag + openVerTag + "5" + closeVerTag + footTag), noEncryptedData},
		{[]byte(headTag + openVerTag + "5" + closeVerTag + "A" + footTag),
			fmt.Sprintf(wrongVersionErr, currentExportedVer, "5")},
	}

	for i, tt := range tests {
		_, _, err := ImportPrivateKey("", tt.data)
		if err == nil || !strings.Contains(err.Error(), tt.err) {
			t.Errorf("Failed to receive expected error for import #%d: %q"+
				"\nexpected: %s\nreceived: %+v", i, tt.data, tt.err, err)
		}
	}
}

// Tests that the encrypted data returned by portablePrivKey.encrypt can be
// decrypted and assembled into a matching portablePrivKey via
// portablePrivKey.decrypt.
func Test_portablePrivKey_encrypt_decrypt(t *testing.T) {
	password, params := "hunter2", testParams()
	rng := csprng.NewSystemRNG()
	ppk := newPPK(18, rng, t)

	encryptedData, salt, err := ppk.encrypt(password, params, rng)
	if err != nil {
		t.Errorf("Failed to encrypt portablePrivKey: %+v", err)
	}

	var ppk2 portablePrivKey
	err = ppk2.decrypt(password, encryptedData, salt, params)
	if err != nil {
		t.Errorf("Failed to decrypt portablePrivKey: %+v", err)
	}

	if !reflect.DeepEqual(*ppk, ppk2) {
		t.Errorf("Decrypted portablePrivKey does not match original."+
			"\nexpected: %+v\nreceived: %+v", *ppk, ppk2)
	}
}

// Error path: Tests that portablePrivKey.encrypt returns an error when the RNG
// returns an error when making the salt.
func Test_portablePrivKey_encrypt_MakeSaltError(t *testing.T) {
	password, params := "hunter2", testParams()
	rng := bytes.NewBuffer([]byte{})
	ppk := portablePrivKey{}
	expectedErr := strings.Split(readSaltErr, "%")[0]

	_, _, err := ppk.encrypt(password, params, rng)
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("Unexpected error when RNG returns a read error."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Error path: Tests that portablePrivKey.decrypt returns the expected error
// when the encrypted data cannot be decrypted due to an invalid password.
func Test_portablePrivKey_decrypt_DecryptError(t *testing.T) {
	password, params := "hunter2", testParams()
	rng := csprng.NewSystemRNG()
	ppk := newPPK(18, rng, t)

	encryptedData, salt, err := ppk.encrypt(password, params, rng)
	if err != nil {
		t.Errorf("Failed to encrypt portablePrivKey: %+v", err)
	}

	expectedErr := strings.Split(decryptionErr, "%")[0]
	err = ppk.decrypt("bad", encryptedData, salt, params)
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("Unexpected error when decryption should have failed."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Error path: Tests that portablePrivKey.decrypt returns the expected error
// when the decrypted data cannot be decoded because it is not a
// portablePrivKey.
func Test_portablePrivKey_decrypt_DecodeError(t *testing.T) {
	password, params := "hunter2", testParams()
	rng := csprng.NewSystemRNG()
	ppk := newPPK(18, rng, t)

	// Generate encrypted data that is not a portablePrivKey
	salt, _ := makeSalt(rng)
	key := deriveKey(password, salt, params)
	encryptedData := encryptPrivateKey([]byte("invalid data"), key, rng)

	expectedErr := strings.Split(decodeErr, "%")[0]
	err := ppk.decrypt(password, encryptedData, salt, params)
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("Unexpected error when decoding should have failed."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Tests that a portablePrivKey marshalled via portablePrivKey.encode and
// unmarshalled via portablePrivKey.decode matches the original.
func Test_portablePrivKey_encode_decode(t *testing.T) {
	ppk := newPPK(18, csprng.NewSystemRNG(), t)
	data := ppk.encode()

	newPpk := &portablePrivKey{}
	if err := newPpk.decode(data); err != nil {
		t.Errorf("Failed to unmarshal data: %+v", err)
	}

	if !reflect.DeepEqual(ppk, newPpk) {
		t.Errorf("Unmarshalled portablePrivKey does not match original."+
			"\nexpected: %+v\nreceived: %+v", ppk, newPpk)
	}
}

// Error path: Tests that portablePrivKey.decode returns the expected error when
// the data passed in is of the wrong length.
func Test_portablePrivKey_decode_DataLengthError(t *testing.T) {
	ppk := newPPK(18, csprng.NewSystemRNG(), t)
	data := ppk.encode()[:25]

	expectedErr := fmt.Sprintf(unmarshalDataLenErr, encodedLenMin, len(data))
	err := ppk.decode(data)
	if err == nil || err.Error() != expectedErr {
		t.Errorf("Did not receive expected error for data that is too short."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Error path: Tests that portablePrivKey.decode returns the expected error when
// the data has an incorrect version.
func Test_portablePrivKey_decode_IncorrectVersionError(t *testing.T) {
	ppk := newPPK(18, csprng.NewSystemRNG(), t)

	data := ppk.encode()
	data[0] = currentEncryptedVer + 1

	expectedErr := fmt.Sprintf(versionMismatchErr, data[0], currentEncryptedVer)
	err := ppk.decode(data)
	if err == nil || err.Error() != expectedErr {
		t.Errorf("Did not receive expected error with an incorrect version."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Error path: Tests that portablePrivKey.decode returns the expected error when
// there is an invalid RSA key PEM.
func Test_portablePrivKey_decode_InvalidRsaKeyPEM(t *testing.T) {
	ppk := newPPK(18, csprng.NewSystemRNG(), t)
	data := ppk.encode()[:encodedLenMin+6]

	expectedErr := strings.Split(decodePemErr, "%")[0]
	err := ppk.decode(data)
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("Did not receive expected error with an invalid key PEM."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Happy path.
func Test_getTagContents(t *testing.T) {
	testData := map[string]string{
		"test1": "ABC123" + headTag + "test1" + footTag + "DEF456",
		"test2": "Hello, world!" + headTag + "test2" + footTag +
			"Lorem ipsum" + headTag + "test2" + footTag + "-/-*",
	}

	for expected, str := range testData {
		received, err := getTagContents([]byte(str), headTag, footTag)
		if err != nil {
			t.Errorf("Failed to get tag contents from string %s", str)
		}

		if expected != string(received) {
			t.Errorf("Failed to get the expected contents."+
				"\nexpected: %s\nreceived: %s", expected, received)
		}
	}
}

// Tests that getTagContents returns the expected error for a set of strings
// with invalid tag placement.
func Test_getTagContents_MissingTagsError(t *testing.T) {
	testData := map[string]string{
		"ABC123" + headTag + "test1" + "ABC123":           noCloseTagErr,
		"ABC123" + footTag + "test2" + headTag + "ABC123": swappedTagErr,
		"ABC123" + footTag + "ABC123" + footTag + "test3": noOpenTagErr,
	}

	for str, expected := range testData {
		_, err := getTagContents([]byte(str), headTag, footTag)
		if err == nil || err.Error() != expected {
			t.Errorf("Did not get expected error for invalid tag placement."+
				"\nexpected: %s\nexpected: %+v", expected, str)
		}
	}
}

// newPPK generates a new portablePrivKey for testing.
func newPPK(keySize int, rng csprng.Source, t *testing.T) *portablePrivKey {
	channel, privKey, err := NewChannel("name", "d", Public, keySize, rng)
	if err != nil {
		t.Fatalf("Failed to make new channel: %+v", err)
	}

	return &portablePrivKey{
		channelID: channel.ReceptionID,
		privKey:   privKey,
	}
}

////////////////////////////////////////////////////////////////////////////////
// Cryptography                                                               //
////////////////////////////////////////////////////////////////////////////////

// Smoke test of encryptPrivateKey and decryptPrivateKey.
func Test_encryptPrivateKey_decryptPrivateKey(t *testing.T) {
	plaintext := []byte("Hello, World!")
	password := []byte("test_password")
	ciphertext := encryptPrivateKey(plaintext, password, rand.Reader)
	decrypted, err := decryptPrivateKey(ciphertext, password)
	if err != nil {
		t.Errorf("%+v", err)
	}

	for i := range plaintext {
		if plaintext[i] != decrypted[i] {
			t.Errorf("%b != %b", plaintext[i], decrypted[i])
		}
	}
}

// Tests that decryptPrivateKey does not panic when given too little data.
func Test_decryptPrivateKey_ShortDataError(t *testing.T) {
	// Anything under 24 should cause an error.
	ciphertext := []byte{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	_, err := decryptPrivateKey(ciphertext, []byte("dummyPassword"))
	expectedErr := fmt.Sprintf(readNonceLenErr, 24)
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("Unexpected error on short decryption."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}

	// Empty string shouldn't panic should cause an error.
	ciphertext = []byte{}
	_, err = decryptPrivateKey(ciphertext, []byte("dummyPassword"))
	expectedErr = fmt.Sprintf(readNonceLenErr, 0)
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("Unexpected error on short decryption."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Tests that decryptPrivateKey returns an error when an invalid password is used.
func Test_decryptPrivateKey_InvalidPasswordError(t *testing.T) {
	plaintext := []byte("Hello, World!")
	password := []byte("test_password")
	ciphertext := encryptPrivateKey(plaintext, password, rand.Reader)

	expectedErr := strings.Split(decryptWithPasswordErr, "%")[0]

	_, err := decryptPrivateKey(ciphertext, []byte("invalid password"))
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("Unexpected error for invalid password."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Tests that deriveKey returns a key of the correct length and that it is the
// same for the same set of password and salt. Also checks that keys with the
// same salt or passwords do not collide.
func Test_deriveKey(t *testing.T) {
	p := testParams()
	salts := make([][]byte, 6)
	passwords := make([]string, len(salts))
	keys := make(map[string]bool, len(salts)*len(passwords))

	for i := range salts {
		prng := csprng.NewSystemRNG()
		salt, _ := makeSalt(prng)
		salts[i] = salt

		password := make([]byte, 16)
		_, _ = prng.Read(password)
		passwords[i] = base64.StdEncoding.EncodeToString(password)[:16]
	}

	for _, salt := range salts {
		for _, password := range passwords {
			key := deriveKey(password, salt, p)

			// Check that the length of the key is correct
			if len(key) != keyLen {
				t.Errorf("Incorrect key length.\nexpected: %d\nreceived: %d",
					keyLen, len(key))
			}

			// Check that the same key is generated when the same password and
			// salt are used
			key2 := deriveKey(password, salt, p)

			if !bytes.Equal(key, key2) {
				t.Errorf("Keys with same password and salt do not match."+
					"\nexpected: %v\nreceived: %v", key, key2)
			}

			if keys[string(key)] {
				t.Errorf("Key already exists.")
			}
			keys[string(key)] = true
		}
	}
}

// Tests that multiple calls to makeSalt results in unique salts of the
// specified length.
func Test_makeSalt(t *testing.T) {
	salts := make(map[string]bool, 50)
	for i := 0; i < 50; i++ {
		salt, err := makeSalt(csprng.NewSystemRNG())
		if err != nil {
			t.Errorf("MakeSalt returned an error: %+v", err)
		}

		if len(salt) != privKeyPasswordSaltLen {
			t.Errorf("Incorrect salt length.\nexpected: %d\nreceived: %d",
				privKeyPasswordSaltLen, len(salt))
		}

		if salts[string(salt)] {
			t.Errorf("Salt already exists (%d).", i)
		}
		salts[string(salt)] = true
	}
}

// Tests that makeSalt returns an error when the RNG returns an error when read.
func Test_makeSalt_ReadError(t *testing.T) {
	b := bytes.NewBuffer([]byte{})

	expectedErr := strings.Split(readSaltErr, "%")[0]
	_, err := makeSalt(b)
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("Unexpected error when RNG returns a read error."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Tests that makeSalt returns an error when the RNG does not return enough
// bytes.
func Test_makeSalt_ReadNumBytesError(t *testing.T) {
	b := bytes.NewBuffer(make([]byte, privKeyPasswordSaltLen/2))

	expectedErr := fmt.Sprintf(
		saltNumBytesErr, privKeyPasswordSaltLen, privKeyPasswordSaltLen/2)
	_, err := makeSalt(b)
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("Unexpected error when RNG does not return enough bytes."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// testParams returns params used in testing that are quick.
func testParams() backup.Params {
	return backup.Params{
		Time:    1,
		Memory:  1,
		Threads: 1,
	}
}
