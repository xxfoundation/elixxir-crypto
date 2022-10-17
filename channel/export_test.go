////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package channel

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"gitlab.com/elixxir/crypto/backup"
	"gitlab.com/xx_network/crypto/csprng"
	"reflect"
	"strings"
	"testing"
)

// Tests that a message signed with a PrivateIdentity can be verified with the
// same identity once is has been exported and imported.
func TestPrivateIdentity_export_ImportPrivateIdentity_KeySign(t *testing.T) {
	rng := csprng.NewSystemRNG()
	pi, _ := GenerateIdentity(rng)

	message := make([]byte, 256)
	_, _ = rng.Read(message)
	signature := ed25519.Sign(*pi.Privkey, message)

	password := "hunter2"
	exported, err := pi.export(password, backup.DefaultParams(), rng)
	if err != nil {
		t.Errorf("Failed to export PrivateIdentity: %+v", err)
	}

	newPI, err := ImportPrivateIdentity(password, exported)
	if err != nil {
		t.Errorf("Failed to import PrivateIdentity: %+v", err)
	}

	if !ed25519.Verify(newPI.PubKey, message, signature) {
		t.Errorf("Failed to verify message signed by unmarshalled channel.")
	}
}

// Tests that a PrivateIdentity exported via ImportPrivateIdentity.export and
// imported used ImportPrivateIdentity matches the original.
func TestPrivateIdentity_export_ImportPrivateIdentity(t *testing.T) {
	rng := csprng.NewSystemRNG()
	pi, _ := GenerateIdentity(rng)

	password := "hunter2"
	exported, err := pi.export(password, backup.DefaultParams(), rng)
	if err != nil {
		t.Errorf("Failed to export PrivateIdentity: %+v", err)
	}

	newPI, err := ImportPrivateIdentity(password, exported)
	if err != nil {
		t.Errorf("Failed to import PrivateIdentity: %+v", err)
	}

	if !reflect.DeepEqual(pi, newPI) {
		t.Errorf("Decrypted PrivateIdentity does not match original."+
			"\nexpected: %+v\nreceived: %+v", pi, newPI)
	}
}

// Error path: Tests that ImportPrivateIdentity.export returns an error when
// encryption fails due to the RNG being empty.
func TestPrivateIdentity_export_EncryptError(t *testing.T) {
	rng := bytes.NewBuffer([]byte{})
	pi := PrivateIdentity{}
	expectedErr := strings.Split(encryptErr, "%")[0]

	_, err := pi.export("", backup.DefaultParams(), rng)
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("Unexpected error when RNG returns a read error."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Error path: Tests that various invalid exported identities return the
// expected errors.
func TestImportPrivateIdentity_MalformedImportsError(t *testing.T) {
	type test struct {
		data []byte
		err  string
	}

	tests := []test{
		{[]byte{}, noDataErr},
		{[]byte("<xxChannelIdentity(5)xx>"), fmt.Sprintf(noHeadFootTagsErr, noCloseTagErr)},
		{[]byte("<xxChannelIdentity)stuff xxChannelIdentity>"), fmt.Sprintf(noVersionTagErr, noOpenTagErr)},
		{[]byte("<xxChannelIdentity() stuff xxChannelIdentity>"), noVersionErr},
		{[]byte("<xxChannelIdentity(5)xxChannelIdentity>"), noEncryptedData},
		{[]byte("<xxChannelIdentity(5)AxxChannelIdentity>"), fmt.Sprintf(wrongVersionErr, currentExportedVersion, "5")},
	}

	for i, tt := range tests {
		_, err := ImportPrivateIdentity("", tt.data)
		if err == nil || !strings.Contains(err.Error(), tt.err) {
			t.Errorf("Failed to receive expected error for import #%d: %q"+
				"\nexpected: %s\nreceived: %+v", i, tt.data, tt.err, err)
		}
	}
}

// Tests that the encrypted data returned by PrivateIdentity.encrypt can be
// decrypted and assembled into a matching PrivateIdentity via
// decryptPrivateIdentity.
func TestPrivateIdentity_encrypt_decryptPrivateIdentity(t *testing.T) {
	password, params := "hunter2", testParams()
	rng := csprng.NewSystemRNG()
	pi, _ := GenerateIdentity(rng)

	encryptedData, salt, err := pi.encrypt(password, params, rng)
	if err != nil {
		t.Errorf("Failed to encrypt PrivateIdentity: %+v", err)
	}

	newPI, err := decryptPrivateIdentity(password, encryptedData, salt, params)
	if err != nil {
		t.Errorf("Failed to decrypt PrivateIdentity: %+v", err)
	}

	if !reflect.DeepEqual(pi, newPI) {
		t.Errorf("Decrypted PrivateIdentity does not match original."+
			"\nexpected: %+v\nreceived: %+v", pi, newPI)
	}
}

// Error path: Tests that PrivateIdentity.encrypt returns an error when the RNG
// returns an error when making the salt.
func TestPrivateIdentity_encrypt_MakeSaltError(t *testing.T) {
	password, params := "hunter2", testParams()
	rng := bytes.NewBuffer([]byte{})
	pi := PrivateIdentity{}
	expectedErr := strings.Split(readSaltErr, "%")[0]

	_, _, err := pi.encrypt(password, params, rng)
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("Unexpected error when RNG returns a read error."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Error path: Tests that decryptPrivateIdentity returns the expected error when
// the encrypted data cannot be decrypted due to an invalid password.
func Test_decryptPrivateIdentity_DecryptIdentityError(t *testing.T) {
	password, params := "hunter2", testParams()
	rng := csprng.NewSystemRNG()
	pi, _ := GenerateIdentity(rng)

	encryptedData, salt, err := pi.encrypt(password, params, rng)
	if err != nil {
		t.Errorf("Failed to encrypt PrivateIdentity: %+v", err)
	}

	expectedErr := strings.Split(decryptionErr, "%")[0]
	_, err = decryptPrivateIdentity("bad", encryptedData, salt, params)
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("Unexpected error when decryption should have failed."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Error path: Tests that decryptPrivateIdentity returns the expected error when
// the decrypted data cannot be decoded because it is not a PrivateIdentity.
func Test_decryptPrivateIdentity_DecodeIdentityError(t *testing.T) {
	password, params := "hunter2", testParams()
	rng := csprng.NewSystemRNG()

	// Generate encrypted data that is not a PrivateIdentity
	salt, _ := makeSalt(rng)
	key := deriveKey(password, salt, params)
	encryptedData := encryptIdentity([]byte("invalid data"), key, rng)

	expectedErr := strings.Split(decodeErr, "%")[0]
	_, err := decryptPrivateIdentity(password, encryptedData, salt, params)
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("Unexpected error when decoding should have failed."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Tests that a PrivateIdentity marshalled via PrivateIdentity.encode
// and unmarshalled via decodePrivateIdentity matches the original.
func TestPrivateIdentity_encode_decodePrivateIdentity(t *testing.T) {
	pi, _ := GenerateIdentity(csprng.NewSystemRNG())

	data := pi.encode()

	newPi, err := decodePrivateIdentity(data)
	if err != nil {
		t.Errorf("Failed to unmarshal encrypted data: %+v", err)
	}

	if !reflect.DeepEqual(pi, newPi) {
		t.Errorf("Unmarshalled PrivateIdentity does not match original."+
			"\nexpected: %+v\nreceived: %+v", pi, newPi)
	}
}

// Error path: Tests that decodePrivateIdentity returns the expected error when the
// data passed in is of the wrong length.
func Test_decodePrivateIdentity_DataLengthError(t *testing.T) {
	pi, _ := GenerateIdentity(csprng.NewSystemRNG())
	data := pi.encode()[5:]

	expectedErr := fmt.Sprintf(unmarshalDataLenErr, encodedLen, len(data))

	_, err := decodePrivateIdentity(data)
	if err == nil || err.Error() != expectedErr {
		t.Errorf("Did not receive expected error for data that is too short."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Error path: Tests that decodePrivateIdentity returns the expected error when the
// data has an incorrect version.
func Test_decodePrivateIdentity_IncorrectVersionError(t *testing.T) {
	pi, _ := GenerateIdentity(csprng.NewSystemRNG())

	data := pi.encode()
	data[0] = currentEncryptedVersion + 1

	expectedErr := fmt.Sprintf(
		versionMismatchErr, data[0], currentEncryptedVersion)

	_, err := decodePrivateIdentity(data)
	if err == nil || err.Error() != expectedErr {
		t.Errorf("Did not receive expected error with an incorrect version."+
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
