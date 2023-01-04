////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package broadcast

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"github.com/pkg/errors"
	"gitlab.com/xx_network/crypto/csprng"
	goUrl "net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// Tests that a URL created via Channel.ShareURL can be decoded using
// DecodeShareURL and that it matches the original.
func TestChannel_ShareURL_DecodeShareURL(t *testing.T) {
	host := "https://internet.speakeasy.tech/"
	rng := csprng.NewSystemRNG()

	for i, level := range []PrivacyLevel{Public, Private, Secret} {
		c, _, err := NewChannel("My_Channel",
			"Here is information about my channel.", level, 178, rng)
		if err != nil {
			t.Fatalf("Failed to create new %s channel: %+v", level, err)
		}

		url, password, err := c.ShareURL(host, i, rng)
		if err != nil {
			t.Fatalf("Failed to create %s URL: %+v", level, err)
		}

		newChannel, err := DecodeShareURL(url, password)
		if err != nil {
			t.Errorf("Failed to decode %s URL: %+v", level, err)
		}

		if !reflect.DeepEqual(*c, *newChannel) {
			t.Errorf("Decoded %s channel does not match original."+
				"\nexpected: %+v\nreceived: %+v", level, *c, *newChannel)
		}
	}
}

// Error path: Tests that Channel.ShareURL returns an error for an invalid host.
func TestChannel_ShareURL_ParseError(t *testing.T) {
	rng := csprng.NewSystemRNG()
	c, _, err := NewChannel("ABC", "B", Public, 178, rng)
	if err != nil {
		t.Fatalf("Failed to create new channel: %+v", err)
	}

	host := "invalidHost\x7f"
	expectedErr := strings.Split(parseHostUrlErr, "%")[0]

	_, _, err = c.ShareURL(host, 0, rng)
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("Did not receive expected error for URL %q."+
			"\nexpected: %s\nreceived: %+v", host, expectedErr, err)
	}
}

// Error path: Tests that Channel.ShareURL returns an error when generating a
// password fails due to an empty RNG.
func TestChannel_ShareURL_PasswordRngError(t *testing.T) {
	c, _, err := NewChannel("ABC", "B", Secret, 178, csprng.NewSystemRNG())
	if err != nil {
		t.Fatalf("Failed to create new channel: %+v", err)
	}

	expectedErr := strings.Split(generatePhrasePasswordErr, "%")[0]

	badRng := bytes.NewBuffer(nil)
	_, _, err = c.ShareURL("host", 0, badRng)
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("Did not receive expected error for bad RNG."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Error path: Tests that DecodeShareURL returns an error for an invalid host.
func TestDecodeShareURL_ParseError(t *testing.T) {
	host := "invalidHost\x7f"
	expectedErr := strings.Split(parseShareUrlErr, "%")[0]

	_, err := DecodeShareURL(host, "")
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("Did not receive expected error for URL %q."+
			"\nexpected: %s\nreceived: %+v", host, expectedErr, err)
	}
}

// Error path: Tests that DecodeShareURL returns errors for a list of invalid
// URLs.
func TestDecodeShareURL_DecodeError(t *testing.T) {
	type test struct {
		url, password, err string
	}

	tests := []test{
		{"test?", "", urlVersionErr},
		{"test?v=q", "", parseVersionErr},
		{"test?v=2", "", versionErr},
		{"test?v=1", "", noMaxUsesErr},
		{"test?v=1&m=t", "", parseMaxUsesErr},
		{"test?v=1&m=0", "", malformedUrlErr},
		{"test?v=1&s=AA==&m=0&3Created=0", "", parseLevelErr},
		{"test?v=1&0Name=2&m=0", "", noPasswordErr},
		{"test?v=1&d=2&m=0", "", noPasswordErr},
		{"test?v=1&s=A&2Level=Public&m=0&3Created=0", "", parseSaltErr},
		{"test?v=1&s=AA==&2Level=Public&k=A&m=0&3Created=0", "",
			parseRsaPubKeyHashErr},
		{"test?v=1&s=AA==&2Level=Public&k=AA==&l=q&m=0&3Created=0", "",
			parseRsaPubKeyLengthErr},
		{"test?v=1&s=AA==&2Level=Public&k=AA==&l=5&p=t&m=0&3Created=0", "",
			parseRsaSubPayloadsErr},
		{"test?v=1&s=AA==&2Level=Public&k=AA==&l=5&p=1&e=A&m=0&3Created=0", "",
			parseSecretErr},
		{"test?v=1&0Name=2&m=0&3Created=0", "hello", decryptErr},
		{"test?v=1&d=2&m=0", "hello", decodeEncryptedErr},
	}

	for i, tt := range tests {
		expected := strings.Split(tt.err, "%")[0]

		_, err := DecodeShareURL(tt.url, tt.password)
		if err == nil || !strings.Contains(err.Error(), expected) {
			t.Errorf("Did not receive expected error for URL %q (%d)."+
				"\nexpected: %s\nreceived: %+v", tt.url, i, expected, err)
		}
	}
}

// Error path: Tests that DecodeShareURL returns the expected error when the max
// uses in the URL does not match the max uses in the encrypted secret data.
func TestChannel_DecodeShareURL_MaxUsesMismatchError(t *testing.T) {
	host := "https://internet.speakeasy.tech/"
	rng := csprng.NewSystemRNG()
	c, _, err := NewChannel("ABC", "B", Secret, 178, rng)
	if err != nil {
		t.Fatalf("Failed to create new channel: %+v", err)
	}

	oldMaxUses := 5
	url, password, err := c.ShareURL(host, oldMaxUses, rng)
	if err != nil {
		t.Fatalf("Failed to create URL: %+v", err)
	}

	// Change max uses in URL
	newMaxUses := 6
	url = strings.ReplaceAll(url,
		"&"+MaxUsesKey+"="+strconv.Itoa(oldMaxUses),
		"&"+MaxUsesKey+"="+strconv.Itoa(newMaxUses))

	expectedErr := fmt.Sprintf(maxUsesUrlErr, newMaxUses, oldMaxUses)
	_, err = DecodeShareURL(url, password)
	if err == nil || err.Error() != expectedErr {
		t.Errorf("Did not receive expected error when max uses was changed."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Tests that DecodeShareURL returns an error when NewChannelID returns an error
// due to the salt size being incorrect.
func TestDecodeShareURL_NewChannelIDError(t *testing.T) {
	url := "https://internet.speakeasy.tech/" +
		"?0Name=MyChannel" +
		"&1Description=Here+is+information+about+my+channel." +
		"&2Level=Public" +
		"&3Created=0" +
		"&e=z73XYenRG65WHmJh8r%2BanZ71r2rPOHjTgCSEh05TUlQ%3D" +
		"&k=9b1UtGnZ%2B%2FM3hnXTfNRN%2BZKXcsHyZE00vZ9We0oDP90%3D" +
		"&l=493" +
		"&p=1" +
		"&s=8tJb%2FC9j26MJEfb%2F2463YQ%3D%3D" +
		"&v=1" +
		"&m=0"
	expectedErr := strings.Split(newReceptionIdErr, "%")[0]

	_, err := DecodeShareURL(url, "")
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("Did not receive expected error for URL %q."+
			"\nexpected: %s\nreceived: %+v", url, expectedErr, err)
	}
}

// Tests that DecodeShareURL returns an error when the name in the URL is too
// long.
func TestDecodeShareURL_NameMaxLengthError(t *testing.T) {
	url := "https://internet.speakeasy.tech/" +
		"?0Name=" + strings.Repeat("A", NameMaxChars+1) +
		"&1Description=Here+is+information+about+my+channel." +
		"&2Level=Public" +
		"&3Created=0" +
		"&e=GBBSbhYkAWj58b1befVCOQIUpnyv3nw2B97oe3Z0%2B6A%3D" +
		"&k=ktKmxghB12i9I3ava5bX4hqH82gVCFnbOccKicNIBwk%3D" +
		"&l=493" +
		"&m=0" +
		"&p=1" +
		"&s=95flF3q1rSlqQXbrksem9HHK%2BFeG2iHn7AEoGk%2BI230%3D" +
		"&v=1"

	_, err := DecodeShareURL(url, "")
	if errors.Unwrap(err) != MaxNameCharLenErr {
		t.Errorf("Did not receive expected error when the name in the URL is "+
			"too long.\nexpected: %s\nreceived: %+v", MaxNameCharLenErr, err)
	}
}

// Tests that DecodeShareURL returns an error when the description in the URL is
// too long.
func TestDecodeShareURL_DescriptionMaxLengthError(t *testing.T) {
	url := "https://internet.speakeasy.tech/" +
		"?0Name=Channel" +
		"&1Description=" + strings.Repeat("A", DescriptionMaxChars+1) +
		"&2Level=Public" +
		"&3Created=0" +
		"&e=GBBSbhYkAWj58b1befVCOQIUpnyv3nw2B97oe3Z0%2B6A%3D" +
		"&k=ktKmxghB12i9I3ava5bX4hqH82gVCFnbOccKicNIBwk%3D" +
		"&l=493" +
		"&m=0" +
		"&p=1" +
		"&s=95flF3q1rSlqQXbrksem9HHK%2BFeG2iHn7AEoGk%2BI230%3D" +
		"&v=1"

	_, err := DecodeShareURL(url, "")
	if errors.Unwrap(err) != MaxDescriptionCharLenErr {
		t.Errorf("Did not receive expected error when the description in the "+
			"URL is too long.\nexpected: %s\nreceived: %+v",
			MaxDescriptionCharLenErr, err)
	}
}

// Tests that GetShareUrlType returns the expected PrivacyLevel for every type
// of URL.
func TestGetShareUrlType(t *testing.T) {
	host := "https://internet.speakeasy.tech/"
	rng := csprng.NewSystemRNG()

	for i, level := range []PrivacyLevel{Public, Private, Secret} {
		c, _, err := NewChannel("My_Channel",
			"Here is information about my channel.", level, 178, rng)
		if err != nil {
			t.Fatalf("Failed to create new %s channel: %+v", level, err)
		}

		url, _, err := c.ShareURL(host, i, rng)
		if err != nil {
			t.Fatalf("Failed to create %s URL: %+v", level, err)
		}

		pl, err := GetShareUrlType(url)
		if err != nil {
			t.Errorf("Failed to get type of URL %q: %+v", url, err)
		}

		if level != pl {
			t.Errorf("Did not receive expected privacy Level."+
				"\nexpected: %s\nreceived: %s", level, pl)
		}
	}
}

// Error path: Tests that GetShareUrlType returns an error for an invalid host.
func TestGetShareUrlType_ParseError(t *testing.T) {
	host := "invalidHost\x7f"
	c, err := GetShareUrlType(host)
	if err == nil {
		t.Errorf("Expected error for invalid host URL: %+v", c)
	}
}

// Error path: Tests that GetShareUrlType returns errors for a list of invalid
// URLs.
func TestGetShareUrlType_Error(t *testing.T) {
	type test struct {
		url, password, err string
	}

	tests := []test{
		{"test?", "", urlVersionErr},
		{"test?v=" + strconv.Itoa(shareUrlVersion), "", malformedUrlErr},
		{"test?v=q", "", parseVersionErr},
		{"test?v=" + strconv.Itoa(shareUrlVersion+1), "", versionErr},
	}

	for i, tt := range tests {
		_, err := GetShareUrlType(tt.url)
		expected := strings.Split(tt.err, "%")[0]
		if err == nil || !strings.Contains(err.Error(), expected) {
			t.Errorf("Did not receive expected error for URL %q (%d)."+
				"\nexpected: %s\nreceived: %+v", tt.url, i, tt.err, err)
		}
	}
}

// Tests that a channel can be encoded to a URL using
// Channel.encodePublicShareURL and decoded to a new channel using
// Channel.decodePublicShareURL and that it matches the original.
func TestChannel_encodePublicShareURL_decodePublicShareURL(t *testing.T) {
	rng := csprng.NewSystemRNG()
	c, _, err := NewChannel("Test_Channel", "Description", Public, 178, rng)
	if err != nil {
		t.Fatalf("Failed to create new channel: %+v", err)
	}

	urlValues := make(goUrl.Values)
	urlValues = c.encodePublicShareURL(urlValues)

	var newChannel Channel
	err = newChannel.decodePublicShareURL(urlValues)
	if err != nil {
		t.Errorf("Error decoding URL values: %+v", err)
	}

	// Reception ID is set at the layer above
	newChannel.ReceptionID = c.ReceptionID

	if !reflect.DeepEqual(*c, newChannel) {
		t.Errorf("Decoded channel does not match original."+
			"\nexpected: %+v\nreceived: %+v", *c, newChannel)
	}
}

// Tests that a channel can be encoded to a URL using
// Channel.encodePrivateShareURL and decoded to a new channel using
// Channel.decodePrivateShareURL and that it matches the original.
func TestChannel_encodePrivateShareURL_decodePrivateShareURL(t *testing.T) {
	rng := csprng.NewSystemRNG()
	c, _, err := NewChannel("Test_Channel", "Description", Private, 178, rng)
	if err != nil {
		t.Fatalf("Failed to create new channel: %+v", err)
	}

	const password = "password"
	maxUses := 12
	urlValues := make(goUrl.Values)
	urlValues = c.encodePrivateShareURL(urlValues, password, maxUses, rng)

	var newChannel Channel
	loadedMaxUses, err := newChannel.decodePrivateShareURL(urlValues, password)
	if err != nil {
		t.Errorf("Error decoding URL values: %+v", err)
	}

	if maxUses != loadedMaxUses {
		t.Errorf("Did not get expected max uses.\nexpected: %d\nreceived: %d",
			maxUses, loadedMaxUses)
	}

	// Reception ID is set at the layer above
	newChannel.ReceptionID = c.ReceptionID

	if !reflect.DeepEqual(*c, newChannel) {
		t.Errorf("Decoded channel does not match original."+
			"\nexpected: %+v\nreceived: %+v", *c, newChannel)
	}
}

// Error path: Tests Channel.decodePrivateShareURL returns the expected error
// when decoding the data fails.
func TestChannel_decodePrivateShareURL(t *testing.T) {
	urlValues := make(goUrl.Values)
	urlValues.Set(createdKey, "5")
	urlValues.Set(dataKey, "invalid data")

	var newChannel Channel
	expectedErr := strings.Split(decodeEncryptedErr, "%")[0]
	_, err := newChannel.decodePrivateShareURL(urlValues, "")
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("Did not receive expected error when the data is invalid."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Tests that a channel can be encoded to a URL using
// Channel.encodeSecretShareURL and decoded to a new channel using
// Channel.decodeSecretShareURL and that it matches the original.
func TestChannel_encodeSecretShareURL_decodeSecretShareURL(t *testing.T) {
	rng := csprng.NewSystemRNG()
	c, _, err := NewChannel("Test_Channel", "Description", Secret, 178, rng)
	if err != nil {
		t.Fatalf("Failed to create new channel: %+v", err)
	}

	const password = "password"
	maxUses := 2
	urlValues := make(goUrl.Values)
	urlValues = c.encodeSecretShareURL(urlValues, password, maxUses, rng)

	var newChannel Channel
	loadedMaxUses, err := newChannel.decodeSecretShareURL(urlValues, password)
	if err != nil {
		t.Errorf("Error decoding URL values: %+v", err)
	}

	if maxUses != loadedMaxUses {
		t.Errorf("Did not get expected max uses.\nexpected: %d\nreceived: %d",
			maxUses, loadedMaxUses)
	}

	// Reception ID is set at the layer above
	newChannel.ReceptionID = c.ReceptionID

	if !reflect.DeepEqual(*c, newChannel) {
		t.Errorf("Decoded channel does not match original."+
			"\nexpected: %+v\nreceived: %+v", *c, newChannel)
	}
}

// Tests that a channel marshalled with Channel.marshalPrivateShareUrlSecrets
// and unmarshalled with Channel.unmarshalPrivateShareUrlSecrets matches the
// original, except for the Name, Description, and ReceptionID, which are added
// in the layer above.
func TestChannel_marshalPrivateShareUrlSecrets_unmarshalPrivateShareUrlSecrets(
	t *testing.T) {
	rng := csprng.NewSystemRNG()
	c, _, err := NewChannel("Test_Channel", "Description", Private, 178, rng)
	if err != nil {
		t.Fatalf("Failed to create new channel: %+v", err)
	}

	maxUses := 5
	data := c.marshalPrivateShareUrlSecrets(maxUses)

	var newChannel Channel
	unmarshalledMaxUses, err := newChannel.unmarshalPrivateShareUrlSecrets(data)
	if err != nil {
		t.Fatalf("Failed to unmarshal private channel data: %+v", err)
	}

	if maxUses != unmarshalledMaxUses {
		t.Errorf("Unmarshalled max uses does not match expected."+
			"\nexpected: %d\nreceived: %d", maxUses, unmarshalledMaxUses)
	}

	// Name, description, creation, and reception ID are set at the layer above
	newChannel.Name = c.Name
	newChannel.Description = c.Description
	newChannel.Created = c.Created
	newChannel.ReceptionID = c.ReceptionID

	if !reflect.DeepEqual(*c, newChannel) {
		t.Errorf("Unmarshalled channel does not match original."+
			"\nexpected: %+v\nreceived: %+v", *c, newChannel)
	}
}

// Tests that a channel marshalled with Channel.marshalSecretShareUrlSecrets and
// unmarshalled with Channel.unmarshalSecretShareUrlSecrets matches the
// original, except for the ReceptionID, which is added in the layer above.
func TestChannel_marshalSecretShareUrlSecrets_unmarshalSecretShareUrlSecrets(
	t *testing.T) {
	rng := csprng.NewSystemRNG()
	c, _, err := NewChannel("Test_Channel", "Description", Secret, 178, rng)
	if err != nil {
		t.Fatalf("Failed to create new channel: %+v", err)
	}

	maxUses := 5
	data := c.marshalSecretShareUrlSecrets(maxUses)

	var newChannel Channel
	unmarshalledMaxUses, err := newChannel.unmarshalSecretShareUrlSecrets(data)
	if err != nil {
		t.Fatalf("Failed to unmarshal secret channel data: %+v", err)
	}

	if maxUses != unmarshalledMaxUses {
		t.Errorf("Unmarshalled max uses does not match expected."+
			"\nexpected: %d\nreceived: %d", maxUses, unmarshalledMaxUses)
	}

	// Reception ID is set at the layer above
	newChannel.ReceptionID = c.ReceptionID

	if !reflect.DeepEqual(*c, newChannel) {
		t.Errorf("Unmarshalled channel does not match original."+
			"\nexpected: %+v\nreceived: %+v", *c, newChannel)
	}
}

// Smoke test of encryptShareURL and decryptShareURL.
func Test_encryptShareURL_decryptShareURL(t *testing.T) {
	plaintext := []byte("Hello, World!")
	password := "test_password"
	ciphertext := encryptShareURL(plaintext, password, rand.Reader)
	decrypted, err := decryptShareURL(ciphertext, password)
	if err != nil {
		t.Errorf("%+v", err)
	}

	for i := range plaintext {
		if plaintext[i] != decrypted[i] {
			t.Errorf("%b != %b", plaintext[i], decrypted[i])
		}
	}
}

// Tests that decryptShareURL does not panic when given too little data.
func Test_decryptShareURL_ShortData(t *testing.T) {
	// Anything under 24 should cause an error.
	ciphertext := []byte{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	_, err := decryptShareURL(ciphertext, "dummyPassword")
	if err == nil {
		t.Errorf("Expected error on short decryption")
	}

	expectedErrMsg := "Read 24 bytes, too short to decrypt"
	if err == nil || err.Error()[:len(expectedErrMsg)] != expectedErrMsg {
		t.Errorf("Unexpected error: %+v", err)
	}

	// Empty string shouldn't panic should cause an error.
	ciphertext = []byte{}
	_, err = decryptShareURL(ciphertext, "dummyPassword")
	if err == nil {
		t.Errorf("Expected error on short decryption")
	}

	expectedErrMsg = "Read 0 bytes, too short to decrypt"
	if err == nil || err.Error()[:len(expectedErrMsg)] != expectedErrMsg {
		t.Errorf("Unexpected error: %+v", err)
	}
}
