////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package broadcast

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"gitlab.com/xx_network/crypto/csprng"
	goUrl "net/url"
	"strconv"
	"strings"
	"testing"
)

// Tests that a URL created via Channel.InviteURL can be decoded using
// DecodeInviteURL and that it matches the original.
func TestChannel_InviteURL_DecodeInviteURL(t *testing.T) {
	host := "https://internet.speakeasy.tech/"
	rng := csprng.NewSystemRNG()

	for i, level := range []PrivacyLevel{Public, Private, Secret} {
		c, _, err := NewChannel("My_Channel",
			"Here is information about my channel.", level, 512, rng)
		require.NoError(t, err)

		url, err := c.InviteURL(host, i)
		require.NoError(t, err)

		newChannel, err := DecodeInviteURL(url)
		require.NoError(t, err)

		require.Equal(t, *c, *newChannel)
	}
}

func TestChannel_InviteURL(t *testing.T) {
	url := "http://backdev.speakeasy.tech/join?0Name=aaaa&1Description=aaaaa&2Level=Public&3Created=1673641306768948209&e=RKinl7gyIKBGAdRwq3ZLRajX33Vo0vv%2FW5Mt1GVbWgY%3D&k=iLGoDv%2BJdHy7RameVqOa2NJ1mDLXmEyv%2FpXoysHAqcI%3D&l=368&m=0&p=1&s=9vjszGm8UJ3UdTsTF56VLMfMJv1eDk2Epw6r097MBNQ%3D&v=1"
	ch, _ := DecodeInviteURL(url)

	t.Logf("name: %s", ch.Name)
	t.Logf("RsaPubKeyLength: %d", ch.RsaPubKeyLength)
	t.Logf("RSASubPayloads: %d", ch.RSASubPayloads)
}

// Error path: Tests that Channel.InviteURL returns an error for an invalid host.
func TestChannel_InviteURL_ParseError(t *testing.T) {
	rng := csprng.NewSystemRNG()
	c, _, err := NewChannel("ABC", "B", Public, 512, rng)
	if err != nil {
		t.Fatalf("Failed to create new channel: %+v", err)
	}

	host := "invalidHost\x7f"
	expectedErr := strings.Split(parseHostUrlErr, "%")[0]

	_, err = c.InviteURL(host, 0)
	require.ErrorContains(t, err, expectedErr)
}

// Error path: Tests that DecodeInviteURL returns an error for an invalid host.
func TestDecodeInviteURL_ParseError(t *testing.T) {
	host := "invalidHost\x7f"
	expectedErr := strings.Split(parseShareUrlErr, "%")[0]

	_, err := DecodeInviteURL(host)
	require.ErrorContains(t, err, expectedErr)
}

// Error path: Tests that DecodeInviteURL returns errors for a list of invalid
// URLs.
func TestDecodeInviteURL_DecodeError(t *testing.T) {
	type test struct {
		url, err string
	}

	tests := []test{
		{"test?", urlVersionErr},
		{"test?v=q", parseVersionErr},
		{"test?v=2", versionErr},
		{"test?v=1", noMaxUsesErr},
		{"test?v=1&m=t", parseMaxUsesErr},
		{"test?v=1&m=0", malformedUrlErr},
		{"test?v=1&s=AA==&m=0&3Created=0", parseLevelErr},
		{"test?v=1&s=A&2Level=Public&m=0&3Created=0", parseSaltErr},
		{"test?v=1&s=AA==&2Level=Public&k=A&m=0&3Created=0",
			parseRsaPubKeyHashErr},
		{"test?v=1&s=AA==&2Level=Public&k=AA==&l=q&m=0&3Created=0",
			parseRsaPubKeyLengthErr},
		{"test?v=1&s=AA==&2Level=Public&k=AA==&l=5&p=t&m=0&3Created=0",
			parseRsaSubPayloadsErr},
		{"test?v=1&s=AA==&2Level=Public&k=AA==&l=5&p=1&e=A&m=0&3Created=0",
			parseSecretErr},
		{"test?v=1&d=2&m=0", decodeEncryptedErr},
	}

	for _, tt := range tests {
		expected := strings.Split(tt.err, "%")[0]

		_, err := DecodeInviteURL(tt.url)
		require.ErrorContains(t, err, expected)
	}
}

// Error path: Tests that Channel.InviteURL returns the expected error when the
// max uses in the URL does not match the max uses in the secret data.
func TestChannel_DecodeInviteURL_MaxUsesMismatchError(t *testing.T) {
	host := "https://internet.speakeasy.tech/"
	rng := csprng.NewSystemRNG()
	c, _, err := NewChannel("ABC", "B", Secret, 512, rng)
	if err != nil {
		t.Fatalf("Failed to create new channel: %+v", err)
	}

	oldMaxUses := 5
	url, err := c.InviteURL(host, oldMaxUses)
	if err != nil {
		t.Fatalf("Failed to create URL: %+v", err)
	}

	// Change max uses in URL
	newMaxUses := 6
	url = strings.ReplaceAll(url,
		"&"+MaxUsesKey+"="+strconv.Itoa(oldMaxUses),
		"&"+MaxUsesKey+"="+strconv.Itoa(newMaxUses))

	expectedErr := fmt.Sprintf(maxUsesUrlErr, newMaxUses, oldMaxUses)
	_, err = DecodeInviteURL(url)
	require.ErrorContains(t, err, expectedErr)
}

// Tests that DecodeInviteURL returns an error when NewChannelID returns an error
// due to the salt size being incorrect.
func TestDecodeInviteURL_NewChannelIDError(t *testing.T) {
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

	_, err := DecodeInviteURL(url)
	require.ErrorContains(t, err, expectedErr)
}

// Tests that DecodeInviteURL returns an error when the name in the URL is too
// long.
func TestDecodeInviteURL_NameMaxLengthError(t *testing.T) {
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

	_, err := DecodeInviteURL(url)
	require.EqualError(t, errors.Unwrap(err), MaxNameCharLenErr.Error())
}

// Tests that DecodeInviteURL returns an error when the description in the URL is
// too long.
func TestDecodeInviteURL_DescriptionMaxLengthError(t *testing.T) {
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

	_, err := DecodeInviteURL(url)
	require.EqualError(t, errors.Unwrap(err), MaxDescriptionCharLenErr.Error())
}

// Tests that TestGetInviteUrlType returns the expected PrivacyLevel for every type
// of URL.
func TestGetInviteUrlType(t *testing.T) {
	host := "https://internet.speakeasy.tech/"
	rng := csprng.NewSystemRNG()

	for i, level := range []PrivacyLevel{Public, Private, Secret} {
		c, _, err := NewChannel("My_Channel",
			"Here is information about my channel.", level, 512, rng)
		require.NoError(t, err)

		url, err := c.InviteURL(host, i)
		require.NoError(t, err)

		pl, err := GetInviteUrlType(url)
		require.NoError(t, err)
		require.Equal(t, level, pl)
	}
}

// Error path: Tests that GetInviteUrlType returns an error for an invalid host.
func TestGetInviteUrlType_ParseError(t *testing.T) {
	host := "invalidHost\x7f"
	_, err := GetInviteUrlType(host)
	require.Error(t, err)
}

// Error path: Tests that GetInviteUrlType returns errors for a list of invalid
// URLs.
func TestGetInviteUrlType_Error(t *testing.T) {
	type test struct {
		url, err string
	}

	tests := []test{
		{"test?", urlVersionErr},
		{"test?v=" + strconv.Itoa(inviteVersion), malformedUrlErr},
		{"test?v=q", parseVersionErr},
		{"test?v=" + strconv.Itoa(inviteVersion+1), versionErr},
	}

	for _, tt := range tests {
		_, err := GetInviteUrlType(tt.url)
		expected := strings.Split(tt.err, "%")[0]
		require.ErrorContains(t, err, expected)
	}
}

// Tests that a channel can be encoded to a URL using
// Channel.encodePublicInviteURL and decoded to a new channel using
// Channel.decodePublicInviteURL and that it matches the original.
func TestChannel_encodePublicInviteURL_decodePublicInviteURL(t *testing.T) {
	rng := csprng.NewSystemRNG()
	c, _, err := NewChannel("Test_Channel", "Description", Public, 512, rng)
	require.NoError(t, err)
	urlValues := make(goUrl.Values)
	urlValues = c.encodePublicInviteURL(urlValues)

	var newChannel Channel
	err = newChannel.decodePublicInviteURL(urlValues)
	require.NoError(t, err)
	// Reception ID is set at the layer above
	newChannel.ReceptionID = c.ReceptionID

	require.Equal(t, *c, newChannel)
}

// Tests that a channel can be encoded to a URL using
// Channel.encodePrivateInviteURL and decoded to a new channel using
// Channel.decodePrivateInviteURL and that it matches the original.
func TestChannel_encodePrivateInviteURL_decodePrivateInviteURL(t *testing.T) {
	rng := csprng.NewSystemRNG()
	c, _, err := NewChannel("Test_Channel", "Description", Private, 512, rng)
	require.NoError(t, err)

	maxUses := 12
	urlValues := make(goUrl.Values)
	urlValues = c.encodePrivateInviteURL(urlValues, maxUses)

	var newChannel Channel
	loadedMaxUses, err := newChannel.decodePrivateInviteURL(urlValues)
	require.NoError(t, err)

	if maxUses != loadedMaxUses {
		t.Errorf("Did not get expected max uses.\nexpected: %d\nreceived: %d",
			maxUses, loadedMaxUses)
	}

	// Reception ID is set at the layer above
	newChannel.ReceptionID = c.ReceptionID
	require.Equal(t, *c, newChannel)
}

// Error path: Tests Channel.decodePrivateInviteURL returns the expected error
// when decoding the data fails.
func TestChannel_decodeInviteURL(t *testing.T) {
	urlValues := make(goUrl.Values)
	urlValues.Set(createdKey, "5")
	urlValues.Set(dataKey, "invalid data")

	var newChannel Channel
	expectedErr := strings.Split(decodeEncryptedErr, "%")[0]
	_, err := newChannel.decodePrivateInviteURL(urlValues)
	require.ErrorContains(t, err, expectedErr)
}

// Tests that a channel can be encoded to a URL using
// Channel.encodeSecretInviteURL and decoded to a new channel using
// Channel.decodeSecretInviteURL and that it matches the original.
func TestChannel_encodeSecretInviteURL_decodeSecretInviteURL(t *testing.T) {
	rng := csprng.NewSystemRNG()
	c, _, err := NewChannel("Test_Channel", "Description", Secret, 512, rng)
	require.NoError(t, err)

	maxUses := 2
	urlValues := make(goUrl.Values)
	urlValues = c.encodeSecretInviteURL(urlValues, maxUses)

	var newChannel Channel
	loadedMaxUses, err := newChannel.decodeSecretInviteURL(urlValues)
	require.NoError(t, err)

	require.Equal(t, maxUses, loadedMaxUses)

	// Reception ID is set at the layer above
	newChannel.ReceptionID = c.ReceptionID
	require.Equal(t, *c, newChannel)
}

// Tests that a channel marshalled with Channel.marshalPrivateInviteURLSecrets
// and unmarshalled with Channel.unmarshalPrivateInviteURLSecrets matches the
// original, except for the Name, Description, and ReceptionID, which are added
// in the layer above.
func TestChannel_marshalPrivateInviteUrlSecrets_unmarshalPrivateInviteUrlSecrets(
	t *testing.T) {
	rng := csprng.NewSystemRNG()
	c, _, err := NewChannel("Test_Channel", "Description", Private, 512, rng)
	require.NoError(t, err)

	maxUses := 5
	data := c.marshalPrivateInviteURLSecrets(maxUses)

	var newChannel Channel
	unmarshalledMaxUses, err := newChannel.unmarshalPrivateInviteURLSecrets(data)
	require.NoError(t, err)

	require.Equal(t, maxUses, unmarshalledMaxUses)

	// Name, description, creation, and reception ID are set at the layer above
	newChannel.Name = c.Name
	newChannel.Description = c.Description
	newChannel.Created = c.Created
	newChannel.ReceptionID = c.ReceptionID
	require.Equal(t, *c, newChannel)
}

// Tests that a channel marshalled with Channel.marshalSecretInviteURLSecrets and
// unmarshalled with Channel.unmarshalSecretInviteURLSecrets matches the
// original, except for the ReceptionID, which is added in the layer above.
func TestChannel_marshalSecretInviteUrlSecrets_unmarshalSecretInviteUrlSecrets(
	t *testing.T) {
	rng := csprng.NewSystemRNG()
	c, _, err := NewChannel("Test_Channel", "Description", Secret, 512, rng)
	require.NoError(t, err)

	maxUses := 5
	data := c.marshalSecretInviteURLSecrets(maxUses)

	var newChannel Channel
	unmarshalledMaxUses, err := newChannel.unmarshalSecretInviteURLSecrets(data)
	require.NoError(t, err)
	require.Equal(t, maxUses, unmarshalledMaxUses)

	// Reception ID is set at the layer above
	newChannel.ReceptionID = c.ReceptionID

	require.Equal(t, *c, newChannel)
}
