////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package broadcast

import (
	"bytes"
	"github.com/pkg/errors"
	"gitlab.com/elixxir/crypto/cmix"
	"gitlab.com/elixxir/crypto/rsa"
	"gitlab.com/xx_network/crypto/csprng"
	oldRsa "gitlab.com/xx_network/crypto/signature/rsa"
	"gitlab.com/xx_network/primitives/id"
	"gitlab.com/xx_network/primitives/netTime"
	"reflect"
	"strings"
	"testing"
)

func TestChannel_PrettyPrint(t *testing.T) {
	rng := csprng.NewSystemRNG()

	name := "Test_Channel"
	desc := "Channel description." + string(ppDelim)

	channel1, _, err := NewChannel(name, desc, Public, 1000, rng)
	if err != nil {
		t.Fatalf(err.Error())
	}

	pretty1 := channel1.PrettyPrint()

	channel2, err := NewChannelFromPrettyPrint(pretty1)
	if err != nil {
		t.Fatalf("%+v", err)
	}

	pretty2 := channel2.PrettyPrint()

	if pretty1 != pretty2 {
		t.Fatalf("Mismatch in serializations."+
			"\nExpected: %s"+
			"\nReceived: %s", pretty1, pretty2)
	}

	// Verify the new channel made from the pretty print is
	if !channel2.Verify() {
		t.Errorf("the channel failed to verify")
	}
}

func TestChannel_MarshalJson(t *testing.T) {
	// Construct a channel
	rng := csprng.NewSystemRNG()
	pk, err := rsa.GetScheme().Generate(rng, 4096)
	if err != nil {
		t.Fatalf("Failed to generate private key: %+v", err)
	}
	name := "Asymmetric channel"
	desc := "Asymmetric channel description"
	salt := cmix.NewSalt(rng, 512)
	secret := make([]byte, 32)
	_, err = rng.Read(secret)
	if err != nil {
		t.Fatal(err)
	}

	pubKeyPem := oldRsa.CreatePublicKeyPem(pk.Public().GetOldRSA())
	rid, err := NewChannelID(
		name, desc, Public, netTime.Now(), secret, salt, HashSecret(pubKeyPem))
	channel := Channel{
		ReceptionID:   rid,
		Name:          name,
		Description:   desc,
		Salt:          salt,
		RsaPubKeyHash: HashSecret(pubKeyPem),
	}

	// Marshal data
	data, err := channel.MarshalJson()
	if err != nil {
		t.Fatalf("Failed to marshal channel: %+v", err)
	}

	// Unmarshal
	newChannel := &Channel{}
	err = newChannel.UnmarshalJson(data)
	if err != nil {
		t.Fatalf("UnmarshalJSON error: %+v", err)
	}

	if !bytes.Equal(newChannel.RsaPubKeyHash, channel.RsaPubKeyHash) {
		t.Fatalf("Channel's RSA public key hash did not get unmarshaled properly."+
			"\nExpected: %+v"+
			"\nReceived: %+v", channel.RsaPubKeyHash, newChannel.RsaPubKeyHash)
	}

	if !bytes.Equal(newChannel.key, channel.key) {
		t.Fatalf("Channel's key did not get unmarshalled properly."+
			"\nExpected: %+v"+
			"\nReceived: %+v", channel.key, newChannel.key)
	}

	if !bytes.Equal(newChannel.Salt, channel.Salt) {
		t.Fatalf("Channel's salt did not get unmarshalled properly."+
			"\nExpected: %+v"+
			"\nReceived: %+v", channel.Salt, newChannel.Salt)
	}

	if newChannel.Name != channel.Name {
		t.Fatalf("Channel's name did not get unmarshalled properly."+
			"\nExpected: %+v"+
			"\nReceived: %+v", channel.Name, newChannel.Name)
	}

	if newChannel.Description != channel.Description {
		t.Fatalf("Channel's Description did not get unmarshalled properly."+
			"\nExpected: %+v"+
			"\nReceived: %+v", channel.Description, newChannel.Description)
	}

}

func TestRChanel_Marshal_Unmarshal(t *testing.T) {
	rng := csprng.NewSystemRNG()
	packetSize := 1000
	keySize, _ := calculateKeySize(packetSize, packetSize)
	keySize = keySize * 8

	s := rsa.GetScheme()
	pk, err := s.Generate(rng, keySize)
	if err != nil {
		t.Fatalf("Failed to generate private key: %+v", err)
	}
	name := "Asymmetric channel"
	desc := "Asymmetric channel description"
	salt := cmix.NewSalt(rng, 512)
	secret := make([]byte, 32)
	_, err = rng.Read(secret)
	if err != nil {
		t.Fatal(err)
	}

	rid, err := NewChannelID(
		name, desc, Public, netTime.Now(), secret, salt, HashPubKey(pk.Public()))
	ac := &Channel{
		RsaPubKeyLength: 528,
		ReceptionID:     rid,
		Name:            name,
		Description:     desc,
		Salt:            salt,
		RsaPubKeyHash:   HashPubKey(pk.Public()),
	}

	marshalled, err := ac.Marshal()
	if err != nil {
		t.Fatalf("Failed to marshall asymmetric channel: %+v", err)
	}

	unmarshalled, err := UnmarshalChannel(marshalled)
	if err != nil {
		t.Fatalf("Failed to unmarshal data into asymmetric object: %+v", err)
	}

	if !reflect.DeepEqual(ac, unmarshalled) {
		t.Errorf("Did not receive expected asymmetric channel."+
			"\nexpected: %+v\nreceived: %+v", ac, unmarshalled)
	}
}

func TestNewChannel_Verify(t *testing.T) {
	rng := csprng.NewSystemRNG()

	name := "Asymmetric_channel"
	desc := "Asymmetric channel description"

	ac, _, _ := NewChannel(name, desc, Public, 1000, rng)

	if !ac.Verify() {
		t.Fatalf("Channel ID should have verified")
	}
}

func TestChannel_Verify_Happy(t *testing.T) {
	rng := csprng.NewSystemRNG()
	packetSize := 1000
	keySize, _ := calculateKeySize(packetSize, packetSize)
	keySize = keySize * 8

	s := rsa.GetScheme()
	pk, err := s.Generate(rng, keySize)
	if err != nil {
		t.Fatalf("Failed to generate private key: %+v", err)
	}
	name := "Asymmetric channel"
	desc := "Asymmetric channel description"
	level := Public
	created := netTime.Now()
	salt := cmix.NewSalt(rng, saltSize)
	secret := make([]byte, secretSize)
	_, err = rng.Read(secret)
	if err != nil {
		t.Fatal(err)
	}

	hashedSecret := HashSecret(secret)
	hashedPubkey := HashPubKey(pk.Public())

	rid, err := NewChannelID(
		name, desc, level, created, salt, hashedPubkey, hashedSecret)
	ac := &Channel{
		ReceptionID:     rid,
		Name:            name,
		Description:     desc,
		Level:           level,
		Created:         created,
		Salt:            salt,
		RsaPubKeyHash:   hashedPubkey,
		RsaPubKeyLength: 528,
		Secret:          secret,
	}

	if !ac.Verify() {
		t.Fatalf("Channel ID should have verified")
	}
}

func TestChannel_Verify_Fail_BadVerify(t *testing.T) {
	rng := csprng.NewSystemRNG()
	packetSize := 1000
	keySize, _ := calculateKeySize(packetSize, packetSize)
	keySize = keySize * 8

	s := rsa.GetScheme()
	pk, err := s.Generate(rng, keySize)
	if err != nil {
		t.Fatalf("Failed to generate private key: %+v", err)
	}
	name := "Asymmetric channel"
	desc := "Asymmetric channel description"
	salt := cmix.NewSalt(rng, 512)
	secret := make([]byte, 32)
	_, err = rng.Read(secret)
	if err != nil {
		t.Fatal(err)
	}

	hashedPubkey := HashPubKey(pk.Public())

	ac := &Channel{
		RsaPubKeyLength: 528,
		ReceptionID:     &id.ID{},
		Name:            name,
		Description:     desc,
		Salt:            salt,
		Secret:          secret,
		RsaPubKeyHash:   hashedPubkey,
	}

	if ac.Verify() {
		t.Fatalf("Channel ID should not have verified")
	}
}

func TestChannel_Verify_BadGeneration(t *testing.T) {
	rng := csprng.NewSystemRNG()
	packetSize := 1000
	keySize, _ := calculateKeySize(packetSize, packetSize)
	keySize = keySize * 8

	s := rsa.GetScheme()
	pk, err := s.Generate(rng, keySize)
	if err != nil {
		t.Fatalf("Failed to generate private key: %+v", err)
	}
	name := "Asymmetric channel"
	desc := "Asymmetric channel description"
	salt := cmix.NewSalt(rng, 512)
	secret := make([]byte, 32)
	_, err = rng.Read(secret)
	if err != nil {
		t.Fatal(err)
	}

	hashedSecret := HashSecret(secret)
	hashedPubkey := HashPubKey(pk.Public())

	rid, err := NewChannelID(
		name, desc, Public, netTime.Now(), salt, hashedPubkey, hashedSecret)
	ac := &Channel{
		RsaPubKeyLength: 528,
		ReceptionID:     rid,
		Name:            name,
		Description:     desc,
		Salt:            []byte{69},
		Secret:          secret,
		RsaPubKeyHash:   hashedPubkey,
	}

	if ac.Verify() {
		t.Fatalf("Channel ID should not have verified")
	}
}

// Tests that VerifyName does not return an error for a list of valid names.
func TestChannel_VerifyName(t *testing.T) {
	tests := []string{
		strings.Repeat("A", NameMinChars),
		strings.Repeat("A", NameMaxChars),
		"hello",
		"hel1o",
		"سلامدنیا",
		"hel_lo",
	}

	for i, name := range tests {
		if err := VerifyName(name); err != nil {
			t.Errorf("Name %d is invalid %q: %s", i, name, err)
		}
	}
}

// Error path: Tests that VerifyName returns the expected error for a list of
// invalid names.
func TestChannel_VerifyName_InvalidNameError(t *testing.T) {
	tests := map[string]error{
		"":                                  MinNameCharLenErr,
		strings.Repeat("A", NameMinChars-1): MinNameCharLenErr,
		strings.Repeat("A", NameMaxChars+1): MaxNameCharLenErr,
		"😀😀😀":                               NameInvalidCharErr,
		"hel-lo":                            NameInvalidCharErr,
		"hel lo":                            NameInvalidCharErr,
	}

	for name, expected := range tests {

		if err := VerifyName(name); errors.Unwrap(err) != expected {
			t.Errorf("Name %q did not return the expected error."+
				"\nexpected: %s\nreceived: %s", name, expected, err)
		}
	}
}

// Tests that VerifyDescription does not return an error for a list of valid
// description.
func TestChannel_VerifyDescription(t *testing.T) {
	tests := []string{
		strings.Repeat("A", DescriptionMaxChars),
		strings.Repeat("A", DescriptionMaxChars),
		"hello 😀",
		"Symbols? Should. Be! Allowed@",
		"سلامدنیا",
		"hel_lo",
	}

	for i, description := range tests {
		if err := VerifyDescription(description); err != nil {
			t.Errorf("Description %d is invalid %q: %s", i, description, err)
		}
	}
}

// Error path: Tests that VerifyDescription returns the expected error for a
// list of invalid descriptions.
func TestChannel_VerifyDescription_InvalidDescriptionError(t *testing.T) {
	tests := map[string]error{
		strings.Repeat("A", DescriptionMaxChars+1): MaxDescriptionCharLenErr,
	}

	for description, expected := range tests {
		if err := VerifyDescription(description); errors.Unwrap(err) != expected {
			t.Errorf("Description %q did not return the expected error."+
				"\nexpected: %s\nreceived: %s", description, expected, err)
		}
	}
}
