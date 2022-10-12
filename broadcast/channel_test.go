////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package broadcast

import (
	"bytes"
	"gitlab.com/elixxir/crypto/cmix"
	"gitlab.com/elixxir/crypto/rsa"
	"gitlab.com/xx_network/crypto/csprng"
	oldRsa "gitlab.com/xx_network/crypto/signature/rsa"
	"gitlab.com/xx_network/primitives/id"
	"reflect"
	"testing"
)

func TestChannel_PrettyPrint(t *testing.T) {
	rng := csprng.NewSystemRNG()

	name := "Test Channel"
	desc := "This is a test channel"

	channel1, _, err := NewChannel(name, desc, 1000, rng)
	if err != nil {
		t.Fatalf(err.Error())
	}

	pretty1 := channel1.PrettyPrint()
	t.Log(pretty1)

	channel2, err := NewChannelFromPrettyPrint(pretty1)
	if err != nil {
		t.Fatal(err)
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
	rid, err := NewChannelID(name, desc, secret, salt, HashSecret(pubKeyPem))
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

	rid, err := NewChannelID(name, desc, secret, salt, HashPubKey(pk.Public()))
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
		t.Errorf("Did not receive expected asymmetric channel\n\tExpected: %+v\n\tReceived: %+v\n", ac, unmarshalled)
	}
}

func TestNewChannel_Verify(t *testing.T) {
	rng := csprng.NewSystemRNG()

	name := "Asymmetric channel"
	desc := "Asymmetric channel description"

	ac, _, _ := NewChannel(name, desc, 1000, rng)

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
	salt := cmix.NewSalt(rng, saltSize)
	secret := make([]byte, secretSize)
	_, err = rng.Read(secret)
	if err != nil {
		t.Fatal(err)
	}

	hashedSecret := HashSecret(secret)
	hashedPubkey := HashPubKey(pk.Public())

	rid, err := NewChannelID(name, desc, salt, hashedPubkey, hashedSecret)
	ac := &Channel{
		RsaPubKeyLength: 528,
		ReceptionID:     rid,
		Name:            name,
		Description:     desc,
		Salt:            salt,
		Secret:          secret,
		RsaPubKeyHash:   hashedPubkey,
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

	rid, err := NewChannelID(name, desc, salt, hashedPubkey, hashedSecret)
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
