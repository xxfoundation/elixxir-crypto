////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package broadcast

import (
	"bytes"
	"testing"

	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/crypto/signature/rsa"

	"gitlab.com/elixxir/crypto/cmix"
)

func TestChannel_MarshalJson(t *testing.T) {
	// Construct a channel
	rng := csprng.NewSystemRNG()
	pk, err := rsa.GenerateKey(rng, 4096)
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

	rid, err := NewChannelID(name, desc, secret, salt, pk.GetPublic().GetN().Bytes())
	channel := Channel{
		ReceptionID: rid,
		Name:        name,
		Description: desc,
		Salt:        salt,
		RsaPubKey:   pk.GetPublic(),
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

	if newChannel.RsaPubKey.E != channel.RsaPubKey.E {
		t.Fatalf("Channel's RSA public key did not get unmarshaled properly."+
			"\nExpected: %+v"+
			"\nReceived: %+v", channel.RsaPubKey, newChannel.RsaPubKey)
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

func TestChannel_NewChannelIDSecretLength(t *testing.T) {
	name := "mychannelname"
	description := "my channel description"
	rng := csprng.NewSystemRNG()
	salt := make([]byte, 24)
	_, err := rng.Read(salt)
	if err != nil {
		t.Fatal(err)
	}

	privateKey, err := rsa.GenerateKey(rng, 4096)
	if err != nil {
		t.Fatal(err)
	}

	secret := make([]byte, 32)
	_, err = rng.Read(secret)
	if err != nil {
		t.Fatal(err)
	}

	_, err = NewChannelID(name, description, salt, privateKey.GetPublic().GetN().Bytes(), secret)
	if err != nil {
		t.Fatal(err)
	}

	_, err = NewChannelID(name, description, salt, privateKey.GetPublic().GetN().Bytes(), []byte("1234567"))
	if err == nil {
		t.Fatal()
	}
}
