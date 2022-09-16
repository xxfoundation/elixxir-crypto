////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package broadcast

/*
func TestChannel_PrettyPrint(t *testing.T) {
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
	rid, err := NewChannelID(name, desc, secret, salt, hashSecret(rsa.CreatePublicKeyPem(pk.GetPublic())))
	channel1 := Channel{
		Secret:        secret,
		ReceptionID:   rid,
		Name:          name,
		Description:   desc,
		Salt:          salt,
		RsaPubKeyHash: hashSecret(rsa.CreatePublicKeyPem(pk.GetPublic())),
	}

	pretty1 := channel1.PrettyPrint()

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

}

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

	rid, err := NewChannelID(name, desc, secret, salt, hashSecret(rsa.CreatePublicKeyPem(pk.GetPublic())))
	channel := Channel{
		ReceptionID:   rid,
		Name:          name,
		Description:   desc,
		Salt:          salt,
		RsaPubKeyHash: hashSecret(rsa.CreatePublicKeyPem(pk.GetPublic())),
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

func TestRChanel_Marshal_Unmarshal(t *testing.T) {
	rng := csprng.NewSystemRNG()
	packetSize := 1000
	keysize, _ := calculateKeySize(packetSize, packetSize)
	keysize = keysize*8

	s := rsa.GetScheme()
	pk, err := s.Generate(rng, keysize)
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

	rid, err := NewChannelID(name, desc, secret, salt, hashPubKey(pk.Public()))
	ac := &Channel{
		RsaPubKeyLength: 528,
		ReceptionID:     rid,
		Name:            name,
		Description:     desc,
		Salt:            salt,
		RsaPubKeyHash:   hashPubKey(pk.Public()),
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
}*/
