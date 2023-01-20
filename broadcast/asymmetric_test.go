////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package broadcast

import (
	"bytes"
	"gitlab.com/elixxir/crypto/cmix"
	"gitlab.com/elixxir/crypto/rsa"
	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/primitives/netTime"
	"testing"
)

func TestChannel_EncryptRSAToPublic_DecryptRSAToPublic_BigKey(t *testing.T) {
	rng := csprng.NewSystemRNG()
	packetSize := 1000
	internalPacketSize := MaxSizedBroadcastPayloadSize(packetSize)
	keySize, n := calculateKeySize(internalPacketSize)
	if n != 1 {
		t.Fatalf("Keysize is not big.\nexpected: %d\nreceived: %d", 1, n)
	}

	s := rsa.GetScheme()
	pk, err := s.Generate(rng, keySize*8)
	if err != nil {
		t.Fatalf("Failed to generate private key: %+v", err)
	}
	name := "Asymmetric channel"
	desc := "Asymmetric channel description"
	level := Public
	created := netTime.Now()
	salt := cmix.NewSalt(rng, 32)

	secret := make([]byte, 32)
	if _, err = rng.Read(secret); err != nil {
		t.Fatal(err)
	}

	rid, err := NewChannelID(
		name, desc, level, created, salt, HashPubKey(pk.Public()), secret)
	if err != nil {
		t.Fatal(err)
	}
	ac := Channel{
		ReceptionID:     rid,
		Name:            name,
		Description:     desc,
		Level:           level,
		Created:         created,
		Salt:            salt,
		RsaPubKeyHash:   HashPubKey(pk.Public()),
		RsaPubKeyLength: keySize,
		RSASubPayloads:  n,
		Secret:          secret,
	}

	maxPayloadLen, _, _ := ac.GetRSAToPublicMessageLength()
	payload := make([]byte, maxPayloadLen)
	if _, err = rng.Read(payload); err != nil {
		t.Fatalf("Failed to read random data to payload: %+v", err)
	}

	_, encrypted, mac, nonce, err :=
		ac.EncryptRSAToPublic(payload, pk, packetSize, rng)
	if err != nil {
		t.Fatalf("Failed to encrypt payload: %+v", err)
	}

	decrypted, _, err := ac.DecryptRSAToPublic(encrypted, mac, nonce)
	if err != nil {
		t.Fatalf("Failed to decrypt payload: %+v", err)
	}

	if !bytes.Equal(decrypted, payload) {
		t.Errorf("Decrypt did not return expected data"+
			"\nexpected: %v\nreceived: %v", payload, decrypted)
	}
}

func TestChannel_EncryptRSAToPublic_DecryptRSAToPublic_BigKey_SmallPayload(t *testing.T) {
	rng := csprng.NewSystemRNG()
	packetSize := 1000
	internalPacketSize := MaxSizedBroadcastPayloadSize(packetSize)
	keySize, n := calculateKeySize(internalPacketSize)
	if n != 1 {
		t.Fatalf("Keysize is not big.\nexpected: %d\nreceived: %d", 1, n)
	}

	s := rsa.GetScheme()
	pk, err := s.Generate(rng, keySize*8)
	if err != nil {
		t.Fatalf("Failed to generate private key: %+v", err)
	}
	name := "Asymmetric channel"
	desc := "Asymmetric channel description"
	level := Public
	created := netTime.Now()
	salt := cmix.NewSalt(rng, 32)

	secret := make([]byte, 32)
	if _, err = rng.Read(secret); err != nil {
		t.Fatal(err)
	}

	rid, err := NewChannelID(
		name, desc, level, created, salt, HashPubKey(pk.Public()), secret)
	if err != nil {
		t.Fatal(err)
	}
	ac := Channel{
		ReceptionID:     rid,
		Name:            name,
		Description:     desc,
		Level:           level,
		Created:         created,
		Salt:            salt,
		RsaPubKeyHash:   HashPubKey(pk.Public()),
		RsaPubKeyLength: keySize,
		RSASubPayloads:  n,
		Secret:          secret,
	}

	payload := make([]byte, 10)
	if _, err = rng.Read(payload); err != nil {
		t.Fatalf("Failed to read random data to payload: %+v", err)
	}

	_, encrypted, mac, nonce, err :=
		ac.EncryptRSAToPublic(payload, pk, internalPacketSize, rng)
	if err != nil {
		t.Fatalf("Failed to encrypt payload: %+v", err)
	}

	decrypted, _, err := ac.DecryptRSAToPublic(encrypted, mac, nonce)
	if err != nil {
		t.Fatalf("Failed to decrypt payload: %+v", err)
	}

	if !bytes.Equal(decrypted, payload) {
		t.Errorf("Decrypt did not return expected data."+
			"\nexpected: %v\nreceived: %v", payload, decrypted)
	}
}

func TestChannel_EncryptRSAToPublic_DecryptRSAToPublic_NewChannel(t *testing.T) {
	rng := csprng.NewSystemRNG()
	packetSize := 1000

	ac, pk, err := NewChannel(
		"Asymmetric_channel", "Channel description", Public, packetSize, rng)
	if err != nil {
		t.Fatalf("Failed to make new channel: %+v", err)
	}

	maxPayloadLen, _, _ := ac.GetRSAToPublicMessageLength()

	payload := make([]byte, maxPayloadLen)
	if _, err = rng.Read(payload); err != nil {
		t.Fatalf("Failed to read random data to payload: %+v", err)
	}

	_, encrypted, mac, nonce, err :=
		ac.EncryptRSAToPublic(payload, pk, packetSize, rng)
	if err != nil {
		t.Fatalf("Failed to encrypt payload: %+v", err)
	}

	decrypted, _, err := ac.DecryptRSAToPublic(encrypted, mac, nonce)
	if err != nil {
		t.Fatalf("Failed to decrypt payload: %+v", err)
	}

	if !bytes.Equal(decrypted, payload) {
		t.Errorf("Decrypt did not return expected data."+
			"\nexpected: %+v\nreceived: %+v", payload, decrypted)
	}
}

func TestChannel_EncryptRSAToPrivate_DecryptRSAToPrivate_BigKey(t *testing.T) {
	rng := csprng.NewSystemRNG()
	packetSize := 1000
	internalPacketSize := MaxSizedBroadcastPayloadSize(packetSize)
	keySize, n := calculateKeySize(internalPacketSize)
	if n != 1 {
		t.Fatalf("Keysize is not big.\nexpected: %d\nreceived: %d", 1, n)
	}

	s := rsa.GetScheme()
	pk, err := s.Generate(rng, keySize*8)
	if err != nil {
		t.Fatalf("Failed to generate private key: %+v", err)
	}
	name := "Asymmetric channel"
	desc := "Asymmetric channel description"
	level := Public
	created := netTime.Now()
	salt := cmix.NewSalt(rng, 32)

	secret := make([]byte, 32)
	if _, err = rng.Read(secret); err != nil {
		t.Fatal(err)
	}

	rid, err := NewChannelID(
		name, desc, level, created, salt, HashPubKey(pk.Public()), secret)
	if err != nil {
		t.Fatal(err)
	}
	ac := Channel{
		ReceptionID:     rid,
		Name:            name,
		Description:     desc,
		Level:           level,
		Created:         created,
		Salt:            salt,
		RsaPubKeyHash:   HashPubKey(pk.Public()),
		RsaPubKeyLength: keySize,
		RSASubPayloads:  n,
		Secret:          secret,
	}

	maxPayloadLen, _, _ := ac.GetRSAToPublicMessageLength()

	payload := make([]byte, maxPayloadLen)
	if _, err = rng.Read(payload); err != nil {
		t.Fatalf("Failed to read random data to payload: %+v", err)
	}

	encrypted, mac, nonce, err :=
		ac.EncryptRSAToPrivate(payload, pk.Public(), packetSize, rng)
	if err != nil {
		t.Fatalf("Failed to encrypt payload: %+v", err)
	}

	decrypted, err := ac.DecryptRSAToPrivate(pk, encrypted, mac, nonce)
	if err != nil {
		t.Fatalf("Failed to decrypt payload: %+v", err)
	}

	if !bytes.Equal(decrypted, payload) {
		t.Errorf("Decrypt did not return expected data"+
			"\nexpected: %v\nreceived: %v", payload, decrypted)
	}
}

func TestChannel_EncryptRSAToPrivate_DecryptRSAToPrivate_BigKey_SmallPacket(t *testing.T) {
	rng := csprng.NewSystemRNG()
	packetSize := 1000
	internalPacketSize := MaxSizedBroadcastPayloadSize(packetSize)
	keySize, n := calculateKeySize(internalPacketSize)
	if n != 1 {
		t.Fatalf("Keysize is not big.\nexpected: %d\nreceived: %d", 1, n)
	}

	s := rsa.GetScheme()
	pk, err := s.Generate(rng, keySize*8)
	if err != nil {
		t.Fatalf("Failed to generate private key: %+v", err)
	}
	name := "Asymmetric channel"
	desc := "Asymmetric channel description"
	level := Public
	created := netTime.Now()
	salt := cmix.NewSalt(rng, 32)

	secret := make([]byte, 32)
	if _, err = rng.Read(secret); err != nil {
		t.Fatal(err)
	}

	rid, err := NewChannelID(
		name, desc, level, created, salt, HashPubKey(pk.Public()), secret)
	if err != nil {
		t.Fatal(err)
	}
	ac := Channel{
		ReceptionID:     rid,
		Name:            name,
		Description:     desc,
		Level:           level,
		Created:         created,
		Salt:            salt,
		RsaPubKeyHash:   HashPubKey(pk.Public()),
		RsaPubKeyLength: keySize,
		RSASubPayloads:  n,
		Secret:          secret,
	}

	payload := make([]byte, 10)
	if _, err = rng.Read(payload); err != nil {
		t.Fatalf("Failed to read random data to payload: %+v", err)
	}

	encrypted, mac, nonce, err :=
		ac.EncryptRSAToPrivate(payload, pk.Public(), packetSize, rng)
	if err != nil {
		t.Fatalf("Failed to encrypt payload: %+v", err)
	}

	decrypted, err := ac.DecryptRSAToPrivate(pk, encrypted, mac, nonce)
	if err != nil {
		t.Fatalf("Failed to decrypt payload: %+v", err)
	}

	if !bytes.Equal(decrypted, payload) {
		t.Errorf("Decrypt did not return expected data"+
			"\nexpected: %v\nreceived: %v", payload, decrypted)
	}
}

func TestChannel_DecryptRSAToPublicInner(t *testing.T) {
	rng := csprng.NewSystemRNG()
	packetSize := 1000
	internalPacketSize := MaxSizedBroadcastPayloadSize(packetSize)
	keySize, n := calculateKeySize(internalPacketSize)
	if n != 1 {
		t.Fatalf("Keysize is not big.\nexpected: %d\nreceived: %d", 1, n)
	}

	s := rsa.GetScheme()
	pk, err := s.Generate(rng, keySize*8)
	if err != nil {
		t.Fatalf("Failed to generate private key: %+v", err)
	}
	name := "Asymmetric channel"
	desc := "Asymmetric channel description"
	level := Public
	created := netTime.Now()
	salt := cmix.NewSalt(rng, 32)

	secret := make([]byte, 32)
	if _, err = rng.Read(secret); err != nil {
		t.Fatal(err)
	}

	rid, err := NewChannelID(
		name, desc, level, created, salt, HashPubKey(pk.Public()), secret)
	if err != nil {
		t.Fatal(err)
	}
	ac := Channel{
		ReceptionID:     rid,
		Name:            name,
		Description:     desc,
		Level:           level,
		Created:         created,
		Salt:            salt,
		RsaPubKeyHash:   HashPubKey(pk.Public()),
		RsaPubKeyLength: keySize,
		RSASubPayloads:  n,
		Secret:          secret,
	}

	maxPayloadLen, _, _ := ac.GetRSAToPublicMessageLength()
	payload := make([]byte, maxPayloadLen)
	if _, err = rng.Read(payload); err != nil {
		t.Fatalf("Failed to read random data to payload: %+v", err)
	}

	singleEncryptedPayload, _, _, _, err :=
		ac.EncryptRSAToPublic(payload, pk, packetSize, rng)
	if err != nil {
		t.Fatalf("Failed to encrypt payload: %+v", err)
	}

	decrypted, err := ac.DecryptRSAToPublicInner(singleEncryptedPayload)
	if err != nil {
		t.Fatalf("Failed to decrypt payload: %+v", err)
	}

	if !bytes.Equal(decrypted, payload) {
		t.Errorf("Decrypt did not return expected data"+
			"\nexpected: %v\nreceived: %v", payload, decrypted)
	}

	// Test that it properly trims payload that is too long
	decrypted, err = ac.DecryptRSAToPublicInner(
		append(singleEncryptedPayload, singleEncryptedPayload...))
	if err != nil {
		t.Fatalf("Failed to decrypt payload: %+v", err)
	}

	if !bytes.Equal(decrypted, payload) {
		t.Errorf("Decrypt did not return expected data"+
			"\nexpected: %v\nreceived: %v", payload, decrypted)
	}
}
