package broadcast

import (
	"bytes"
	"reflect"
	"testing"

	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/crypto/signature/rsa"

	"gitlab.com/elixxir/crypto/cmix"
)

func TestAsymmetric_Encrypt_Decrypt(t *testing.T) {
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

	rid, err := NewChannelID(name, desc, salt, hashSecret(pk.GetPublic().Bytes()), secret)
	if err != nil {
		t.Fatal(err)
	}

	ac := Channel{
		RsaPubKeyLength: 528,
		Secret:          secret,
		ReceptionID:     rid,
		Name:            name,
		Description:     desc,
		Salt:            salt,
		RsaPubKeyHash:   hashSecret(pk.GetPublic().Bytes()),
	}

	payload := make([]byte, 128)
	_, err = rng.Read(payload)
	if err != nil {
		t.Fatalf("Failed to read random data to payload: %+v", err)
	}
	encrypted, mac, nonce, err := ac.EncryptRSAToPublic(payload, pk, rng)
	if err != nil {
		t.Fatalf("Failed to encrypt payload: %+v", err)
	}

	decrypted, err := ac.DecryptRSAToPublic(encrypted, mac, nonce)
	if err != nil {
		t.Fatalf("Failed to decrypt payload: %+v", err)
	}

	if bytes.Compare(decrypted, payload) != 0 {
		t.Errorf("Decrypt did not return expected data\n\tExpected: %+v\n\tReceived: %+v\n", payload, decrypted)
	}
}

func TestAsymmetric_Marshal_Unmarshal(t *testing.T) {
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
	ac := &Channel{
		RsaPubKeyLength: 528,
		ReceptionID:     rid,
		Name:            name,
		Description:     desc,
		Salt:            salt,
		RsaPubKeyHash:   hashSecret(rsa.CreatePublicKeyPem(pk.GetPublic())),
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

func TestRSAToPrivateEncryptDecrypt(t *testing.T) {
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

	plaintext := []byte("hello world")

	privateKey, err := rsa.GenerateKey(rng, 4096)
	if err != nil {
		t.Fatalf("Failed to generate private key: %+v", err)
	}
	ciphertext, err := channel.EncryptRSAToPrivate(plaintext, rng, privateKey)
	if err != nil {
		t.Fatal()
	}
	plaintext2, err := channel.DecryptRSAToPrivate(ciphertext, rng, privateKey.GetPublic())
	if err != nil {
		t.Fatal()
	}
	if !bytes.Equal(plaintext, plaintext2) {
		t.Fatal()
	}
}
