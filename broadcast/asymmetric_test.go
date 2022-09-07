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
		panic(err)
	}

	rid, err := NewChannelID(name, desc, salt, hashSecret(rsa.CreatePublicKeyPem(pk.GetPublic())), secret)
	if err != nil {
		panic(err)
	}

	ac := Channel{
		RsaPubKeyLength: 528,
		Secret:          secret,
		ReceptionID:     rid,
		Name:            name,
		Description:     desc,
		Salt:            salt,
		RsaPubKeyHash:   hashSecret(rsa.CreatePublicKeyPem(pk.GetPublic())),
	}

	payload := make([]byte, 128)
	_, err = rng.Read(payload)
	if err != nil {
		t.Fatalf("Failed to read random data to payload: %+v", err)
	}
	encrypted, mac, nonce, err := ac.EncryptAsymmetric(payload, pk, pk.GetPublic(), rng)
	if err != nil {
		t.Fatalf("Failed to encrypt payload: %+v", err)
	}

	decrypted, err := ac.DecryptAsymmetric(encrypted, mac, nonce)
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
		panic(err)
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
	plaintext := []byte("hello world")
	label := []byte("channel_messages")
	rng := csprng.NewSystemRNG()

	privateKey, err := rsa.GenerateKey(rng, 4096)
	if err != nil {
		t.Fatalf("Failed to generate private key: %+v", err)
	}
	ciphertext, err := EncryptRSAToPrivate(plaintext, rng, privateKey, label)
	if err != nil {
		t.Fatal()
	}
	plaintext2, err := DecryptRSAToPrivate(ciphertext, rng, privateKey, label)
	if err != nil {
		t.Fatal()
	}
	if !bytes.Equal(plaintext, plaintext2) {
		t.Fatal()
	}
}
