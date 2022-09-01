package broadcast

import (
	"bytes"
	cryptorsa "crypto/rsa"
	"encoding/json"
	"fmt"
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
	rid, err := NewChannelID(name, desc, salt, pk.GetPublic().GetN().Bytes())
	ac := Channel{
		ReceptionID: rid,
		Name:        name,
		Description: desc,
		Salt:        salt,
		RsaPubKey:   pk.GetPublic(),
	}

	marshaled, _ := json.Marshal(pk.GetPublic())
	fmt.Printf("%s\n\n", marshaled)

	marshalled, _ := json.Marshal(ac)
	if err != nil {
		t.Fatalf("Failed to marshal pub key: %v", err)
	}

	fmt.Printf("%s\n", marshalled)

	payload := make([]byte, 128)
	_, err = rng.Read(payload)
	if err != nil {
		t.Fatalf("Failed to read random data to payload: %+v", err)
	}
	encrypted, _, _, err := ac.EncryptAsymmetric(payload, pk, rng)
	if err != nil {
		t.Fatalf("Failed to encrypt payload: %+v", err)
	}

	decrypted, err := ac.DecryptAsymmetric(encrypted)
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
	rid, err := NewChannelID(name, desc, salt, pk.GetPublic().GetN().Bytes())
	ac := &Channel{
		ReceptionID: rid,
		Name:        name,
		Description: desc,
		Salt:        salt,
		RsaPubKey:   pk.GetPublic(),
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

	privateKey, err := cryptorsa.GenerateKey(rng, 4096)
	if err != nil {
		t.Fatalf("Failed to generate private key: %+v", err)
	}
	publicKey := privateKey.Public()
	ciphertext, err := EncryptRSAToPrivate(plaintext, rng, publicKey.(*cryptorsa.PublicKey), label)
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
