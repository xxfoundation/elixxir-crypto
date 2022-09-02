package broadcast

import (
	"bytes"
	"encoding/json"
	"fmt"
	"gitlab.com/elixxir/crypto/cmix"
	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/crypto/signature/rsa"
	"reflect"
	"testing"
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

	rid, err := NewChannelID(name, desc, salt, pk.GetPublic().GetN().Bytes(), secret)
	if err != nil {
		panic(err)
	}

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
	secret := make([]byte, 32)
	_, err = rng.Read(secret)
	if err != nil {
		panic(err)
	}

	rid, err := NewChannelID(name, desc, secret, salt, pk.GetPublic().GetN().Bytes())
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
