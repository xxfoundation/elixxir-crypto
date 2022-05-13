package broadcast

import (
	"bytes"
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
	rid, err := NewAsymmetricID(name, desc, salt, pk.GetPublic().GetN().Bytes())
	ac := Asymmetric{
		ReceptionID: rid,
		Name:        name,
		Description: desc,
		Salt:        salt,
		RsaPubKey:   pk.GetPublic(),
	}

	payload := make([]byte, 128)
	_, err = rng.Read(payload)
	if err != nil {
		t.Fatalf("Failed to read random data to payload: %+v", err)
	}
	encrypted, _, _, err := ac.Encrypt(payload, pk, rng)
	if err != nil {
		t.Fatalf("Failed to encrypt payload: %+v", err)
	}

	decrypted, err := ac.Decrypt(encrypted)
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
	rid, err := NewAsymmetricID(name, desc, salt, pk.GetPublic().GetN().Bytes())
	ac := &Asymmetric{
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

	unmarshalled, err := UnmarshalAsymmetric(marshalled)
	if err != nil {
		t.Fatalf("Failed to unmarshal data into asymmetric object: %+v", err)
	}

	if !reflect.DeepEqual(ac, unmarshalled) {
		t.Errorf("Did not receive expected asymmetric channel\n\tExpected: %+v\n\tReceived: %+v\n", ac, unmarshalled)
	}
}
