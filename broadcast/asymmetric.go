package broadcast

import (
	"encoding/json"
	"gitlab.com/elixxir/crypto/hash"
	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/crypto/multicastRSA"
	"gitlab.com/xx_network/primitives/id"
)

type Asymmetric struct {
	ReceptionID *id.ID // ReceptionID = H(Name, Description, Salt, RsaPubKey)
	Name        string
	Description string
	Salt        []byte
	RsaPubKey   multicastRSA.PublicKey
}

func (a *Asymmetric) Encrypt(payload []byte, pk multicastRSA.PrivateKey, csprng csprng.Source) ([]byte, error) {
	h, err := hash.NewCMixHash()
	if err != nil {
		return nil, err
	}

	encrypted, err := multicastRSA.EncryptOAEP(h, csprng, pk, payload, []byte(a.Name))
	if err != nil {
		return nil, err
	}
	return encrypted, nil
}

func (a *Asymmetric) Decrypt(payload []byte) ([]byte, error) {
	h, err := hash.NewCMixHash()
	if err != nil {
		return nil, err
	}
	decrypted, err := multicastRSA.DecryptOAEP(h, a.RsaPubKey, payload, []byte(a.Name))
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}

// Marshal serialises the Symmetric object into JSON.
func (a *Asymmetric) Marshal() ([]byte, error) {
	return json.Marshal(a)
}

// UnmarshalAsymmetric deserializes the JSON into a new Symmetric.
func UnmarshalAsymmetric(data []byte) (*Asymmetric, error) {
	var a Asymmetric
	return &a, json.Unmarshal(data, &a)
}

// NewAsymmetricID creates a new asymmetric channel ID based on name, description, salt and RSA public key
func NewAsymmetricID(name, description string, salt, rsaPub []byte) (*id.ID, error) {
	h, err := hash.NewCMixHash()
	if err != nil {
		return nil, err
	}
	_, err = h.Write([]byte(name))
	if err != nil {
		return nil, err
	}
	_, err = h.Write([]byte(description))
	if err != nil {
		return nil, err
	}
	_, err = h.Write(salt)
	if err != nil {
		return nil, err
	}
	_, err = h.Write(rsaPub)
	if err != nil {
		return nil, err
	}

	sid := &id.ID{}
	copy(sid[:], h.Sum(nil))
	sid.SetType(id.User)
	return sid, nil
}
