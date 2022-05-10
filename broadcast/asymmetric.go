package broadcast

import (
	"encoding/json"
	"gitlab.com/elixxir/crypto/hash"
	"gitlab.com/elixxir/primitives/format"
	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/crypto/multicastRSA"
	"gitlab.com/xx_network/primitives/id"
)

// Asymmetric uniquely identifies an asymmetric broadcast channel
type Asymmetric struct {
	ReceptionID *id.ID // ReceptionID = H(Name, Description, Salt, RsaPubKey)
	Name        string
	Description string
	Salt        []byte
	RsaPubKey   multicastRSA.PublicKey
}

// Encrypt an asymmetric broadcast payload, return it along with a mac & fingerprint
func (a *Asymmetric) Encrypt(payload []byte, pk multicastRSA.PrivateKey, csprng csprng.Source) (
	encryptedPayload, mac []byte, nonce format.Fingerprint, err error) {
	h, err := hash.NewCMixHash()
	if err != nil {
		return
	}

	// Note: this doesn't really do much
	nonce = newNonce(csprng)
	key := newMessageKey(nonce, pk.GetN().Bytes())
	mac = makeMAC(key, payload)

	// Encrypt payload using multicastRSA
	encryptedPayload, err = multicastRSA.EncryptOAEP(h, csprng, pk, payload, a.label())
	if err != nil {
		return
	}

	return
}

func (a *Asymmetric) Decrypt(payload []byte) ([]byte, error) {
	h, err := hash.NewCMixHash()
	if err != nil {
		return nil, err
	}
	decrypted, err := multicastRSA.DecryptOAEP(h, a.RsaPubKey, payload, a.label())
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}

// Marshal serialises the Symmetric object into JSON.
func (a *Asymmetric) Marshal() ([]byte, error) {
	return json.Marshal(a)
}

func (a *Asymmetric) label() []byte {
	return append([]byte(a.Name), []byte(a.Description)...)
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
