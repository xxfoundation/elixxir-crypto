package broadcast

import (
	"crypto/sha256"
	"encoding/json"
	"gitlab.com/elixxir/crypto/cmix"
	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/crypto/signature/rsa"
	"gitlab.com/xx_network/primitives/id"
)

type Channel struct {
	ReceptionID *id.ID // ReceptionID = H(Name, Description, Salt, RsaPubKey)
	Name        string
	Description string
	Salt        []byte
	RsaPubKey   *rsa.PublicKey

	// Only appears in memory, is not contained in the marshalled version.
	// Lazily evaluated on first use.
	// key = H(ReceptionID)
	key []byte
}

func NewChannel(name, description string, rng csprng.Source) (*Channel, *rsa.PrivateKey, error) {
	pk, err := rsa.GenerateKey(rng, 4096)
	if err != nil {
		return nil, nil, err
	}
	salt := cmix.NewSalt(rng, 512)

	channelID, err := NewChannelID(name, description, salt, rsa.CreatePublicKeyPem(pk.GetPublic()))
	if err != nil {
		return nil, nil, err
	}

	return &Channel{
		ReceptionID: channelID,
		Name:        name,
		Description: description,
		Salt:        salt,
		RsaPubKey:   pk.GetPublic(),
	}, pk, nil
}

func UnmarshalChannel(data []byte) (*Channel, error) {
	var c Channel
	return &c, json.Unmarshal(data, &c)
}

// Marshal serialises the Symmetric object into JSON.
func (c *Channel) Marshal() ([]byte, error) {
	return json.Marshal(c)
}

func (c *Channel) label() []byte {
	return append([]byte(c.Name), []byte(c.Description)...)
}

// NewChannelID creates a new channel ID based on name, description, salt and RSA public key
func NewChannelID(name, description string, salt, rsaPub []byte) (*id.ID, error) {
	h := sha256.New()
	_, err := h.Write([]byte(name))
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

type channelDisk struct {
	ReceptionID *id.ID
	Name        string
	Description string
	Salt        []byte
	RsaPubKey   *rsa.PublicKey
	key         []byte
}

func (c *Channel) MarshalJson() ([]byte, error) {
	return json.Marshal(channelDisk{
		ReceptionID: c.ReceptionID,
		Name:        c.Name,
		Description: c.Description,
		Salt:        c.Salt,
		RsaPubKey:   c.RsaPubKey,
		key:         c.key,
	})

}

func (c *Channel) UnmarshalJson(b []byte) error {
	cDisk := &channelDisk{}
	err := json.Unmarshal(b, cDisk)
	if err != nil {
		return err
	}

	*c = Channel{
		ReceptionID: cDisk.ReceptionID,
		Name:        cDisk.Name,
		Description: cDisk.Description,
		Salt:        cDisk.Salt,
		RsaPubKey:   cDisk.RsaPubKey,
		key:         cDisk.key,
	}

	return nil

}
