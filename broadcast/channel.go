package broadcast

import (
	"encoding/json"
	"errors"
	"hash"
	"io"

	jww "github.com/spf13/jwalterweatherman"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/hkdf"

	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/crypto/signature/rsa"
	"gitlab.com/xx_network/primitives/id"

	"gitlab.com/elixxir/crypto/cmix"
)

const hkdfInfo = "XX_Network_Broadcast_Channel_HKDF_Blake2b"

var ErrSecretSizeIncorrect = errors.New("NewChannelID secret must be 32 bytes long.")

// Channel is a multicast communication channel that retains the
// various privacy notions that this mix network provides.
type Channel struct {
	ReceptionID     *id.ID
	Name            string
	Description     string
	Salt            []byte
	RsaPubKeyHash   []byte
	RsaPubKeyLength int
	Secret          []byte

	// Only appears in memory, is not contained in the marshalled version.
	// Lazily evaluated on first use.
	// key = H(ReceptionID)
	key []byte
}

func NewChannel(name, description string, packetPayloadLength int, rng csprng.Source) (*Channel, *rsa.PrivateKey, error) {
	pk, err := rsa.GenerateKey(rng, packetPayloadLength/2)
	if err != nil {
		return nil, nil, err
	}
	salt := cmix.NewSalt(rng, 512)

	secret := make([]byte, 32)
	n, err := rng.Read(secret)
	if err != nil {
		jww.FATAL.Panic(err)
	}
	if n != 32 {
		jww.FATAL.Panic("failed to read from rng")
	}

	channelID, err := NewChannelID(name, description, salt, hashSecret(rsa.CreatePublicKeyPem(pk.GetPublic())), secret)
	if err != nil {
		return nil, nil, err
	}

	return &Channel{
		ReceptionID:   channelID,
		Name:          name,
		Description:   description,
		Salt:          salt,
		RsaPubKeyHash: hashSecret(rsa.CreatePublicKeyPem(pk.GetPublic())),
		Secret:        secret,
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

// NewChannelID creates a new channel ID, the resulting 32 byte
// identity is derived like this:
//
// intermediary = H(name | description | rsaPubHash | hashedSecret | salt)
// identityBytes = HKDF(intermediary, salt, hkdfInfo)
func NewChannelID(name, description string, salt, rsaPubHash, secret []byte) (*id.ID, error) {

	if len(secret) != 32 {
		return nil, ErrSecretSizeIncorrect
	}

	hkdfHash := func() hash.Hash {
		hash, err := blake2b.New256(nil)
		if err != nil {
			jww.FATAL.Panic(err)
		}
		return hash
	}

	hkdf1 := hkdf.New(hkdfHash,
		deriveIntermediary(name, description, salt, rsaPubHash, hashSecret(secret)),
		salt,
		[]byte(hkdfInfo))

	identityBytes := make([]byte, 32)
	n, err := io.ReadFull(hkdf1, identityBytes)
	if err != nil {
		jww.FATAL.Panic(err)
	}
	if n != 32 {
		jww.FATAL.Panic("failed to read from hkdf")
	}

	sid := &id.ID{}
	copy(sid[:], identityBytes)
	sid.SetType(id.User)

	return sid, nil
}

type channelDisk struct {
	ReceptionID   *id.ID
	Name          string
	Description   string
	Salt          []byte
	RsaPubKeyHash []byte
	Secret        []byte
	key           []byte
}

func (c *Channel) MarshalJson() ([]byte, error) {
	return json.Marshal(channelDisk{
		ReceptionID:   c.ReceptionID,
		Name:          c.Name,
		Description:   c.Description,
		Salt:          c.Salt,
		RsaPubKeyHash: c.RsaPubKeyHash,
		Secret:        c.Secret,
		key:           c.key,
	})

}

func (c *Channel) UnmarshalJson(b []byte) error {
	cDisk := &channelDisk{}
	err := json.Unmarshal(b, cDisk)
	if err != nil {
		return err
	}

	*c = Channel{
		ReceptionID:   cDisk.ReceptionID,
		Name:          cDisk.Name,
		Description:   cDisk.Description,
		Salt:          cDisk.Salt,
		RsaPubKeyHash: cDisk.RsaPubKeyHash,
		Secret:        cDisk.Secret,
		key:           cDisk.key,
	}

	return nil

}
