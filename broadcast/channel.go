package broadcast

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"strconv"
	"strings"

	jww "github.com/spf13/jwalterweatherman"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/hkdf"

	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/crypto/signature/rsa"
	"gitlab.com/xx_network/primitives/id"

	"gitlab.com/elixxir/crypto/cmix"
)

const (
	version  = "v1"
	hkdfInfo = "XX_Network_Broadcast_Channel_HKDF_Blake2b"
)

// ErrSecretSizeIncorrect indicates an incorrect sized secret.
var ErrSecretSizeIncorrect = errors.New("NewChannelID secret must be 32 bytes long.")

// ErrPayloadLengthIsOdd indicates an odd packet payload length.
var ErrPayloadLengthIsOdd = errors.New("Packet payload length must be even.")

// ErrMalformedPrettyPrintedChannel indicates the channel description blob was malformed.
var ErrMalformedPrettyPrintedChannel = errors.New("Malformed pretty printed channel.")

// Channel is a multicast communication channel that retains the
// various privacy notions that this mix network provides.
type Channel struct {
	ReceptionID         *id.ID
	Name                string
	Description         string
	Salt                []byte
	RsaPubKeyHash       []byte
	RsaPubKeyLength     int
	RsaCiphertextLength int
	Secret              []byte

	// Only appears in memory, is not contained in the marshalled version.
	// Lazily evaluated on first use.
	// key = H(ReceptionID)
	key []byte
}

func NewChannel(name, description string, packetPayloadLength int, rng csprng.Source) (*Channel, *rsa.PrivateKey, error) {

	if packetPayloadLength%2 != 0 {
		return nil, nil, ErrPayloadLengthIsOdd
	}

	pk, err := rsa.GenerateKey(rng, (packetPayloadLength-rsa.ELength)/2)
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

	pubKeyBytes := pk.GetPublic().Bytes()

	channelID, err := NewChannelID(name, description, salt, hashSecret(pubKeyBytes), secret)
	if err != nil {
		return nil, nil, err
	}

	return &Channel{
		ReceptionID:         channelID,
		Name:                name,
		Description:         description,
		Salt:                salt,
		RsaPubKeyHash:       hashSecret(pubKeyBytes),
		Secret:              secret,
		RsaCiphertextLength: len(pubKeyBytes) - rsa.ELength,
		RsaPubKeyLength:     len(pubKeyBytes),
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
	ReceptionID         *id.ID
	Name                string
	Description         string
	Salt                []byte
	RsaPubKeyHash       []byte
	RsaPubKeyLength     int
	RsaCiphertextLength int
	Secret              []byte
	key                 []byte
}

func (c *Channel) MarshalJson() ([]byte, error) {
	return json.Marshal(channelDisk{
		ReceptionID:         c.ReceptionID,
		Name:                c.Name,
		Description:         c.Description,
		Salt:                c.Salt,
		RsaPubKeyHash:       c.RsaPubKeyHash,
		RsaPubKeyLength:     c.RsaPubKeyLength,
		RsaCiphertextLength: c.RsaCiphertextLength,
		Secret:              c.Secret,
		key:                 c.key,
	})

}

func (c *Channel) UnmarshalJson(b []byte) error {
	cDisk := &channelDisk{}
	err := json.Unmarshal(b, cDisk)
	if err != nil {
		return err
	}

	*c = Channel{
		ReceptionID:         cDisk.ReceptionID,
		Name:                cDisk.Name,
		Description:         cDisk.Description,
		Salt:                cDisk.Salt,
		RsaPubKeyHash:       cDisk.RsaPubKeyHash,
		RsaPubKeyLength:     cDisk.RsaPubKeyLength,
		RsaCiphertextLength: cDisk.RsaCiphertextLength,
		Secret:              cDisk.Secret,
		key:                 cDisk.key,
	}

	return nil

}

// PrettyPrint prints a human-pasteable serialization of this Channel type, like this:
//
// <XXChannel:v1:"name",description:"blah",math:"qw432432sdfserfwerewrwerewrewrwerewrwerewerwee","qw432432sdfserfwerewrwerewrewrwerewrw
// erewerwee","qw432432sdfserfwerewrwerewrewrwerewrwerewerwee","qw432432sdfserfwerewrwerewrewrwerewrwerewerwee",>
func (c *Channel) PrettyPrint() string {
	var b strings.Builder
	fmt.Fprintf(&b, "<XXChannel,%s,%s,description,%s,secret,%s,%s,%s,%d,%d,%s>",
		version,
		c.Name,
		c.Description,
		base64.StdEncoding.EncodeToString(c.ReceptionID[:]),
		base64.StdEncoding.EncodeToString(c.Salt),
		base64.StdEncoding.EncodeToString(c.RsaPubKeyHash),
		c.RsaPubKeyLength,
		c.RsaCiphertextLength,
		base64.StdEncoding.EncodeToString(c.Secret))
	return b.String()
}

// NewChannelFromPrettyPrint creates a new Channel given
// a valid pretty printed Channel serialization via the
// PrettyPrint method.
func NewChannelFromPrettyPrint(p string) (*Channel, error) {
	fields := strings.Split(p, ",")
	if len(fields) != 12 {
		return nil, ErrMalformedPrettyPrintedChannel
	}

	id := new(id.ID)
	rawId, err := base64.StdEncoding.DecodeString(string(fields[6]))
	if err != nil {
		return nil, ErrMalformedPrettyPrintedChannel
	}
	copy(id[:], rawId)

	salt, err := base64.StdEncoding.DecodeString(string(fields[7]))
	if err != nil {
		return nil, ErrMalformedPrettyPrintedChannel
	}

	rsaPubKeyHash, err := base64.StdEncoding.DecodeString(string(fields[8]))
	if err != nil {
		return nil, ErrMalformedPrettyPrintedChannel
	}

	rsaPubKeyLength, err := strconv.Atoi(fields[9])
	if err != nil {
		return nil, ErrMalformedPrettyPrintedChannel
	}

	rsaCiphertextLength, err := strconv.Atoi(fields[10])
	if err != nil {
		return nil, ErrMalformedPrettyPrintedChannel
	}

	secret, err := base64.StdEncoding.DecodeString(string(fields[11][:len(fields[11])-1]))
	if err != nil {
		return nil, ErrMalformedPrettyPrintedChannel
	}

	return &Channel{
		Name:                fields[2],
		Description:         fields[4],
		ReceptionID:         id,
		Salt:                salt,
		RsaPubKeyHash:       rsaPubKeyHash,
		RsaPubKeyLength:     rsaPubKeyLength,
		RsaCiphertextLength: rsaCiphertextLength,
		Secret:              secret,
	}, nil
}
