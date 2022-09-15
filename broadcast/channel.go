package broadcast

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"gitlab.com/elixxir/crypto/rsa"
	"hash"
	"io"
	"strconv"
	"strings"

	jww "github.com/spf13/jwalterweatherman"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/hkdf"

	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/primitives/id"

	"gitlab.com/elixxir/crypto/cmix"
)

const (
	version  = 1
	hkdfInfo = "XX_Network_Broadcast_Channel_HKDF_Blake2b"
)

var channelHash = blake2b.New256

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
	RSASubPayloads		int
	Secret              []byte

	// Only appears in memory, is not contained in the marshalled version.
	// Lazily evaluated on first use.
	// key = H(ReceptionID)
	key []byte
}

// NewChannel creates a new channel with a variable rsa keysize calculated based
// off of recommended security parameters.
func NewChannel(name, description string, packetPayloadLength int,
	rng csprng.Source) (*Channel, rsa.PrivateKey, error) {
	return NewChannelVariableKeyUnsafe(name, description, packetPayloadLength,
		rsa.GetScheme().GetDefaultKeySize(), rng)
}

// NewChannelVariableKeyUnsafe creates a new channel with a variable rsa keysize calculated to
// optimally use space in the packer.
// Do not use unless you know what you are doing
func NewChannelVariableKeyUnsafe(name, description string, packetPayloadLength,
	maxKeysize int,rng csprng.Source) (*Channel, rsa.PrivateKey, error) {

	//get the key size and the number of fields
	keysize, numSubpayloads := calculateKeySize(packetPayloadLength,maxKeysize)

	s := rsa.GetScheme()

	pk, err := s.Generate(rng, keysize)
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

	pubkeyHash := hashPubKey(pk.Public())

	channelID, err := NewChannelID(name, description, salt, pubkeyHash, secret)
	if err != nil {
		return nil, nil, err
	}

	return &Channel{
		ReceptionID:         channelID,
		Name:                name,
		Description:         description,
		Salt:                salt,
		RsaPubKeyHash:       pubkeyHash,
		Secret:              secret,
		RsaPubKeyLength:     keysize,
		RSASubPayloads: 	 numSubpayloads,
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



func (c *Channel) MarshalJson() ([]byte, error) {
	return json.Marshal(c)

}

func (c *Channel) UnmarshalJson(b []byte) error {
	err := json.Unmarshal(b, c)
	if err != nil {
		return err
	}
	return nil
}

// PrettyPrint prints a human-pasteable serialization of this Channel type, like this:
//
// <XXChannel:v1:"name",description:"blah",math:"qw432432sdfserfwerewrwerewrewrwerewrwerewerwee","qw432432sdfserfwerewrwerewrewrwerewrw
// erewerwee","qw432432sdfserfwerewrwerewrewrwerewrwerewerwee","qw432432sdfserfwerewrwerewrewrwerewrwerewerwee",>
func (c *Channel) PrettyPrint() string {
	var b strings.Builder
	fmt.Fprintf(&b, "<XXChannel-v%d:%s,description:%s,secrets:%s,%s,%d,%d,%s>",
		version,
		c.Name,
		c.Description,
		base64.StdEncoding.EncodeToString(c.Salt),
		base64.StdEncoding.EncodeToString(c.RsaPubKeyHash),
		c.RsaPubKeyLength,
		c.RSASubPayloads,
		base64.StdEncoding.EncodeToString(c.Secret))
	return b.String()
}

// NewChannelFromPrettyPrint creates a new Channel given
// a valid pretty printed Channel serialization via the
// PrettyPrint method.
func NewChannelFromPrettyPrint(p string) (*Channel, error) {
	fields := strings.FieldsFunc(p,split)
	if len(fields) != 10 {
		return nil, ErrMalformedPrettyPrintedChannel
	}


	salt, err := base64.StdEncoding.DecodeString(string(fields[6]))
	if err != nil {
		return nil, ErrMalformedPrettyPrintedChannel
	}

	rsaPubKeyHash, err := base64.StdEncoding.DecodeString(string(fields[7]))
	if err != nil {
		return nil, ErrMalformedPrettyPrintedChannel
	}

	rsaPubKeyLength, err := strconv.Atoi(fields[8])
	if err != nil {
		return nil, ErrMalformedPrettyPrintedChannel
	}

	rsaSubPayloads, err := strconv.Atoi(fields[10])
	if err != nil {
		return nil, ErrMalformedPrettyPrintedChannel
	}

	secret, err := base64.StdEncoding.DecodeString(string(fields[11][:len(fields[11])-1]))
	if err != nil {
		return nil, ErrMalformedPrettyPrintedChannel
	}

	c := &Channel{
		Name:                fields[1],
		Description:         fields[3],
		Salt:                salt,
		RsaPubKeyHash:       rsaPubKeyHash,
		RsaPubKeyLength:     rsaPubKeyLength,
		RSASubPayloads: 	 rsaSubPayloads,
		Secret:              secret,
	}

	c.ReceptionID, err = NewChannelID(c.Name, c.Description, c.Salt, c.RsaPubKeyHash, c.Secret)
	if err != nil {
		return nil, ErrMalformedPrettyPrintedChannel
	}

	return c, nil
}

func split(r rune)bool{
	return r==',' || r == ':'
}