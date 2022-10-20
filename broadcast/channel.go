////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package broadcast

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"gitlab.com/elixxir/crypto/rsa"
	"hash"
	"io"
	"regexp"
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
	version       = 1
	hkdfInfo      = "XX_Network_Broadcast_Channel_HKDF_Blake2b"
	labelConstant = "XX_Network_Broadcast_Channel_Constant"
	saltSize      = 32 // 256 bits
	secretSize    = 32 // 256 bits

	// NameMinChars is the minimum number of UTF-8 characters allowed in a
	// channel name.
	NameMinChars = 3 // 3 characters

	// NameMaxChars is the maximum number of UTF-8 characters allowed in a
	// channel name.
	NameMaxChars = 24 // 24 characters

	// DescriptionMaxChars is the maximum number of UTF-8 characters allowed in
	// a channel description.
	DescriptionMaxChars = 144 // 144 characters
)

var channelHash = blake2b.New256

// Error messages.
var (
	// ErrSecretSizeIncorrect indicates an incorrect sized secret.
	ErrSecretSizeIncorrect = errors.New(
		"NewChannelID secret must be 32 bytes long.")

	// ErrSaltSizeIncorrect indicates an incorrect sized salt.
	ErrSaltSizeIncorrect = errors.New(
		"NewChannelID salt must be 32 bytes long.")

	// ErrMalformedPrettyPrintedChannel indicates the channel description blob
	// was malformed.
	ErrMalformedPrettyPrintedChannel = errors.New(
		"Malformed pretty printed channel.")

	// MinNameCharLenErr is returned when the name is shorter than the minimum
	// character limit.
	MinNameCharLenErr = errors.Errorf(
		"name cannot be shorter than %d characters", NameMinChars)

	// MaxNameCharLenErr is returned when the name is longer than the maximum
	// character limit.
	MaxNameCharLenErr = errors.Errorf(
		"name cannot be longer than %d characters", NameMaxChars)

	// NameInvalidCharErr is returned when the name contains disallowed
	// characters.
	NameInvalidCharErr = errors.New("name contains disallowed characters")

	// MaxDescriptionCharLenErr is returned when the description is longer than
	// the maximum character limit.
	MaxDescriptionCharLenErr = errors.Errorf(
		"description cannot be longer than %d characters", DescriptionMaxChars)

	// InvalidPrivacyLevelErr is returned when the PrivacyLevel is not one of
	// the valid chooses.
	InvalidPrivacyLevelErr = errors.New("invalid privacy Level")
)

// Channel is a multicast communication channel that retains the various privacy
// notions that this mix network provides.
type Channel struct {
	ReceptionID     *id.ID
	Name            string
	Description     string
	Salt            []byte
	RsaPubKeyHash   []byte
	RsaPubKeyLength int
	RSASubPayloads  int
	Secret          []byte

	// Determines the amount of information displayed as plaintext vs encrypted
	// when sharing channel information.
	Level PrivacyLevel

	// This key only appears in memory; it is not contained in the marshalled
	// version. It is lazily evaluated on first use.
	//  key = H(ReceptionID)
	key []byte
}

// NewChannel creates a new channel with a variable RSA key size calculated
// based off of recommended security parameters.
//
// The name cannot be more than NameMaxChars characters long and the description
// cannot be more than DescriptionMaxChars characters long.
func NewChannel(name, description string, level PrivacyLevel,
	packetPayloadLength int, rng csprng.Source) (*Channel, rsa.PrivateKey, error) {
	return NewChannelVariableKeyUnsafe(name, description, level,
		packetPayloadLength, rsa.GetScheme().GetDefaultKeySize(), rng)
}

// NewChannelVariableKeyUnsafe creates a new channel with a variable RSA key
// size calculated to optimally use space in the packer.
//
// Do not use this function unless you know what you are doing.
//
// packetPayloadLength is in bytes. maxKeySizeBits is the length, in bits, of an
// RSA key defining the channel in bits. It must be divisible by 8.
func NewChannelVariableKeyUnsafe(name, description string, level PrivacyLevel,
	packetPayloadLength, maxKeySizeBits int, rng csprng.Source) (
	*Channel, rsa.PrivateKey, error) {

	if maxKeySizeBits%8 != 0 {
		return nil, nil, errors.New("maxKeySizeBits must be divisible by 8")
	}

	if err := VerifyName(name); err != nil {
		return nil, nil, err
	}
	if err := VerifyDescription(description); err != nil {
		return nil, nil, err
	}
	if !level.Verify() {
		return nil, nil, errors.WithStack(InvalidPrivacyLevelErr)
	}

	// Get the key size and the number of fields
	keySize, numSubPayloads :=
		calculateKeySize(packetPayloadLength, maxKeySizeBits/8)

	s := rsa.GetScheme()

	// Multiply the key size by 8 because Scheme.Generate expects a key size in
	// bits not bytes
	pk, err := s.Generate(rng, keySize*8)
	if err != nil {
		return nil, nil, err
	}
	salt := cmix.NewSalt(rng, saltSize)

	secret := make([]byte, secretSize)
	n, err := rng.Read(secret)
	if err != nil {
		jww.FATAL.Panic(err)
	}
	if n != secretSize {
		jww.FATAL.Panicf(
			"secret requires %d bytes, found %d bytes", secretSize, n)
	}

	pubKeyHash := HashPubKey(pk.Public())

	channelID, err := NewChannelID(
		name, description, level, salt, pubKeyHash, HashSecret(secret))
	if err != nil {
		return nil, nil, err
	}

	return &Channel{
		ReceptionID:     channelID,
		Name:            name,
		Description:     description,
		Salt:            salt,
		RsaPubKeyHash:   pubKeyHash,
		RsaPubKeyLength: keySize,
		RSASubPayloads:  numSubPayloads,
		Secret:          secret,
		Level:           level,
	}, pk, nil
}

func UnmarshalChannel(data []byte) (*Channel, error) {
	var c Channel
	return &c, json.Unmarshal(data, &c)
}

// Marshal serialises the Channel into JSON.
func (c *Channel) Marshal() ([]byte, error) {
	return json.Marshal(c)
}

func (c *Channel) label() []byte {
	l := append([]byte(c.Name), []byte(c.Description)...)
	return append(l, []byte(labelConstant)...)
}

// Verify checks that the channel ID is the same one generated by the channel
// primitives.
func (c *Channel) Verify() bool {
	gen, err := NewChannelID(c.Name, c.Description, c.Level, c.Salt,
		c.RsaPubKeyHash, HashSecret(c.Secret))
	if err != nil {
		jww.ERROR.Printf("Channel verify failed due to error from "+
			"channel generation: %+v", err)
		return false
	}
	return c.ReceptionID.Cmp(gen)
}

// NewChannelID creates a new channel [id.ID] with a type [id.User].
//
// The 32-byte identity is derived as described below:
//  intermediary = H(name | description | salt | rsaPubHash | hashedSecret)
//  identityBytes = HKDF(intermediary, salt, hkdfInfo)
func NewChannelID(name, description string, level PrivacyLevel, salt,
	rsaPubHash, secretHash []byte) (*id.ID, error) {
	if len(salt) != saltSize {
		return nil, ErrSaltSizeIncorrect
	}

	hkdfHash := func() hash.Hash {
		h, err := blake2b.New256(nil)
		if err != nil {
			jww.FATAL.Panic(err)
		}
		return h
	}

	intermediary :=
		deriveIntermediary(
			name, description, level, salt, rsaPubHash, secretHash)
	hkdf1 := hkdf.New(hkdfHash, intermediary, salt, []byte(hkdfInfo))

	const identitySize = 32
	identityBytes := make([]byte, identitySize)
	n, err := io.ReadFull(hkdf1, identityBytes)
	if err != nil {
		jww.FATAL.Panic(err)
	}
	if n != identitySize {
		jww.FATAL.Panicf(
			"channel identity requires %d bytes, HKDF provided %d bytes",
			identitySize, n)
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

// PrivacyLevel returns the Level of privacy set for this channel.
func (c *Channel) PrivacyLevel() PrivacyLevel {
	return c.Level
}

// PrettyPrint prints a human-readable serialization of this Channel that can b
// copy and pasted.
//
// Example:
//  <Speakeasy-v1:Test Channel,description:This is a test channel,secrets:YxHhRAKy2D4XU2oW5xnW/3yaqOeh8nO+ZSd3nUmiQ3c=,6pXN2H9FXcOj7pjJIZoq6nMi4tGX2s53fWH5ze2dU1g=,493,1,MVjkHlm0JuPxQNAn6WHsPdOw9M/BUF39p7XB/QEkQyc=>
func (c *Channel) PrettyPrint() string {
	return fmt.Sprintf(
		"<Speakeasy-v%d:%s,description:%s,Level:%s,secrets:%s,%s,%d,%d,%s>",
		version,
		c.Name,
		c.Description,
		c.Level.Marshal(),
		base64.StdEncoding.EncodeToString(c.Salt),
		base64.StdEncoding.EncodeToString(c.RsaPubKeyHash),
		c.RsaPubKeyLength,
		c.RSASubPayloads,
		base64.StdEncoding.EncodeToString(c.Secret))
}

// NewChannelFromPrettyPrint creates a new Channel given a valid pretty printed
// Channel serialization generated using the Channel.PrettyPrint method.
func NewChannelFromPrettyPrint(p string) (*Channel, error) {
	fields := strings.FieldsFunc(p, split)
	if len(fields) != 12 {
		return nil, errors.Errorf(
			"%v: number of fields %d does not match expected of %d",
			ErrMalformedPrettyPrintedChannel, len(fields), 12)
	}

	level, err := UnmarshalPrivacyLevel(fields[5])
	if err != nil {
		return nil, errors.Errorf("%v: could not decode privacy Level: %+v",
			ErrMalformedPrettyPrintedChannel, err)
	}

	salt, err := base64.StdEncoding.DecodeString(fields[7])
	if err != nil {
		return nil, errors.Errorf("%v: Failed to decode salt: %+v",
			ErrMalformedPrettyPrintedChannel, err)
	}

	rsaPubKeyHash, err := base64.StdEncoding.DecodeString(fields[8])
	if err != nil {
		return nil, errors.Errorf("%v: Failed to decode RSA public key: %+v",
			ErrMalformedPrettyPrintedChannel, err)
	}

	rsaPubKeyLength, err := strconv.Atoi(fields[9])
	if err != nil {
		return nil, errors.Errorf("%v: Failed to decode RSA public key length: %+v",
			ErrMalformedPrettyPrintedChannel, err)
	}

	rsaSubPayloads, err := strconv.Atoi(fields[10])
	if err != nil {
		return nil, errors.Errorf("%v: Failed to decode RSA sub payloads: %+v",
			ErrMalformedPrettyPrintedChannel, err)
	}

	secret, err := base64.StdEncoding.DecodeString(fields[11])
	if err != nil {
		return nil, errors.Errorf("%v: Failed to decode secret: %+v",
			ErrMalformedPrettyPrintedChannel, err)
	}

	c := &Channel{
		Name:            fields[1],
		Description:     fields[3],
		Level:           level,
		Salt:            salt,
		RsaPubKeyHash:   rsaPubKeyHash,
		RsaPubKeyLength: rsaPubKeyLength,
		RSASubPayloads:  rsaSubPayloads,
		Secret:          secret,
	}

	// Ensure that the name, description, and privacy Level are valid
	if err = VerifyName(c.Name); err != nil {
		return nil, err
	}
	if err := VerifyDescription(c.Description); err != nil {
		return nil, err
	}
	if !c.Level.Verify() {
		return nil, errors.WithStack(InvalidPrivacyLevelErr)
	}

	c.ReceptionID, err = NewChannelID(c.Name, c.Description, c.Level, c.Salt,
		c.RsaPubKeyHash, HashSecret(c.Secret))
	if err != nil {
		return nil, ErrMalformedPrettyPrintedChannel
	}

	return c, nil
}

func split(r rune) bool {
	return r == ',' || r == ':' || r == '>'
}

// nameMatch is the regular expressions that channel names are checked against.
// It only allows letters, numbers, and underscores.
//
// Regex explains:
//  ^       must start with any of the characters enumerated below
//  \p{L}   any kind of letter from any language
//  0-9     any digit 0 through 9
//  _       underscore
//  $       must end with any of the characters enumerated above
//  +       match any number of character enumerated above
var nameMatch = regexp.MustCompile(`[^\p{L}0-9_$]+`)

// VerifyName verifies that the name is a valid channel name.
func VerifyName(name string) error {
	nameLen := len([]rune(name))

	if nameLen < NameMinChars {
		return errors.WithStack(MinNameCharLenErr)
	} else if nameLen > NameMaxChars {
		return errors.WithStack(MaxNameCharLenErr)
	} else if nameMatch.MatchString(name) {
		return errors.WithStack(NameInvalidCharErr)
	}

	return nil
}

// VerifyDescription verifies that the description is a valid channel
// description.
func VerifyDescription(description string) error {
	if len([]rune(description)) > DescriptionMaxChars {
		return errors.WithStack(MaxDescriptionCharLenErr)
	}

	return nil
}
