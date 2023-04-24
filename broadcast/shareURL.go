////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package broadcast

import (
	"bytes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"github.com/pkg/errors"
	"github.com/sethvargo/go-diceware/diceware"
	jww "github.com/spf13/jwalterweatherman"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
	"io"
	goUrl "net/url"
	"strconv"
	"strings"
	"time"
)

// The current version number of the share URL structure.
const shareUrlVersion = 1

// Names for keys in the URL.
const (
	versionKey         = "v"
	nameKey            = "0Name"
	descKey            = "1Description"
	levelKey           = "2Level"
	createdKey         = "3Created"
	saltKey            = "s"
	rsaPubKeyHashKey   = "k"
	rsaPubKeyLengthKey = "l"
	rsaSubPayloadsKey  = "p"
	secretKey          = "e"
	dataKey            = "d"

	// MaxUsesKey is the key used to save max uses in a URL. The value is
	// expected to be a positive integer.
	MaxUsesKey = "m"
)

// Data lengths.
const (
	privLevelLen        = 1
	nameLengthLen       = 2
	descLengthLen       = 2
	createdLen          = 8
	saltLen             = saltSize
	rsaPubKeyHashLen    = blake2b.Size256
	rsaPubKeyLengthLen  = 2
	rsaSubPayloadsLen   = 2
	secretLen           = secretSize
	maxUsesLen          = 2
	marshaledPrivateLen = privLevelLen + saltLen + rsaPubKeyHashLen +
		rsaPubKeyLengthLen + rsaSubPayloadsLen + secretLen + maxUsesLen
	marshaledSecretLen = nameLengthLen + descLengthLen + marshaledPrivateLen +
		createdLen
)

// Link type constants.
const (
	// share indicates the link being created for simple URL creation.
	share = false
	// invite indicates the link being created is intended for invitations.
	invite = true

	// NOTE: If more types are added, this may be refactored into an enum.
)

// Error messages.
const (
	// Channel.ShareURL
	parseHostUrlErr           = "could not parse host URL: %+v"
	generatePhrasePasswordErr = "failed to generate password: %+v"

	// DecodeShareURL
	parseShareUrlErr    = "could not parse URL: %+v"
	urlVersionErr       = "no version found"
	parseVersionErr     = "failed to parse version: %+v"
	noMaxUsesErr        = "no max uses found"
	parseMaxUsesErr     = "failed to parse max version: %+v"
	versionErr          = "version mismatch: require v%d, found v%d"
	decodePublicUrlErr  = "could not decode public share URL: %+v"
	decodePrivateUrlErr = "could not decode private share URL: %+v"
	decodeSecretUrlErr  = "could not decode secret share URL: %+v"
	noPasswordErr       = "no password specified"
	malformedUrlErr     = "URL is missing required data"
	maxUsesUrlErr       = "max uses in URL %d does not match expected %d"
	newReceptionIdErr   = "could not create new channel ID: %+v"

	// Channel.decodePublicURL
	parseCreatedErr         = "failed to parse creation time: %+v"
	parseLevelErr           = "failed to parse privacy Level: %+v"
	parseSaltErr            = "failed to parse Salt: %+v"
	parseRsaPubKeyHashErr   = "failed to parse RsaPubKeyHash: %+v"
	parseRsaPubKeyLengthErr = "failed to parse RsaPubKeyLength: %+v"
	parseRsaSubPayloadsErr  = "failed to parse RSASubPayloads: %+v"
	parseSecretErr          = "failed to parse Secret: %+v"

	// Channel.decodePrivateURL and Channel.decodeSecretURL
	decodeEncryptedErr = "could not decode encrypted data string: %+v"
	decryptErr         = "could not decrypt encrypted data: %+v"
	unmarshalUrlErr    = "could not unmarshal data: %+v"

	// Channel.unmarshalPrivateURLSecrets and
	// Channel.unmarshalSecretURLSecrets
	unmarshalPrivateDataLenErr = "data must be %d bytes, data received is %d bytes"
	unmarshalSecretDataLenErr  = "data must be at least %d bytes, data received is %d bytes"
	unmarshalSecretDataLenErr2 = "data must be %d bytes, data received is %d bytes"
)

// ShareURL generates a URL that can be used to share this channel with others
// on the given host.
//
// The RNG is only used for generating passwords for Private or Secret channels.
// It can be set to nil for Public channels. No password is returned for Public
// channels.
//
// See [Channel.Level] for information on URL privacy.
//
// The maxUses is the maximum number of times this URL can be used to join a
// channel. If it is set to 0, then it can be shared unlimited times. The max
// uses is set as a URL parameter using the key [MaxUsesKey]. Note that this
// number is also encoded in the secret data for private and secret URLs, so if
// the number is changed in the URL, is will be verified when calling
// [DecodeShareURL]. There is no enforcement for public URLs.
func (c *Channel) ShareURL(
	url string, maxUses int, csprng io.Reader) (string, string, error) {
	return c.getURL(url, maxUses, csprng, share)
}

// DecodeShareURL decodes the given URL to a Channel. If the channel is Private
// or Secret, then a password is required. Otherwise, an error is returned.
func DecodeShareURL(url, password string) (*Channel, error) {
	return decodeURL(url, password, share)
}

// InviteURL generates a URL that can be used to create an invitation for this
// channel with others on the given host.
//
// See [Channel.Level] for information on URL privacy.
//
// The maxUses is the maximum number of times this URL can be used to join a
// channel. If it is set to 0, then it can be shared unlimited times. The max
// uses is set as a URL parameter using the key [MaxUsesKey]. Note that this
// number is also encoded in the secret data for private and secret URLs, so if
// the number is changed in the URL, is will be verified when calling
// [DecodeInviteURL]. There is no enforcement for public URLs.
func (c *Channel) InviteURL(url string, maxUses int) (string, error) {
	u, _, err := c.getURL(url, maxUses, nil, invite)
	return u, err
}

// DecodeInviteURL decodes the given invite URL to a Channel.
func DecodeInviteURL(url string) (*Channel, error) {
	return decodeURL(url, "", invite)
}

// GetURLType determines the PrivacyLevel of the channel's URL.
func GetURLType(url string) (PrivacyLevel, error) {
	u, err := goUrl.Parse(url)
	if err != nil {
		return 0, errors.Errorf(parseShareUrlErr, err)
	}

	q := u.Query()

	// Check the version
	versionString := q.Get(versionKey)
	if versionString == "" {
		return 0, errors.New(urlVersionErr)
	}
	v, err := strconv.Atoi(versionString)
	if err != nil {
		return 0, errors.Errorf(parseVersionErr, err)
	} else if v != shareUrlVersion {
		return 0, errors.Errorf(versionErr, shareUrlVersion, v)
	}

	// Decode the URL based on the information available (e.g., only the public
	// URL has a salt, so if the saltKey is specified, it is a public URL)
	switch {
	case q.Has(saltKey):
		return Public, nil
	case q.Has(nameKey):
		return Private, nil
	case q.Has(dataKey):
		return Secret, nil
	default:
		return 0, errors.New(malformedUrlErr)
	}
}

// getURL is a helper function which constructs the URL for sharing or
// invitation.
func (c *Channel) getURL(url string, maxUses int, csprng io.Reader,
	isInvite bool) (string, string, error) {
	u, err := goUrl.Parse(url)
	if err != nil {
		return "", "", errors.Errorf(parseHostUrlErr, err)
	}

	// If this is for a sharable link and the privacy Level is Private or
	// Secret, then generate a password
	var password string
	if isInvite && c.Level != Public {
		password, err = generatePhrasePassword(8, csprng)
		if err != nil {
			return "", "", errors.Errorf(generatePhrasePasswordErr, err)
		}
	}

	q := u.Query()
	q.Set(versionKey, strconv.Itoa(shareUrlVersion))
	q.Set(MaxUsesKey, strconv.Itoa(maxUses))

	// Generate URL queries based on the privacy Level
	switch c.Level {
	case Public:
		u.RawQuery = c.encodePublicURL(q).Encode()
	case Private:
		u.RawQuery = c.encodePrivateURL(q, password, maxUses, csprng, isInvite).Encode()
	case Secret:
		u.RawQuery = c.encodeSecretURL(q, password, maxUses, csprng, isInvite).Encode()
	}

	u.RawQuery = q.Encode()

	return u.String(), password, nil
}

// decodeURL is a helper function which decodes a URL, either for sharing or
// invitation.
func decodeURL(url, password string, isInvite bool) (*Channel, error) {
	u, err := goUrl.Parse(url)
	if err != nil {
		return nil, errors.Errorf(parseShareUrlErr, err)
	}

	q := u.Query()

	// Check the version
	versionString := q.Get(versionKey)
	if versionString == "" {
		return nil, errors.New(urlVersionErr)
	}
	v, err := strconv.Atoi(versionString)
	if err != nil {
		return nil, errors.Errorf(parseVersionErr, err)
	} else if v != shareUrlVersion {
		return nil, errors.Errorf(versionErr, shareUrlVersion, v)
	}

	// Get the max uses
	maxUsesString := q.Get(MaxUsesKey)
	if maxUsesString == "" {
		return nil, errors.New(noMaxUsesErr)
	}
	maxUsesFromURL, err := strconv.Atoi(maxUsesString)
	if err != nil {
		return nil, errors.Errorf(parseMaxUsesErr, err)
	}

	c := &Channel{}
	var maxUses int

	// Decode the URL based on the information available (e.g., only the public
	// URL has a salt, so if the saltKey is specified, it is a public URL)
	switch {
	case q.Has(saltKey):
		err = c.decodePublicURL(q)
		if err != nil {
			return nil, errors.Errorf(decodePublicUrlErr, err)
		}
	case q.Has(nameKey):
		if password == "" {
			return nil, errors.New(noPasswordErr)
		}
		maxUses, err = c.decodePrivateURL(q, password, isInvite)
		if err != nil {
			return nil, errors.Errorf(decodePrivateUrlErr, err)
		}
	case q.Has(dataKey):
		if password == "" {
			return nil, errors.New(noPasswordErr)
		}
		maxUses, err = c.decodeSecretURL(q, password, isInvite)
		if err != nil {
			return nil, errors.Errorf(decodeSecretUrlErr, err)
		}
	default:
		return nil, errors.New(malformedUrlErr)
	}

	if c.Level == Private || c.Level == Secret {
		if maxUses != maxUsesFromURL {
			return nil, errors.Errorf(maxUsesUrlErr, maxUsesFromURL, maxUses)
		}
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

	// Generate the channel ID
	c.ReceptionID, err = NewChannelID(c.Name, c.Description, c.Level, c.Created,
		c.Salt, c.RsaPubKeyHash, HashSecret(c.Secret))
	if err != nil {
		return nil, errors.Errorf(newReceptionIdErr, err)
	}

	return c, nil
}

// encodePublicURL encodes the channel to a Public share URL.
func (c *Channel) encodePublicURL(q goUrl.Values) goUrl.Values {
	q.Set(nameKey, c.Name)
	q.Set(descKey, c.Description)
	q.Set(levelKey, c.Level.Marshal())
	q.Set(createdKey, strconv.FormatInt(c.Created.UnixNano(), 10))
	q.Set(saltKey, base64.StdEncoding.EncodeToString(c.Salt))
	q.Set(rsaPubKeyHashKey, base64.StdEncoding.EncodeToString(c.RsaPubKeyHash))
	q.Set(rsaPubKeyLengthKey, strconv.Itoa(c.RsaPubKeyLength))
	q.Set(rsaSubPayloadsKey, strconv.Itoa(c.RSASubPayloads))
	q.Set(secretKey, base64.StdEncoding.EncodeToString(c.Secret))

	return q
}

// decodePublicURL decodes the values in the url.Values from a Public share
// URL to a channel.
func (c *Channel) decodePublicURL(q goUrl.Values) error {
	var err error

	c.Name = q.Get(nameKey)
	c.Description = q.Get(descKey)

	created, err := strconv.ParseInt(q.Get(createdKey), 10, 64)
	if err != nil {
		return errors.Errorf(parseCreatedErr, err)
	}
	c.Created = time.Unix(0, created)

	c.Level, err = UnmarshalPrivacyLevel(q.Get(levelKey))
	if err != nil {
		return errors.Errorf(parseLevelErr, err)
	}

	c.Salt, err = base64.StdEncoding.DecodeString(q.Get(saltKey))
	if err != nil {
		return errors.Errorf(parseSaltErr, err)
	}

	c.RsaPubKeyHash, err = base64.StdEncoding.DecodeString(q.Get(rsaPubKeyHashKey))
	if err != nil {
		return errors.Errorf(parseRsaPubKeyHashErr, err)
	}

	c.RsaPubKeyLength, err = strconv.Atoi(q.Get(rsaPubKeyLengthKey))
	if err != nil {
		return errors.Errorf(parseRsaPubKeyLengthErr, err)
	}

	c.RSASubPayloads, err = strconv.Atoi(q.Get(rsaSubPayloadsKey))
	if err != nil {
		return errors.Errorf(parseRsaSubPayloadsErr, err)
	}

	c.Secret, err = base64.StdEncoding.DecodeString(q.Get(secretKey))
	if err != nil {
		return errors.Errorf(parseSecretErr, err)
	}

	return nil
}

// encodePrivateURL encodes the channel to a Private URL.
func (c *Channel) encodePrivateURL(q goUrl.Values, password string, maxUses int,
	csprng io.Reader, isInvite bool) goUrl.Values {

	data := createDataForURL(c.marshalPrivateURLSecrets(maxUses),
		password, csprng, isInvite)

	q.Set(nameKey, c.Name)
	q.Set(descKey, c.Description)
	q.Set(createdKey, strconv.FormatInt(c.Created.UnixNano(), 10))
	q.Set(dataKey, base64.StdEncoding.EncodeToString(data))

	return q
}

// decodePrivateURL decodes the values in the url.Values from a Private
// share URL to a channel.
func (c *Channel) decodePrivateURL(
	q goUrl.Values, password string, isInvite bool) (int, error) {
	c.Name = q.Get(nameKey)
	c.Description = q.Get(descKey)

	created, err := strconv.ParseInt(q.Get(createdKey), 10, 64)
	if err != nil {
		return 0, errors.Errorf(parseCreatedErr, err)
	}
	c.Created = time.Unix(0, created)

	dataFromUrl, err := base64.StdEncoding.DecodeString(q.Get(dataKey))
	if err != nil {
		return 0, errors.Errorf(decodeEncryptedErr, err)
	}

	data, err := retrieveDataFromURL(dataFromUrl, password, isInvite)
	if err != nil {
		return 0, err
	}

	maxUses, err := c.unmarshalPrivateURLSecrets(data)
	if err != nil {
		return 0, errors.Errorf(unmarshalUrlErr, err)
	}

	return maxUses, nil
}

// encodeSecretURL encodes the channel to a Secret share URL.
func (c *Channel) encodeSecretURL(q goUrl.Values, password string,
	maxUses int, csprng io.Reader, isInvite bool) goUrl.Values {
	data := createDataForURL(c.marshalSecretURLSecrets(maxUses),
		password, csprng, isInvite)

	q.Set(versionKey, strconv.Itoa(shareUrlVersion))
	q.Set(dataKey, base64.StdEncoding.EncodeToString(data))

	return q
}

// decodePrivateURL decodes the values in the url.Values from a Secret
// share URL to a channel.
func (c *Channel) decodeSecretURL(
	q goUrl.Values, password string, isInvite bool) (int, error) {

	dataFromUrl, err := base64.StdEncoding.DecodeString(q.Get(dataKey))
	if err != nil {
		return 0, errors.Errorf(decodeEncryptedErr, err)
	}

	data, err := retrieveDataFromURL(dataFromUrl, password, isInvite)
	if err != nil {
		return 0, err
	}

	maxUses, err := c.unmarshalSecretURLSecrets(data)
	if err != nil {
		return 0, errors.Errorf(unmarshalUrlErr, err)
	}

	return maxUses, nil
}

// createDataForURL is a helper function which creates the channel data placed
// within the URL. This is handled differently for sharing and invitation URLs.
func createDataForURL(marshalledSecrets []byte, password string,
	csprng io.Reader, isInvite bool) []byte {
	if isInvite {
		return marshalledSecrets
	}
	return encryptShareURL(marshalledSecrets, password, csprng)
}

// retrieveDataFromURL is a helper function which retrieves the channel data
// within the URL.
func retrieveDataFromURL(dataFromURL []byte, password string,
	isInvite bool) ([]byte, error) {
	if isInvite {
		return dataFromURL, nil
	}

	return decryptShareURL(dataFromURL, password)
}

// marshalPrivateURLSecrets marshals the channel's Level, Salt,
// RsaPubKeyHash, RsaPubKeyLength, RSASubPayloads, Secret, and max uses into a
// byte slice.
//
//	+---------+-------+---------------+-----------------+----------------+----------+----------+
//	| Privacy | Salt  | RsaPubKeyHash | RsaPubKeyLength | RSASubPayloads |  Secret  | Max Uses |
//	|  Level  |  32   |               |                 |                |          |          |
//	| 1 byte  | bytes |    32 bytes   |     2 bytes     |     2 bytes    | 32 bytes |  2 bytes |
//	+---------+-------+---------------+-----------------+----------------+----------+----------+
func (c *Channel) marshalPrivateURLSecrets(maxUses int) []byte {
	var buff bytes.Buffer
	buff.Grow(marshaledPrivateLen)

	// Privacy Level byte
	buff.WriteByte(byte(c.Level))

	// Salt (fixed length of saltSize)
	buff.Write(c.Salt)

	// RsaPubKeyHash
	buff.Write(c.RsaPubKeyHash)

	// RsaPubKeyLength
	b := make([]byte, rsaPubKeyLengthLen)
	binary.LittleEndian.PutUint16(b, uint16(c.RsaPubKeyLength))
	buff.Write(b)

	// RSASubPayloads
	b = make([]byte, rsaSubPayloadsLen)
	binary.LittleEndian.PutUint16(b, uint16(c.RSASubPayloads))
	buff.Write(b)

	// Secret (fixed length of secretSize)
	buff.Write(c.Secret)

	// Max uses
	b = make([]byte, maxUsesLen)
	binary.LittleEndian.PutUint16(b, uint16(maxUses))
	buff.Write(b)

	return buff.Bytes()
}

// unmarshalPrivateURLSecrets unmarshalls the byte slice into the channel's
// Level, Salt, RsaPubKeyHash, RsaPubKeyLength, RSASubPayloads, and Secret and
// returns the max uses.
func (c *Channel) unmarshalPrivateURLSecrets(data []byte) (int, error) {
	if len(data) != marshaledPrivateLen {
		return 0, errors.Errorf(
			unmarshalPrivateDataLenErr, marshaledPrivateLen, len(data))
	}

	buff := bytes.NewBuffer(data)

	c.Level = PrivacyLevel(buff.Next(privLevelLen)[0])
	c.Salt = buff.Next(saltLen)
	c.RsaPubKeyHash = buff.Next(rsaPubKeyHashLen)
	c.RsaPubKeyLength =
		int(binary.LittleEndian.Uint16(buff.Next(rsaPubKeyLengthLen)))
	c.RSASubPayloads =
		int(binary.LittleEndian.Uint16(buff.Next(rsaSubPayloadsLen)))
	c.Secret = buff.Next(secretLen)
	maxUses := int(binary.LittleEndian.Uint16(buff.Next(maxUsesLen)))

	return maxUses, nil
}

// marshalSecretURLSecrets marshals the channel's Level, Name, Description,
// Salt, RsaPubKeyHash, RsaPubKeyLength, RSASubPayloads, and Secret into a byte
// slice.
//
//	+---------+---------+-------------+------+-------------+----------+-------+---------------+-----------------+----------------+----------+----------+
//	| Privacy |  Name   | Description |      |             | Created | Salt  | RsaPubKeyHash | RsaPubKeyLength | RSASubPayloads |  Secret  | Max Uses |
//	|  Level  | Length  |   Length    | Name | Description |         |  32   |               |                 |                |          |          |
//	| 1 byte  | 2 bytes |   2 bytes   |      |             | 8 bytes | bytes |    32 bytes   |     2 bytes     |     2 bytes    | 32 bytes |  2 bytes |
//	+---------+---------+-------------+------+-------------+----------+-------+---------------+-----------------+----------------+----------+----------+
func (c *Channel) marshalSecretURLSecrets(maxUses int) []byte {
	var buff bytes.Buffer
	buff.Grow(len(c.Name) + len(c.Description) + marshaledSecretLen)

	// Privacy Level byte
	buff.WriteByte(byte(c.Level))

	// Length of Name
	b := make([]byte, nameLengthLen)
	binary.LittleEndian.PutUint16(b, uint16(len(c.Name)))
	buff.Write(b)

	// Length of Description
	b = make([]byte, descLengthLen)
	binary.LittleEndian.PutUint16(b, uint16(len(c.Description)))
	buff.Write(b)

	// Name
	buff.WriteString(c.Name)

	// Description
	buff.WriteString(c.Description)

	// Creation date
	b = make([]byte, createdLen)
	binary.LittleEndian.PutUint64(b, uint64(c.Created.UnixNano()))
	buff.Write(b)

	// Salt (fixed length of saltSize)
	buff.Write(c.Salt)

	// RsaPubKeyHash
	buff.Write(c.RsaPubKeyHash)

	// RsaPubKeyLength
	b = make([]byte, rsaPubKeyLengthLen)
	binary.LittleEndian.PutUint16(b, uint16(c.RsaPubKeyLength))
	buff.Write(b)

	// RSASubPayloads
	b = make([]byte, rsaSubPayloadsLen)
	binary.LittleEndian.PutUint16(b, uint16(c.RSASubPayloads))
	buff.Write(b)

	// Secret (fixed length of secretSize)
	buff.Write(c.Secret)

	// Max uses
	b = make([]byte, maxUsesLen)
	binary.LittleEndian.PutUint16(b, uint16(maxUses))
	buff.Write(b)

	return buff.Bytes()
}

// unmarshalPrivateURLSecrets unmarshalls the byte slice into the channel's
// Level, Name, Description, Salt, RsaPubKeyHash, RsaPubKeyLength,
// RSASubPayloads, and Secret and returns the max uses.
func (c *Channel) unmarshalSecretURLSecrets(data []byte) (int, error) {
	if len(data) < marshaledSecretLen {
		return 0, errors.Errorf(
			unmarshalSecretDataLenErr, marshaledSecretLen, len(data))
	}
	buff := bytes.NewBuffer(data)

	// Privacy Level
	c.Level = PrivacyLevel(buff.Next(privLevelLen)[0])

	nameLen := int(binary.LittleEndian.Uint16(buff.Next(nameLengthLen)))
	descLen := int(binary.LittleEndian.Uint16(buff.Next(descLengthLen)))

	if len(data) != marshaledSecretLen+nameLen+descLen {
		return 0, errors.Errorf(unmarshalSecretDataLenErr2,
			marshaledSecretLen+nameLen+descLen, len(data))
	}

	c.Name = string(buff.Next(nameLen))
	c.Description = string(buff.Next(descLen))
	c.Created =
		time.Unix(0, int64(binary.LittleEndian.Uint64(buff.Next(createdLen))))
	c.Salt = buff.Next(saltLen)
	c.RsaPubKeyHash = buff.Next(rsaPubKeyHashLen)
	c.RsaPubKeyLength =
		int(binary.LittleEndian.Uint16(buff.Next(rsaPubKeyLengthLen)))
	c.RSASubPayloads =
		int(binary.LittleEndian.Uint16(buff.Next(rsaSubPayloadsLen)))
	c.Secret = buff.Next(secretLen)
	maxUses := int(binary.LittleEndian.Uint16(buff.Next(maxUsesLen)))

	return maxUses, nil
}

// generatePhrasePassword generates a random English phrase to use as a
// password.
func generatePhrasePassword(numWords int, csprng io.Reader) (string, error) {
	g, err := diceware.NewGenerator(
		&diceware.GeneratorInput{RandReader: csprng})
	if err != nil {
		return "", err
	}

	words, err := g.Generate(numWords)
	if err != nil {
		return "", err
	}

	return strings.Join(words, " "), nil
}

// encryptShareURL encrypts the data for a shared URL using XChaCha20-Poly1305.
func encryptShareURL(data []byte, password string, csprng io.Reader) []byte {
	chaCipher := initChaCha20Poly1305(password)
	nonce := make([]byte, chaCipher.NonceSize())
	if _, err := io.ReadFull(csprng, nonce); err != nil {
		jww.FATAL.Panicf("Could not generate nonce %+v", err)
	}
	ciphertext := chaCipher.Seal(nonce, nonce, data, nil)
	return ciphertext
}

// decryptShareURL decrypts the encrypted data from a shared URL using
// XChaCha20-Poly1305.
func decryptShareURL(data []byte, password string) ([]byte, error) {
	chaCipher := initChaCha20Poly1305(password)
	nonceLen := chaCipher.NonceSize()
	if (len(data) - nonceLen) <= 0 {
		return nil, errors.Errorf(
			"Read %d bytes, too short to decrypt", len(data))
	}
	nonce, ciphertext := data[:nonceLen], data[nonceLen:]
	plaintext, err := chaCipher.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.Errorf("Cannot decrypt with password: %+v", err)
	}
	return plaintext, nil
}

// initChaCha20Poly1305 returns a XChaCha20-Poly1305 cipher.AEAD that uses the
// given password hashed into a 256-bit key.
func initChaCha20Poly1305(password string) cipher.AEAD {
	pwHash := blake2b.Sum256([]byte(password))
	chaCipher, err := chacha20poly1305.NewX(pwHash[:])
	if err != nil {
		jww.FATAL.Panicf("Could not init XChaCha20Poly1305 mode: %+v", err)
	}

	return chaCipher
}
