////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package broadcast

import (
	"encoding/base64"
	"github.com/pkg/errors"
	goUrl "net/url"
	"strconv"
	"time"
)

// The current version number of the invite URL structure.
const inviteVersion = 1

// InviteURL todo: docstring
func (c *Channel) InviteURL(url string, maxUses int) (string, error) {
	u, err := goUrl.Parse(url)
	if err != nil {
		return "", errors.Errorf(parseHostUrlErr, err)
	}

	q := u.Query()
	q.Set(versionKey, strconv.Itoa(inviteVersion))
	q.Set(MaxUsesKey, strconv.Itoa(maxUses))

	switch c.Level {
	case Public:
		u.RawQuery = c.encodePublicInviteURL(q).Encode()
	case Private:
		u.RawQuery = c.encodePrivateInviteURL(q, maxUses).Encode()
	case Secret:
		u.RawQuery = c.encodeSecretInviteURL(q, maxUses).Encode()
	}

	return u.String(), nil
}

// DecodeInviteURL decodes the given invite URL to a Channel. If the channel is
// Private or Secret, then a password is required. Otherwise, an error is
// returned.
func DecodeInviteURL(url string) (*Channel, error) {
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
	} else if v != inviteVersion {
		return nil, errors.Errorf(versionErr, inviteVersion, v)
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
		err = c.decodePublicInviteURL(q)
		if err != nil {
			return nil, errors.Errorf(decodePublicUrlErr, err)
		}
	case q.Has(nameKey):
		maxUses, err = c.decodePrivateInviteURL(q)
		if err != nil {
			return nil, errors.Errorf(decodePrivateUrlErr, err)
		}
	case q.Has(dataKey):
		maxUses, err = c.decodeSecretInviteURL(q)
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

// GetInviteUrlType determines the PrivacyLevel of the [Channel]'s invite URL.
func GetInviteUrlType(url string) (PrivacyLevel, error) {
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
	} else if v != inviteVersion {
		return 0, errors.Errorf(versionErr, inviteVersion, v)
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

// encodePublicInviteURL encodes the channel to a Public invite URL.
func (c *Channel) encodePublicInviteURL(q goUrl.Values) goUrl.Values {
	// For now there is no functional difference between public ShareURL and
	// public InviteURL implementation, so this encoding function acts as a
	// wrapper around ShareURL's implementation. If the implementation diverges,
	// the functionality can go here in the future without affecting the caller
	// of this function.
	return c.encodePublicShareURL(q)
}

// decodePublicInviteURL decodes the values in the url.Values from a Public share
// URL to a channel.
func (c *Channel) decodePublicInviteURL(q goUrl.Values) error {
	// For now there is no functional difference between public ShareURL and
	// public InviteURL implementation, so this decoding function acts as a
	// wrapper around ShareURL's implementation. If the implementation diverges,
	// the functionality can go here in the future without affecting the caller
	// of this function.
	return c.decodePublicShareURL(q)
}

// encodePrivateInviteURL encodes the channel to a Private invite URL.
func (c *Channel) encodePrivateInviteURL(
	q goUrl.Values, maxUses int) goUrl.Values {
	marshalledSecrets := c.marshalPrivateInviteURLSecrets(maxUses)
	q.Set(nameKey, c.Name)
	q.Set(descKey, c.Description)
	q.Set(createdKey, strconv.FormatInt(c.Created.UnixNano(), 10))
	q.Set(dataKey, base64.StdEncoding.EncodeToString(marshalledSecrets))

	return q
}

// decodePrivateInviteURL decodes the values in the url.Values from a Private
// invite URL to a channel.
func (c *Channel) decodePrivateInviteURL(q goUrl.Values) (int, error) {
	c.Name = q.Get(nameKey)
	c.Description = q.Get(descKey)

	created, err := strconv.ParseInt(q.Get(createdKey), 10, 64)
	if err != nil {
		return 0, errors.Errorf(parseCreatedErr, err)
	}
	c.Created = time.Unix(0, created)

	data, err := base64.StdEncoding.DecodeString(q.Get(dataKey))
	if err != nil {
		return 0, errors.Errorf(decodeEncryptedErr, err)
	}

	maxUses, err := c.unmarshalPrivateInviteURLSecrets(data)
	if err != nil {
		return 0, errors.Errorf(unmarshalUrlErr, err)
	}

	return maxUses, nil
}

// encodeSecretInviteURL encodes the channel to a Secret invite URL.
func (c *Channel) encodeSecretInviteURL(
	q goUrl.Values, maxUses int) goUrl.Values {
	marshalledSecrets := c.marshalSecretInviteURLSecrets(maxUses)
	q.Set(versionKey, strconv.Itoa(inviteVersion))
	q.Set(dataKey, base64.StdEncoding.EncodeToString(marshalledSecrets))

	return q
}

// decodeSecretInviteURL decodes the values in the url.Values from a Secret
// invite URL to a channel.
func (c *Channel) decodeSecretInviteURL(
	q goUrl.Values) (int, error) {
	data, err := base64.StdEncoding.DecodeString(q.Get(dataKey))
	if err != nil {
		return 0, errors.Errorf(decodeEncryptedErr, err)
	}

	maxUses, err := c.unmarshalSecretInviteURLSecrets(data)
	if err != nil {
		return 0, errors.Errorf(unmarshalUrlErr, err)
	}

	return maxUses, nil
}

// marshalPrivateInviteURLSecrets marshals the [Channel]'s relevant fields into a
// byte slice. Refer to [Channel.marshalPrivateShareUrlSecrets] for more
// information.
func (c *Channel) marshalPrivateInviteURLSecrets(maxUses int) []byte {
	// For now there is no functional difference between public ShareURL and
	// public InviteURL implementation, so this marshal function acts as a
	// wrapper around ShareURL's implementation. If the implementation diverges,
	// the functionality can go here in the future without affecting the caller
	// of this function.
	return c.marshalPrivateShareUrlSecrets(maxUses)
}

// unmarshalPrivateInviteURLSecrets unmarshalls the byte slice into the
// [Channel]'s fields and returns the max uses. Refer to
// [Channel.unmarshalPrivateShareUrlSecrets] for more information.
func (c *Channel) unmarshalPrivateInviteURLSecrets(data []byte) (int, error) {
	// For now there is no functional difference between public ShareURL and
	// public InviteURL implementation, so this unmarshal function acts as a
	// wrapper around ShareURL's implementation. If the implementation diverges,
	// the functionality can go here in the future without affecting the caller
	// of this function.
	return c.unmarshalPrivateShareUrlSecrets(data)
}

// marshalSecretInviteURLSecrets marshals the [Channel]'s relevant fields into
// a byte slice. Refer to [Channel.marshalSecretShareUrlSecrets] for more
// information.
func (c *Channel) marshalSecretInviteURLSecrets(maxUses int) []byte {
	// For now there is no functional difference between public ShareURL and
	// public InviteURL implementation, so this marshal function acts as a
	// wrapper around ShareURL's implementation. If the implementation diverges,
	// the functionality can go here in the future without affecting the caller
	// of this function.
	return c.marshalSecretShareUrlSecrets(maxUses)
}

// unmarshalSecretInviteURLSecrets unmarshalls the byte slice into the
// [Channel]'s fields and returns the max uses. Refer to
// [Channel.unmarshalSecretShareUrlSecrets] for more  information.
func (c *Channel) unmarshalSecretInviteURLSecrets(data []byte) (int, error) {
	// For now there is no functional difference between public ShareURL and
	// public InviteURL implementation, so this unmarshal function acts as a
	// wrapper around ShareURL's implementation. If the implementation diverges,
	// the functionality can go here in the future without affecting the caller
	// of this function.
	return c.unmarshalSecretShareUrlSecrets(data)
}
