////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package broadcast

import (
	"bytes"
	"github.com/pkg/errors"
	"strconv"
	"strings"
)

type ChannelOptions func(*Options)

func SetAdminLevel(al AdminLevel) ChannelOptions {
	return func(o *Options) {
		o.AdminLevel = al
	}
}

type Options struct {
	AdminLevel AdminLevel
}

func NewOptions() Options {
	return Options{AdminLevel: DefaultAdminLevel}
}

// Defaults for each option in Options. Note: Do not modify already set
// defaults. Doing so could break existing channels.
const (
	DefaultAdminLevel = Normal
)

// encodingOrder is an ordered list of functions that encode a single [Options]
// field. The ordering of this list is very important. All new entries should
// only be added to the end of the list. Not doing so can break existing
// channels.
//
// Each function always returns the byte encoding of a specific option to be
// used for hashing. If the option matches the default, then it returns true
// along with the encoded value.
var encodingOrder = []func(o *Options) (encoded []byte, isDefault bool){
	func(o *Options) ([]byte, bool) {
		return o.AdminLevel.Marshal(), o.AdminLevel == DefaultAdminLevel
	},
}

// encode encodes the options to be hashed. It handles the addition of future
// options by going in reverse order and ignoring defaults until custom option
// is found.
func (o *Options) encode() []byte {
	var buff bytes.Buffer
	var hitNonDefault bool
	for i := len(encodingOrder) - 1; i >= 0; i-- {
		encoded, isDefault := encodingOrder[i](o)
		if isDefault && !hitNonDefault {
			continue
		}
		hitNonDefault = true
		buff.Write(encoded)
	}

	return buff.Bytes()
}

func (o *Options) encodeForURL() string {
	var sb strings.Builder

	sb.WriteRune(rune(strconv.FormatUint(uint64(o.AdminLevel), 10)[0]))

	return sb.String()
}

func (o *Options) decodeFromURL(s string) error {
	sr := strings.NewReader(s)

	adminLevelRune, _, err := sr.ReadRune()
	if err != nil {
		return errors.Wrap(err, "failed to read admin level rune")
	}

	adminLevel, err := strconv.ParseUint(string(adminLevelRune), 10, 8)
	if err != nil {
		return errors.Wrap(err, "failed to parse admin level rune")
	}

	o.AdminLevel = AdminLevel(adminLevel)

	return nil
}

const (
	oppNumFields  = 1
	oppDelim      = '/'
	oppAdminLevel = "adminLevel:"
)

// PrettyPrint prints a human-readable serialization of this Channel that can b
// copy and pasted.
//
// Example:
//
//	adminLevel:normal
func (o *Options) PrettyPrint() string {
	fields := [oppNumFields]string{
		oppAdminLevel + o.AdminLevel.MarshalText(),
	}

	return strings.Join(fields[:], string(oppDelim))
}

// NewOptionsFromPrettyPrint creates a new [Options] given a valid pretty
// printed [Options] serialization generated using the [Options.PrettyPrint]
// method.
func NewOptionsFromPrettyPrint(p string) (Options, error) {
	opts := NewOptions()
	// Split into separate fields
	fields := strings.Split(p, string(oppDelim))
	if len(fields) != oppNumFields {
		return Options{}, errors.Errorf(
			"expected %d fields, found %d fields", oppNumFields, len(fields))
	}

	err := opts.AdminLevel.UnmarshalText(strings.TrimPrefix(fields[0], oppAdminLevel))
	if err != nil {
		return Options{}, errors.Wrap(err, "failed to unmarshal admin level")
	}

	return opts, nil
}

// AdminLevel specifies the level of control the admin has over the channel.
type AdminLevel uint8

const (
	// Normal indicates that users have normal access to read and post and the
	// admin has the ability to use admin tools such as muting and deleting.
	Normal AdminLevel = 0

	// Announcement indicates only admin messages are allowed to be posted to
	// the channel. Users can only read.
	Announcement AdminLevel = 1

	// Free indicates that users and admins can post freely; however, admins
	// cannot use any admin controls.
	Free AdminLevel = 2
)

// Marshal marshals the [AdminLevel] into a 1-byte slice.
func (al AdminLevel) Marshal() []byte {
	return []byte{byte(al)}
}

// Unmarshal unmarshalls the slice into the [AdminLevel].
func (al *AdminLevel) Unmarshal(b []byte) {
	*al = AdminLevel(b[0])
}

// MarshalText marshals the [AdminLevel] into a textual form.
func (al AdminLevel) MarshalText() string {
	switch al {
	case Normal:
		return "normal"
	case Announcement:
		return "announcement"
	case Free:
		return "free"
	default:
		return "normal"
	}
}

// UnmarshalText unmarshalls the text into the [AdminLevel].
func (al *AdminLevel) UnmarshalText(text string) error {
	switch text {
	case "normal":
		*al = Normal
	case "announcement":
		*al = Announcement
	case "free":
		*al = Free
	default:
		return errors.Errorf("invalid AdminLevel: %s", text)
	}

	return nil
}

// String returns a human-readable name for the [AdminLevel] for logging and
// debugging. This function adheres to the [fmt.Stringer] interface.
func (al AdminLevel) String() string {
	switch al {
	case Normal:
		return "normal"
	case Announcement:
		return "announcement"
	case Free:
		return "free"
	default:
		return "INVALID ADMIN LEVEL: " + strconv.Itoa(int(al))
	}
}
