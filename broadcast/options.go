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
	jww "github.com/spf13/jwalterweatherman"
	"io"
	"strconv"
	"strings"
)

////////////////////////////////////////////////////////////////////////////////
// Channel Option Functions                                                   //
////////////////////////////////////////////////////////////////////////////////

type ChannelOptions func(*Options)

func SetAdminLevel(al AdminLevel) ChannelOptions {
	return func(o *Options) {
		o.AdminLevel = al
	}
}

////////////////////////////////////////////////////////////////////////////////
// Options Structure                                                          //
////////////////////////////////////////////////////////////////////////////////

// Options contains all the optional configuration options for channels.
type Options struct {
	// NOTE TO DEVELOPERS: When adding an option, it is very important to follow
	// the provided steps to avoid breaking existing channels.
	//
	//  1. Define a default value for the option.
	//  2. Add the field to newOptions with the default value.
	//  3. Add an encoding method for the field to encodingOrder using the
	//     default value. It must be added to the end of the list to avoid
	//     altering the order.
	//  4. Add an encoding/decoding methods for the field to urlCodingOrder. It
	//     must be added to the end of the list to avoid altering the order.
	//  5. Add encoding/decoding methods for the field to prettyPrintCoders.

	// AdminLevel describes the level of control an admin has over a channel.
	AdminLevel AdminLevel `json:"adminLevel"`
}

// newOptions returns a new Options object with all the given ChannelOptions
// applied. Any unset options are set to their defaults.
func newOptions(opts ...ChannelOptions) *Options {
	o := &Options{AdminLevel: DefaultAdminLevel}
	for _, opt := range opts {
		opt(o)
	}
	return o
}

// Defaults for each option in Options. Note: Do not modify already set
// defaults. Doing so could break existing channels.
const (
	DefaultAdminLevel = Normal
)

// encodingOrder is an ordered list of functions that encode a single Options
// field when encoding the options for hashing. The ordering of this list is
// very important. All new entries should only be added to the end of the list.
// Not doing so can break existing channels.
//
// Each function always returns the byte encoding of a specific option to be
// used for hashing. If the option matches the default, then it returns true
// along with the encoded value.
var encodingOrder = []func(o *Options) (encoded []byte, isDefault bool){
	// AdminLevel
	func(o *Options) ([]byte, bool) {
		return o.AdminLevel.marshal(), o.AdminLevel == DefaultAdminLevel
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

// urlCodingOrder is an ordered list of functions that encode and decode a
// single Options field when encoding it for a channel share URL. The ordering
// of this list is very important. All new entries should only be added to the
// end of the list. Not doing so can break existing channels.
//
// Each entry includes an encoder that must encode an option to a single rune
// and decode it back into the field.
var urlCodingOrder = []struct {
	encode func(o *Options) rune
	decode func(r rune, o *Options) error
}{
	{ // AdminLevel
		func(o *Options) rune {
			return rune(strconv.FormatUint(uint64(o.AdminLevel), 10)[0])
		},
		func(r rune, o *Options) error {
			adminLevel, err := strconv.ParseUint(string(r), 10, 8)
			if err != nil {
				return errors.Wrap(err, "failed to parse admin level rune")
			}
			o.AdminLevel = AdminLevel(adminLevel)
			return nil
		},
	},
}

// encodeForURL encodes all the options in the urlCodingOrder list to a concise
// string to be used in the Channel share URL.
func (o *Options) encodeForURL() string {
	var sb strings.Builder

	for _, coder := range urlCodingOrder {
		sb.WriteRune(coder.encode(o))
	}

	return sb.String()
}

// decodeFromURL decodes the string from the Channel share URL to the Options.
// Any runes missing from the encoding are skipped with the initial values
// unchanged. These should most likely be set to default beforehand.
func (o *Options) decodeFromURL(s string) error {
	sr := strings.NewReader(s)

	var r rune
	var err error
	for _, coder := range urlCodingOrder {
		r, _, err = sr.ReadRune()
		if err != nil {
			break
		}

		err = coder.decode(r, o)
		if err != nil {
			return errors.Wrap(err, "failed to decode option")
		}
	}

	if errors.Is(err, io.EOF) {
		// Once the end is reached, finish decoding
		return nil
	}

	return err
}

const (
	oppHead       = "["
	oppTail       = "]"
	oppDelim      = ","
	oppFieldDelim = ":"
	oppNumFields  = 1
	oppAdminLevel = "adminLevel"
)

// prettyPrintCoders is a list of functions that encode and decode a single
// Options field when encoding it for pretty print. The ordering of this list
// does not matter like the other list.
//
// Each entry includes an encoder that must encode an option to a human-readable
// string that does not contain any of the delimiters in the Channel or Options
// pretty print and decode it back into the field.
var prettyPrintCoders = []struct {
	key    string
	encode func(o *Options) string
	decode func(s string, o *Options) error
}{
	{ // AdminLevel
		oppAdminLevel,
		func(o *Options) string {
			return o.AdminLevel.marshalText()
		},
		func(s string, o *Options) error {
			adminLevel, err := unmarshalAdminLevelText(s)
			if err != nil {
				return errors.Wrap(err, "failed to unmarshal admin level")
			}
			o.AdminLevel = adminLevel
			return nil
		},
	},
}

// prettyPrint prints a human-readable serialization of this Option that can be
// included in the Channel pretty print.
//
// Example:
//
//	adminLevel:normal
func (o *Options) prettyPrint() string {
	fields := make([]string, 0, oppNumFields)
	for _, coder := range prettyPrintCoders {
		fields = append(fields, coder.key+oppFieldDelim+coder.encode(o))
	}

	return oppHead + strings.Join(fields[:], oppDelim) + oppTail
}

// newOptionsFromPrettyPrint creates a new Options given a valid pretty printed
// Options serialization generated using the Options.prettyPrint method.
func newOptionsFromPrettyPrint(p string) (*Options, error) {
	opts := newOptions()
	var err error

	// Strip the header and tail
	if !strings.HasPrefix(p, oppHead) {
		return nil, errors.New("missing header")
	}
	p = strings.TrimPrefix(p, oppHead)
	if !strings.HasSuffix(p, oppTail) {
		return nil, errors.New("missing tail")
	}
	p = strings.TrimSuffix(p, oppTail)

	// Split into separate fields and store the keys and values in a map
	fields := strings.Split(p, oppDelim)
	values := make(map[string]string, len(fields))
	for i, field := range fields {
		key, value, found := strings.Cut(field, oppFieldDelim)
		if !found {
			return nil, errors.Errorf(
				"invalid field %d of %d: %q", i+1, len(fields), field)
		}

		values[key] = value
	}

	for _, coder := range prettyPrintCoders {
		val, exists := values[coder.key]
		if exists {
			err = coder.decode(val, opts)
			if err != nil {
				return nil, errors.Wrap(err, "could not decode field")
			}
		}
	}

	return opts, nil
}

////////////////////////////////////////////////////////////////////////////////
// AdminLevel                                                                 //
////////////////////////////////////////////////////////////////////////////////

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

// marshal marshals the [AdminLevel] into a 1-byte slice.
func (al AdminLevel) marshal() []byte {
	return []byte{byte(al)}
}

// marshalText marshals the [AdminLevel] into a textual form.
func (al AdminLevel) marshalText() string {
	switch al {
	case Normal:
		return "normal"
	case Announcement:
		return "announcement"
	case Free:
		return "free"
	default:
		jww.FATAL.Panicf("Failed to marshal invalid AdminLevel: %d", al)
		return ""
	}
}

// unmarshalAdminLevelText unmarshalls the text into an [AdminLevel].
func unmarshalAdminLevelText(text string) (AdminLevel, error) {
	switch text {
	case "normal":
		return Normal, nil
	case "announcement":
		return Announcement, nil
	case "free":
		return Free, nil
	default:
		return 0, errors.Errorf("invalid AdminLevel: %s", text)
	}
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
