////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package broadcast

import (
	"github.com/pkg/errors"
	"strconv"
)

// PrivacyLevel describes the privacy level of a Channel and dedicates how much
// channel information to reveal when sharing.
type PrivacyLevel uint8

const (
	Public PrivacyLevel = iota
	Private
	Secret
)

var privacyLevelNames = map[PrivacyLevel]string{
	Public:  "Public",
	Private: "Private",
	Secret:  "Secret",
}

var privacyLevelValues = map[string]PrivacyLevel{
	"Public":  Public,
	"Private": Private,
	"Secret":  Secret,
}

// Verify returns of the PrivacyLevel is valid.
func (pl PrivacyLevel) Verify() bool {
	return pl <= Secret
}

// String returns a human-readable name for the PrivacyLevel. Used for
// debugging.
func (pl PrivacyLevel) String() string {
	name, exists := privacyLevelNames[pl]
	if !exists {
		return "INVALID PrivacyLevel: " + strconv.Itoa(int(pl))
	}

	return name
}

// Marshal marshals the PrivacyLevel into a string.
func (pl PrivacyLevel) Marshal() string {
	return privacyLevelNames[pl]
}

// UnmarshalPrivacyLevel unmarshalls the marshalled string into a PrivacyLevel.
func UnmarshalPrivacyLevel(s string) (PrivacyLevel, error) {
	pl, exists := privacyLevelValues[s]
	if !exists {
		return 0, errors.Errorf("invalid privacy level %q", s)
	}

	return pl, nil
}
