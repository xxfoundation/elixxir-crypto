////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package channel

import (
	"crypto/ed25519"
	"io"

	"gitlab.com/elixxir/crypto/codename"
)

// A channel identity is a wrapper around a codename.Identity (or
// codename.PrivateIdentity)

// PrivateIdentity for a channel is identical to a codename PrivateIdentity.
type PrivateIdentity struct {
	codename.PrivateIdentity
}

// Identity for a channel is identical to a codename PrivateIdentity.
type Identity struct {
	codename.Identity
}

// GetIdentity returns a channel identity object from the PrivateIdentity
func (pi *PrivateIdentity) GetIdentity() Identity {
	return Identity{pi.Identity}
}

// GenerateIdentity create a new channels identity from scratch and assigns
// it a codename
func GenerateIdentity(rng io.Reader) (PrivateIdentity, error) {
	cpi, err := codename.GenerateIdentity(rng)
	return PrivateIdentity{cpi}, err
}

// ConstructIdentity creates a codename from an extant identity for a given
// version
func ConstructIdentity(pub ed25519.PublicKey, codesetVersion uint8) (Identity,
	error) {
	id, err := codename.ConstructIdentity(pub, codesetVersion)
	return Identity{id}, err
}

// UnmarshalIdentity created an identity from a marshaled version
func UnmarshalIdentity(data []byte) (Identity, error) {
	id, err := codename.UnmarshalIdentity(data)
	return Identity{id}, err
}

// UnmarshalPrivateIdentity creates a private identity from a marshaled version
func UnmarshalPrivateIdentity(data []byte) (PrivateIdentity, error) {
	id, err := codename.UnmarshalPrivateIdentity(data)
	return PrivateIdentity{id}, err
}
