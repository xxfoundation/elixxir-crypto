////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package codename

import (
	"crypto/ed25519"
	"encoding/binary"
	"io"
	"strings"

	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/hash"
	"gitlab.com/elixxir/crypto/nike/ecdh"
	"golang.org/x/crypto/blake2b"
)

// Language represents possible languages to generate code names from.
type Language uint8

const (
	English Language = iota
)

// MaxCodenameLength is the maximum length, in bytes, that a codename can be.
const MaxCodenameLength = 32
const pubkeyHashingConstant = "codenamePubkeyHashingConstant"

// PrivateIdentity is a user's private identity on a channel. It contains their
// public identity and their private key.
type PrivateIdentity struct {
	Privkey ed25519.PrivateKey
	Identity
}

// Marshal creates en exportable version of the PrivateIdentity.
func (i PrivateIdentity) Marshal() []byte {
	return append([]byte{i.CodesetVersion}, append(i.Privkey, i.PubKey...)...)
}

// GetDMToken returns the DM Token for this codename identity.
// TODO: This is not yet stored in the data model, which is why it is
// computed here and accessed through this function.
func (i PrivateIdentity) GetDMToken() uint32 {
	fullToken := hashPrivateKey(i.Privkey)
	return binary.BigEndian.Uint32(fullToken[0:4])
}

// UnmarshalPrivateIdentity created a private identity from a marshaled version
func UnmarshalPrivateIdentity(data []byte) (PrivateIdentity, error) {
	if len(data) != ed25519.PrivateKeySize+ed25519.PublicKeySize+1 {
		return PrivateIdentity{}, errors.New("data to unmarshal as a " +
			"private identity is the wrong length")
	}

	version := data[0]
	// Note: The FromBytes calls make copies, so we don't need to
	// do it here.
	privKeyBytes := data[1 : 1+ed25519.PrivateKeySize]
	pubKeyBytes := data[1+ed25519.PrivateKeySize:]

	pubkey := ecdh.ECDHNIKE.NewEmptyPublicKey()
	err := pubkey.FromBytes(pubKeyBytes)
	if err != nil {
		return PrivateIdentity{}, err
	}
	edPubKey := ecdh.EcdhNike2EdwardsPublicKey(pubkey)

	privkey := ecdh.ECDHNIKE.NewEmptyPrivateKey()
	err = privkey.FromBytes(privKeyBytes)
	if err != nil {
		return PrivateIdentity{}, err
	}
	edPrivKey := ed25519.PrivateKey(privkey.Bytes())

	identity, err := ConstructIdentity(edPubKey, version)
	if err != nil {
		return PrivateIdentity{}, err
	}

	pi := PrivateIdentity{
		Privkey:  edPrivKey,
		Identity: identity,
	}

	return pi, nil
}

// Identity is the public object describing all aspects of a channel definition
type Identity struct {
	PubKey ed25519.PublicKey

	Honorific CodeNamePart
	Adjective CodeNamePart
	Noun      CodeNamePart

	Codename  string
	Color     string
	Extension string

	CodesetVersion uint8
}

// GenerateIdentity create a new channels identity from scratch and assigns
// it a codename
func GenerateIdentity(rng io.Reader) (PrivateIdentity, error) {
	pub, priv, err := ed25519.GenerateKey(rng)
	if err != nil {
		return PrivateIdentity{}, err
	}

	identity, err := ConstructIdentity(pub, currentCodesetVersion)
	if err != nil {
		return PrivateIdentity{}, err
	}

	pi := PrivateIdentity{
		Privkey:  priv,
		Identity: identity,
	}

	return pi, nil
}

// ConstructIdentity creates a codename from an extant identity for a given
// version
func ConstructIdentity(
	pub ed25519.PublicKey, codesetVersion uint8) (Identity, error) {
	constructor, exists := identityConstructorCodesets[codesetVersion]
	if !exists {
		return Identity{}, errors.Errorf(
			"%d is an invalid codeset version", codesetVersion)
	}

	id, _, err := constructor(pub)

	return id, err
}

// constructIdentityV0 is version 0 of the identity constructor.
func constructIdentityV0(pub ed25519.PublicKey) (Identity, int, error) {

	input := pub

	codename := "1234567890123456789012345678901234567890"
	var honorific CodeNamePart
	var adjective CodeNamePart
	var noun CodeNamePart

	h, _ := blake2b.New256(nil)
	c := 0
	for ; len([]rune(codename)) > MaxCodenameLength; c++ {
		h.Reset()
		h.Write(input)
		h.Write([]byte(pubkeyHashingConstant))
		input = h.Sum(nil)

		honorific = generateCodeNamePart(h, input, honorificSalt, honorifics)
		adjective = generateCodeNamePart(h, input, adjectiveSalt, adjectives)
		noun = generateCodeNamePart(h, input, nounSalt, nouns)

		if honorific.Generated != "" {
			adjective.Generated = strings.Title(adjective.Generated)
		}

		if honorific.Generated != "" || adjective.Generated != "" {
			noun.Generated = strings.Title(noun.Generated)
		}

		codename = honorific.Generated + adjective.Generated + noun.Generated
	}

	i := Identity{
		PubKey:         pub,
		Honorific:      honorific,
		Adjective:      adjective,
		Noun:           noun,
		Codename:       codename,
		Color:          generateColor(h, pub),
		Extension:      generateExtension(h, pub),
		CodesetVersion: 0,
	}
	return i, c, nil
}

// Marshal creates an exportable version of the Identity.
func (i Identity) Marshal() []byte {
	return append([]byte{i.CodesetVersion}, i.PubKey...)
}

// UnmarshalIdentity created an identity from a marshaled version
func UnmarshalIdentity(data []byte) (Identity, error) {
	if len(data) != ed25519.PublicKeySize+1 {
		return Identity{}, errors.New("data to unmarshal as an identity is " +
			"the wrong length")
	}

	version := data[0]
	pubkey := ecdh.ECDHNIKE.NewEmptyPublicKey()
	// This makes a copy so we don't need to copy here
	err := pubkey.FromBytes(data[1:])
	if err != nil {
		return Identity{}, err
	}
	edPubKey := ecdh.EcdhNike2EdwardsPublicKey(pubkey)

	return ConstructIdentity(edPubKey, version)
}

// hashPrivateKey is a helper function which generates a DM token.
// As per spec, this is just a hash of the private key.
func hashPrivateKey(privKey ed25519.PrivateKey) []byte {
	h, err := hash.NewCMixHash()
	if err != nil {
		jww.FATAL.Panicf("Failed to generate cMix hash: %+v", err)
	}

	h.Write(privKey.Seed())
	return h.Sum(nil)
}
