////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

// Package ecdh provide an implementation of the Nike interface
// using X25519.
package ecdh

import (
	"crypto/ed25519"
	"crypto/sha512"
	"errors"
	"runtime"

	"filippo.io/edwards25519"
	jww "github.com/spf13/jwalterweatherman"
	"golang.org/x/crypto/curve25519"

	"gitlab.com/xx_network/crypto/csprng"

	"gitlab.com/elixxir/crypto/nike"
)

type ecdhNIKE struct{}

// ECDHNIKE is an implementation of the nike.Nike interface using
// X25519.
var ECDHNIKE = &ecdhNIKE{}

var _ nike.PrivateKey = (*PrivateKey)(nil)
var _ nike.PublicKey = (*PublicKey)(nil)
var _ nike.Nike = (*ecdhNIKE)(nil)

func (d *ecdhNIKE) PublicKeySize() int {
	return curve25519.PointSize
}

func (d *ecdhNIKE) PrivateKeySize() int {
	return curve25519.ScalarSize
}

func (d *ecdhNIKE) NewEmptyPrivateKey() nike.PrivateKey {
	return &PrivateKey{
		privateKey: []byte{},
	}
}

func (d *ecdhNIKE) NewEmptyPublicKey() nike.PublicKey {
	return &PublicKey{
		publicKey: []byte{},
	}
}

func (d *ecdhNIKE) UnmarshalBinaryPublicKey(b []byte) (nike.PublicKey, error) {
	pubKey := d.NewEmptyPublicKey()
	err := pubKey.FromBytes(b)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

func (d *ecdhNIKE) UnmarshalBinaryPrivateKey(b []byte) (nike.PrivateKey, error) {
	privKey := d.NewEmptyPrivateKey()
	err := privKey.FromBytes(b)
	if err != nil {
		return nil, err
	}
	return privKey, nil
}

func (d *ecdhNIKE) NewKeypair() (nike.PrivateKey, nike.PublicKey) {
	rng := csprng.NewSystemRNG()
	privKey := make([]byte, d.PrivateKeySize())
	count, err := rng.Read(privKey)
	if err != nil {
		jww.FATAL.Panic(err)
	}
	if count != d.PrivateKeySize() {
		jww.FATAL.Panic("rng failure")
	}

	pubKey, err := curve25519.X25519(privKey, curve25519.Basepoint)
	if err != nil {
		jww.FATAL.Panic(err)
	}

	return &PrivateKey{
			privateKey: privKey,
		}, &PublicKey{
			publicKey: pubKey,
		}
}

func (d *ecdhNIKE) DerivePublicKey(privKey nike.PrivateKey) nike.PublicKey {
	pubKey, err := curve25519.X25519(privKey.(*PrivateKey).privateKey, curve25519.Basepoint)
	if err != nil {
		jww.FATAL.Panic(err)
	}
	return &PublicKey{
		publicKey: pubKey,
	}
}

// PrivateKey is an implementation of the nike.PrivateKey interface.
type PrivateKey struct {
	privateKey []byte
}

func (p *PrivateKey) Scheme() nike.Nike {
	return ECDHNIKE
}

func (p *PrivateKey) DerivePublicKey() nike.PublicKey {
	pubKey, err := curve25519.X25519(p.privateKey, curve25519.Basepoint)
	if err != nil {
		jww.FATAL.Panic(err)
	}
	return &PublicKey{
		publicKey: pubKey,
	}
}

func (p *PrivateKey) DeriveSecret(pubKey nike.PublicKey) []byte {
	secret, err := curve25519.X25519(p.privateKey,
		(pubKey.(*PublicKey)).publicKey)
	if err != nil {
		jww.FATAL.Panic(err)
	}
	return secret
}

//go:noinline
func (p *PrivateKey) Reset() {
	for i := 0; i < len(p.privateKey); i++ {
		p.privateKey[i] = 0
	}
	runtime.KeepAlive(p.privateKey)
}

func (p *PrivateKey) Bytes() []byte {
	return p.privateKey
}

func (p *PrivateKey) FromBytes(data []byte) error {
	if len(data) != ECDHNIKE.PrivateKeySize() {
		return errors.New("invalid key size")
	}
	p.privateKey = data
	return nil
}

// FromEdwards implements the edwards to montgomery
// conversion as specified in https://www.rfc-editor.org/rfc/rfc8032#section-5.1.5
func (p *PrivateKey) FromEdwards(privateKey ed25519.PrivateKey) {
	dhBytes := sha512.Sum512(privateKey[:32])
	dhBytes[0] &= 248
	dhBytes[31] &= 127
	dhBytes[31] |= 64
	err := p.FromBytes(dhBytes[:32])
	if err != nil {
		jww.FATAL.Panic(err)
	}
}

// PublicKey is an implementation of the nike.PublicKey interface.
type PublicKey struct {
	publicKey []byte
}

func (p *PublicKey) Scheme() nike.Nike {
	return ECDHNIKE
}

//go:noinline
func (p *PublicKey) Reset() {
	for i := 0; i < len(p.publicKey); i++ {
		p.publicKey[i] = 0
	}
	runtime.KeepAlive(p.publicKey)
}

func (p *PublicKey) Bytes() []byte {
	return p.publicKey
}

func (p *PublicKey) FromBytes(data []byte) error {
	if len(data) != ECDHNIKE.PublicKeySize() {
		return errors.New("invalid key size")
	}
	p.publicKey = data
	return nil
}

// FromEdwards implements the edwards to montgomery
// Per RFC 7748, EDDSA Public keys can be trivially
// converted (https://www.rfc-editor.org/rfc/rfc7748.html#page-14)
func (p *PublicKey) FromEdwards(publicKey ed25519.PublicKey) {
	ed_pub, _ := new(edwards25519.Point).SetBytes(publicKey)
	p.FromBytes(ed_pub.BytesMontgomery())
}
