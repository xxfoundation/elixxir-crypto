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
	"io"
	"runtime"

	"filippo.io/edwards25519"
	jww "github.com/spf13/jwalterweatherman"
	"golang.org/x/crypto/curve25519"

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
	return ed25519.PublicKeySize
}

func (d *ecdhNIKE) PrivateKeySize() int {
	return ed25519.PrivateKeySize
}

func (d *ecdhNIKE) NewEmptyPrivateKey() nike.PrivateKey {
	return &PrivateKey{
		edwards:    ed25519.PrivateKey{},
		privateKey: nil,
	}
}

func (d *ecdhNIKE) NewEmptyPublicKey() nike.PublicKey {
	return &PublicKey{
		edwards:   ed25519.PublicKey{},
		publicKey: nil,
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

func (d *ecdhNIKE) NewKeypair(rng io.Reader) (nike.PrivateKey, nike.PublicKey) {
	pubEdwards, privEdwards, err := ed25519.GenerateKey(rng)
	if err != nil {
		jww.FATAL.Panicf("rng failure: %+v", err)
	}

	priv := &PrivateKey{}
	priv.FromEdwards(privEdwards)
	pub := &PublicKey{}
	pub.FromEdwards(pubEdwards)

	return priv, pub
}

func (d *ecdhNIKE) DerivePublicKey(privKey nike.PrivateKey) nike.PublicKey {
	pubEdwards := privKey.(*PrivateKey).edwards.Public().(ed25519.PublicKey)
	pubKey := &PublicKey{}
	pubKey.FromEdwards(pubEdwards)
	return pubKey
}

// PrivateKey is an implementation of the nike.PrivateKey interface.
type PrivateKey struct {
	edwards    ed25519.PrivateKey
	privateKey []byte
}

func (p *PrivateKey) Scheme() nike.Nike {
	return ECDHNIKE
}

func (p *PrivateKey) DerivePublicKey() nike.PublicKey {
	return ECDHNIKE.DerivePublicKey(p)
}

func (p *PrivateKey) DeriveSecret(pubKey nike.PublicKey) []byte {
	secret, err := curve25519.X25519(p.privateKey,
		(pubKey.(*PublicKey)).publicKey)
	panicOnError(err)
	return secret
}

//go:noinline
func (p *PrivateKey) Reset() {
	for i := 0; i < len(p.edwards); i++ {
		p.edwards[i] = 0
	}
	for i := 0; i < len(p.privateKey); i++ {
		p.privateKey[i] = 0
	}
	runtime.KeepAlive(p.edwards)
	runtime.KeepAlive(p.privateKey)
}

func (p *PrivateKey) Bytes() []byte {
	res := make([]byte, ECDHNIKE.PrivateKeySize())
	copy(res, p.edwards)
	return res
}

func (p *PrivateKey) MontgomeryBytes() []byte {
	res := make([]byte, len(p.privateKey))
	copy(res, p.privateKey)
	return res
}

func (p *PrivateKey) FromBytes(data []byte) error {
	if len(data) != ECDHNIKE.PrivateKeySize() {
		return errors.New("invalid key size")
	}
	edwards := ed25519.PrivateKey(data)
	p.FromEdwards(edwards)
	return nil
}

// FromEdwards implements the edwards to montgomery
// conversion as specified in https://www.rfc-editor.org/rfc/rfc8032#section-5.1.5
func (p *PrivateKey) FromEdwards(privateKey ed25519.PrivateKey) {
	p.edwards = privateKey
	dhBytes := sha512.Sum512(privateKey[:32])
	dhBytes[0] &= 248
	dhBytes[31] &= 127
	dhBytes[31] |= 64
	p.privateKey = dhBytes[:32]
}

// PublicKey is an implementation of the nike.PublicKey interface.
type PublicKey struct {
	edwards   ed25519.PublicKey
	publicKey []byte
}

func (p *PublicKey) Scheme() nike.Nike {
	return ECDHNIKE
}

//go:noinline
func (p *PublicKey) Reset() {
	for i := 0; i < len(p.edwards); i++ {
		p.edwards[i] = 0
	}
	runtime.KeepAlive(p.edwards)
	for i := 0; i < len(p.publicKey); i++ {
		p.publicKey[i] = 0
	}
	runtime.KeepAlive(p.publicKey)
}

func (p *PublicKey) Bytes() []byte {
	res := make([]byte, ECDHNIKE.PublicKeySize())
	copy(res, p.edwards)
	return res
}

func (p *PublicKey) MontgomeryBytes() []byte {
	res := make([]byte, len(p.publicKey))
	copy(res, p.publicKey)
	return res
}

func (p *PublicKey) FromBytes(data []byte) error {
	if len(data) != ECDHNIKE.PublicKeySize() {
		return errors.New("invalid key size")
	}
	edwards := ed25519.PublicKey(data)
	p.FromEdwards(edwards)
	return nil
}

// FromEdwards implements the edwards to montgomery
// Per RFC 7748, EDDSA Public keys can be trivially
// converted (https://www.rfc-editor.org/rfc/rfc7748.html#page-14)
func (p *PublicKey) FromEdwards(publicKey ed25519.PublicKey) {
	p.edwards = publicKey
	ed_pub, _ := new(edwards25519.Point).SetBytes(publicKey)
	p.publicKey = ed_pub.BytesMontgomery()
}

// panicOnError is a helper function which will panic if the
// error is not nil. This primarily serves as a fix for
// the coverage hit by un-testable error conditions.
func panicOnError(err error) {
	if err != nil {
		jww.FATAL.Panic(err)
	}
}
