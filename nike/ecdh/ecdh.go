////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

// Package ecdh provide an implementation of the Nike interface
// using X25519.
package ecdh

import (
	"errors"
	"runtime"

	"golang.org/x/crypto/curve25519"

	"gitlab.com/elixxir/crypto/nike"
	"gitlab.com/xx_network/crypto/csprng"
)

// ecdhNIKE is an implementation of the nike.Nike interface.
type ecdhNIKE struct{}

// ECDHNIKE is an implementation of the nike.Nike interface using
// X25519.
var ECDHNIKE = &ecdhNIKE{}

var _ nike.PrivateKey = (*privateKey)(nil)
var _ nike.PublicKey = (*publicKey)(nil)
var _ nike.Nike = (*ecdhNIKE)(nil)

func (d *ecdhNIKE) PublicKeySize() int {
	return curve25519.PointSize
}

func (d *ecdhNIKE) PrivateKeySize() int {
	return curve25519.ScalarSize
}

func (d *ecdhNIKE) NewEmptyPrivateKey() nike.PrivateKey {
	return &privateKey{
		privateKey: []byte{},
	}
}

func (d *ecdhNIKE) NewEmptyPublicKey() nike.PublicKey {
	return &publicKey{
		publicKey: []byte{},
	}
}

// UnmarshalBinaryPublicKey unmarshals the public key bytes.
func (d *ecdhNIKE) UnmarshalBinaryPublicKey(b []byte) (nike.PublicKey, error) {
	pubKey := d.NewEmptyPublicKey()
	err := pubKey.FromBytes(b)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

// UnmarshalBinaryPrivateKey unmarshals the public key bytes.
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
		panic(err)
	}
	if count != d.PrivateKeySize() {
		panic("rng failure")
	}

	pubKey, err := curve25519.X25519(privKey, curve25519.Basepoint)
	if err != nil {
		panic(err)
	}

	return &privateKey{
			privateKey: privKey,
		}, &publicKey{
			publicKey: pubKey,
		}
}

func (d *ecdhNIKE) DerivePublicKey(privKey nike.PrivateKey) nike.PublicKey {
	pubKey, err := curve25519.X25519(privKey.(*privateKey).privateKey, curve25519.Basepoint)
	if err != nil {
		panic(err)
	}
	return &publicKey{
		publicKey: pubKey,
	}
}

// PrivateKey is an implementation of the nike.PrivateKey interface.
type privateKey struct {
	privateKey []byte
}

func (p *privateKey) Scheme() nike.Nike {
	return ECDHNIKE
}

func (p *privateKey) DeriveSecret(pubKey nike.PublicKey) []byte {
	secret, err := curve25519.X25519(p.privateKey,
		(pubKey.(*publicKey)).publicKey)
	if err != nil {
		panic(err)
	}
	return secret
}

//go:noinline
func (p *privateKey) Reset() {
	for i := 0; i < len(p.privateKey); i++ {
		p.privateKey[i] = 0
	}
	runtime.KeepAlive(p.privateKey)
}

func (p *privateKey) Bytes() []byte {
	return p.privateKey
}

func (p *privateKey) FromBytes(data []byte) error {
	if len(data) != ECDHNIKE.PrivateKeySize() {
		return errors.New("invalid key size")
	}
	p.privateKey = data
	return nil
}

// PublicKey is an implementation of the nike.PublicKey interface.
type publicKey struct {
	publicKey []byte
}

func (p *publicKey) Scheme() nike.Nike {
	return ECDHNIKE
}

func (p *publicKey) Reset() {
	for i := 0; i < len(p.publicKey); i++ {
		p.publicKey[i] = 0
	}
	runtime.KeepAlive(p.publicKey)
}

func (p *publicKey) Bytes() []byte {
	return p.publicKey
}

func (p *publicKey) FromBytes(data []byte) error {
	if len(data) != ECDHNIKE.PublicKeySize() {
		return errors.New("invalid key size")
	}
	p.publicKey = data
	return nil
}
