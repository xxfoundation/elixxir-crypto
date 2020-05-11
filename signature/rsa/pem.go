////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

// Package rsa pem.go imports and exports to pem files.
package rsa

import (
	gorsa "crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// LoadPrivateKeyFromPem decodes and produces an RSA PrivateKey in PKCS#1 PEM
// format
// Usage:
//    pem := ioutil.ReadFile("pemfile.pem")
//    privateKey, err := LoadPrivateKeyFromPem(pem)
func LoadPrivateKeyFromPem(pemBytes []byte) (*PrivateKey, error) {
	block, rest := pem.Decode(pemBytes)

	//handles if structged as a PEM in a PEM
	if block == nil {
		block, _ = pem.Decode(rest)
		if block == nil {
			return nil, errors.New("could not decode PEM")
		}
	}

	var key interface{}
	var err error

	//decodes the pem depending on type
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	}

	if err != nil {
		return nil, errors.New(
			fmt.Sprintf("could not decode key from PEM: %+v", err))
	}

	keyRSA, success := key.(*gorsa.PrivateKey)

	if !success {
		return nil, errors.New("decoded key is not an RSA key")
	}

	return &PrivateKey{*keyRSA}, nil
}

// LoadPublicKeyFromPem decodes and produces an RSA PublicKey in PKCS#1 PEM
// format
func LoadPublicKeyFromPem(pemBytes []byte) (*PublicKey, error) {
	block, rest := pem.Decode(pemBytes)
	for block != nil && block.Type != "RSA PUBLIC KEY" {
		block, rest = pem.Decode(rest)
	}
	if block == nil {
		return nil, errors.New("No RSA PUBLIC KEY block in PEM file")
	}

	key, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return &PublicKey{*key}, nil
}

// CreatePrivateKeyPem creates a PEM file from a private key
func CreatePrivateKeyPem(k *PrivateKey) []byte {
	// Note we have to dig into the wrappers .PrivateKey object here
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(&k.PrivateKey),
	}
	pemBytes := pem.EncodeToMemory(block)
	return pemBytes[:len(pemBytes)-1] // Strip newline
}

// CreatePrivateKeyPem creates a PEM file from a private key
func CreatePublicKeyPem(k *PublicKey) []byte {
	// Note we have to dig into the wrappers .PrivateKey object here
	block := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&k.PublicKey),
	}
	pemBytes := pem.EncodeToMemory(block)
	return pemBytes[:len(pemBytes)-1] // Strip newline
}
