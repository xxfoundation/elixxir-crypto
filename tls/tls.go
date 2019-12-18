////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////
package tls

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// LoadCertificate takes a pem encoded certificate (ie the contents of a crt file),
// parses it and outputs an x509 certificate object
func LoadCertificate(certContents string) (*x509.Certificate, error) {
	//Decode the pem encoded cert
	certDecoded, _ := pem.Decode([]byte(certContents))
	if certDecoded == nil {
		err := errors.New("decoding PEM Failed")
		return nil, err
	}
	//Parse the cert to create a new cert object
	cert, err := x509.ParseCertificate(certDecoded.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// LoadRSAPrivateKey takes a pem encoded private key (ie the contents of a private key file),
// parses it and outputs an x509 private key object
func LoadRSAPrivateKey(privContents string) (*rsa.PrivateKey, error) {
	//Decode the pem encoded cert
	keyDecoded, _ := pem.Decode([]byte(privContents))
	if keyDecoded == nil {
		err := errors.New("decoding PEM Failed")
		return nil, err
	}
	if key, err := x509.ParsePKCS1PrivateKey(keyDecoded.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(keyDecoded.Bytes); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey:
			return key, nil
		case *ecdsa.PrivateKey:
			return nil, errors.New("found unknown or invalid private key type in PKCS#8 wrapping")
		default:
			return nil, errors.New("found unknown or invalid private key type in PKCS#8 wrapping")
		}
	}
	return nil, errors.New("failed to parse private key")
}
