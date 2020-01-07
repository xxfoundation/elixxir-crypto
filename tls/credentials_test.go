////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////
package tls

import (
	"github.com/mitchellh/go-homedir"
	"gitlab.com/elixxir/crypto/signature/rsa"
	"gitlab.com/elixxir/crypto/testkeys"
	"gitlab.com/elixxir/primitives/utils"
	"google.golang.org/grpc/credentials"
	"testing"
)

//Happy path
func TestGetFullPath(t *testing.T) {
	h, _ := homedir.Dir()
	p := "~/test/test"
	full := getFullPath(p)
	if full != h+p[1:] {
		t.Errorf("Failed")
	}
}

//Happy path
func TestNewCredentialsFromFile(t *testing.T) {
	path := testkeys.GetTestCertPath()
	var tlsCreds credentials.TransportCredentials
	tlsCreds, err := NewCredentialsFromFile(path, "")
	if err != nil {
		t.Errorf("Error setting tls credentials: %+v", err)
	}
	if tlsCreds == nil {
		t.Errorf("Failed to set tls credentials")
	}
}

//Error path
func TestNewCredentialsFromFileError(t *testing.T) {
	path := testkeys.GetTestCertPath() + "sfdk"
	_, err := NewCredentialsFromFile(path, "")
	if err == nil {
		t.Errorf("Expected to receive error, instead got: %+v", err)
	}
}

//Happy path
func TestNewCredentialsFromPEM(t *testing.T) {
	var tlsCreds credentials.TransportCredentials
	tlsCreds, err := NewCredentialsFromPEM(Cert, "")
	if err != nil {
		t.Errorf("Error setting tls credentials: %+v", err)
	}
	if tlsCreds == nil {
		t.Errorf("Failed to set tls credentials")
	}
}

//Error path
func TestNewCredentialsFromPEMError(t *testing.T) {
	_, err := NewCredentialsFromPEM("this is a cert yes", "")
	if err == nil {
		t.Errorf("Expected to receive error, instead got: %+v", err)
	}
}

//Happy path
func TestNewPublicKeyFromFile(t *testing.T) {
	path := testkeys.GetTestCertPath()
	var p *rsa.PublicKey
	p, err := NewPublicKeyFromFile(path)
	if err != nil {
		t.Errorf("Error setting tls credentials: %+v", err)
	}
	if p == nil {
		t.Errorf("Failed to set tls credentials")
	}
}

//Error path
func TestNewPublicKeyFromFileError(t *testing.T) {
	path := testkeys.GetTestCertPath() + "sdfsd"
	badCertPath := testkeys.GetTestKeyPath()
	k, err := NewPublicKeyFromFile(path)
	if err == nil {
		t.Errorf("Expected to receive error, instead got: %+v", k)
	}

	k, err = NewPublicKeyFromFile(badCertPath)
	if err == nil {
		t.Errorf("Expected to receive error, instead got: %+v", k)
	}
}

//Happy path
func TestNewPublicKeyFromPEM(t *testing.T) {
	path := testkeys.GetTestCertPath()
	filePath := getFullPath(path)
	certBytes, err := utils.ReadFile(filePath)
	if err != nil {
		t.Errorf("Failed to read public key file at %s: %+v", filePath, err)
	}

	var p *rsa.PublicKey
	p, err = NewPublicKeyFromPEM(certBytes)
	if err != nil {
		t.Errorf("Error setting tls credentials: %+v", err)
	}
	if p == nil {
		t.Errorf("Failed to set tls credentials")
	}
}

//Error path: Pass in a key rather than a cert
func TestNewPublicKeyFromPEMError(t *testing.T) {

	path := testkeys.GetTestKeyPath()
	filePath := getFullPath(path)
	keyBytes, err := utils.ReadFile(filePath)
	if err != nil {
		t.Errorf("Failed to read public key file at %s: %+v", filePath, err)
	}

	var p *rsa.PublicKey

	p, err = NewPublicKeyFromPEM(keyBytes)
	if err == nil {
		t.Errorf("Expected to receive error, instead got: %+v", p)
	}
}
