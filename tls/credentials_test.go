package tls

import (
	"github.com/mitchellh/go-homedir"
	"gitlab.com/elixxir/crypto/signature/rsa"
	"gitlab.com/elixxir/crypto/testkeys"
	"google.golang.org/grpc/credentials"
	"io/ioutil"
	"testing"
)

func TestGetFullPath(t *testing.T) {
	h, _ := homedir.Dir()
	p := "~/test/test"
	full := getFullPath(p)
	if full != h+p[1:] {
		t.Errorf("Failed")
	}
}

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

func TestNewCredentialsFromFileError(t *testing.T) {
	path := testkeys.GetTestCertPath() + "sfdk"
	_, err := NewCredentialsFromFile(path, "")
	if err == nil {
		t.Errorf("Expected to receive error, instead got: %+v", err)
	}
}

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

func TestNewCredentialsFromPEMError(t *testing.T) {
	_, err := NewCredentialsFromPEM("this is a cert yes", "")
	if err == nil {
		t.Errorf("Expected to receive error, instead got: %+v", err)
	}
}

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

func TestNewPublicKeyFromFileError(t *testing.T) {
	path := testkeys.GetTestCertPath() + "sdfsd"
	badCertPath := testkeys.GetTestKeyPath()
	_, err := NewPublicKeyFromFile(path)
	if err == nil {
		t.Errorf("Expected to receive error, instead got: %+v", err)
	}

	_, err2 := NewPublicKeyFromFile(badCertPath)
	if err2 == nil {
		t.Errorf("Expected to receive error, instead got: %+v", err)
	}
}

func TestNewPublicKeyFromPEM(t *testing.T) {
	path := testkeys.GetTestCertPath()
	filePath := getFullPath(path)
	keyBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		t.Errorf("Failed to read public key file at %s: %+v", filePath, err)
	}

	var p *rsa.PublicKey
	p, err = NewPublicKeyFromPEM(keyBytes)
	if err != nil {
		t.Errorf("Error setting tls credentials: %+v", err)
	}
	if p == nil {
		t.Errorf("Failed to set tls credentials")
	}
}
