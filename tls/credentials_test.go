package tls

import (
	"gitlab.com/elixxir/crypto/signature/rsa"
	"gitlab.com/elixxir/crypto/testkeys"
	"google.golang.org/grpc/credentials"
	"testing"
)

func TestNewCredentialsFromFile(t *testing.T) {
	path := testkeys.GetTestCertPath()
	var tlsCreds credentials.TransportCredentials
	tlsCreds = NewCredentialsFromFile(path, "*.cmix.rip")
	if tlsCreds == nil {
		t.Errorf("Failed to set tls credentials")
	}
}

func TestNewCredentialsFromPEM(t *testing.T) {
	var tlsCreds credentials.TransportCredentials
	tlsCreds = NewCredentialsFromPEM(Cert, "*.cmix.rip")
	if tlsCreds == nil {
		t.Errorf("Failed to set tls credentials")
	}
}

func TestNewPublicKeyFromFile(t *testing.T) {
	path := testkeys.GetTestCertPath()
	var p *rsa.PublicKey
	p = NewPublicKeyFromFile(path)
	if p == nil {
		t.Errorf("Failed to set tls credentials")
	}
}
