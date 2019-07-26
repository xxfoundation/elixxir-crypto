package tls

import (
	"github.com/mitchellh/go-homedir"
	"gitlab.com/elixxir/crypto/signature/rsa"
	"gitlab.com/elixxir/crypto/testkeys"
	"google.golang.org/grpc/credentials"
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
	tlsCreds = NewCredentialsFromFile(path, "")
	if tlsCreds == nil {
		t.Errorf("Failed to set tls credentials")
	}
}

func TestNewCredentialsFromPEM(t *testing.T) {
	var tlsCreds credentials.TransportCredentials
	tlsCreds = NewCredentialsFromPEM(Cert, "")
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
