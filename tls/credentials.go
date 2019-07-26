package tls

import (
	gorsa "crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/mitchellh/go-homedir"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/signature/rsa"
	"google.golang.org/grpc/credentials"
	"io/ioutil"
	"strings"
)

func getFullPath(path string) string {
	if len(path) > 0 && path[0] == '~' {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			jww.FATAL.Panicf("Unable to locate home directory: %v", err)
		}
		// Append the home directory to the path
		return home + strings.TrimLeft(path, "~")
	}
	return path
}

func NewCredentialsFromPEM(certificate string, nameOverride string) credentials.TransportCredentials {
	if nameOverride == "" {
		jww.WARN.Printf("Failure to provide name override can result in" +
			" TLS connection timeouts")
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(certificate)) {
		jww.FATAL.Panicf("")
	}
	return credentials.NewClientTLSFromCert(pool, nameOverride)
}

func NewCredentialsFromFile(filePath string, nameOverride string) credentials.TransportCredentials {
	if nameOverride == "" {
		jww.WARN.Printf("Failure to provide name override can result in" +
			" TLS connection timeouts")
	}

	filePath = getFullPath(filePath)
	result, err := credentials.NewClientTLSFromFile(filePath, nameOverride)
	if err != nil {
		jww.FATAL.Panicf("Could not load TLS keys: %s", errors.New(err.Error()))
	}
	return result
}

func NewPublicKeyFromFile(filePath string) *rsa.PublicKey {
	filePath = getFullPath(filePath)
	keyBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		jww.FATAL.Panicf("Failed to read public key file at %s: %+v", filePath, err)
	}

	block, _ := pem.Decode(keyBytes)

	var cert *x509.Certificate
	cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		jww.ERROR.Printf("Error parsing PEM into certificate: %+v", err)
	}

	rsaPublicKey := cert.PublicKey.(*gorsa.PublicKey)
	return &rsa.PublicKey{
		PublicKey: *rsaPublicKey,
	}
}
