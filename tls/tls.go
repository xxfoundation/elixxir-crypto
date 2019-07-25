package tls

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
)

func LoadCSR(csrContents string) (*x509.CertificateRequest, error) {
	certDecoded, _ := pem.Decode([]byte(csrContents))
	if certDecoded == nil {
		err := errors.New("Decoding PEM Failed")
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(certDecoded.Bytes)
	if err != nil {
		return nil, err
	}
	return csr, nil
}

func LoadCertificate(certContents string) (*x509.Certificate, error) {
	certDecoded, _ := pem.Decode([]byte(certContents))
	if certDecoded == nil {
		err := errors.New("Decoding PEM Failed")
		return nil, err
	}
	cert, err := x509.ParseCertificate(certDecoded.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}
