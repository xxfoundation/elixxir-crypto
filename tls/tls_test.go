package tls

import (
	"testing"
)

const Cert = `-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----
`

const CertReq = `-----BEGIN CERTIFICATE REQUEST-----
MIIErjCCApYCAQAwaTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRIwEAYDVQQH
DAlDbGFyZW1vbnQxEDAOBgNVBAoMB0VsaXh4aXIxFDASBgNVBAsMC0RldmVsb3Bt
ZW50MREwDwYDVQQDDAhjbWl4LnJpcDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
AgoCggIBAMXOJ4lDDe2USdfy8uPTiIXbQ/e4k5nXwRuktTAsbqzjiFfqs8Z8WczJ
NTy9vHYlFJhxCTldPT9GDk5dHh8ZalYBnjoMtetW5jTcKH1KHY61LgWp3tFAMQRP
nnvHStpp+glNLHKDQZz+63UwdajbjlLWVE65yclqNj+P2h3ItIkpMIoVVgkqP69W
A5SbEXWm8OEYUx5UuYIsQUmxW+ftkSq6Enzz9uv+Z1bcGjUmnAhQ2rR8/hCV+41c
hGzIIZ6DvQClzvINK+dlaNObx55OzzCXy3n9RBtSmUEQTtTeKu+H1QeMKJh+s0/9
AnNU5QT8yqzxV03oItntS14WyjXfc0aWBanMkgD/D7MzbOaNoi34BTMNnusZ9PCt
Jd05ohYQptHwgcMqpVeWvG2dF4wCPb+C9apvKgGYism7LVJFghhtpCVGmcWf1QZN
WorSX/teHG+CFwEcLLkuUK+EvFQDt0IPqp+cGf/hc/YQdj6vMWB85ZAwodoviCYH
2zllkr56LWabv14IIDwhVxY3zIyEF0GtNe/R88zhB0aMPsGgwHU5qYVgDzUmk35+
O2Cn6y8w3rIRsW5tloNFhAelIEexK8JE5p0Kzv3scT2e4+GcKY4cqNIC6py0vkun
9P9VSKIHavRVgIJ7GoMX8BwfppoGfI/kqWbl5im+9jjbz3sMXzTdAgMBAAGgADAN
BgkqhkiG9w0BAQsFAAOCAgEAK2zn0T82VhNYVP/JBckDl+jqFBTvhC2CSr0CGH5r
g2fh7NEc/i0/dQfHEuiYkG0GwAAT2oCDSuZ5aeXCzY7Sw3TO69Xjj63+DqLVu9bg
ICBhkDb3JiyMvwyBl2AFRuaXmwm4vx/cQtOdLxzAVbBjbyDkOPrivQ4R3MKQzY95
5njYQQC7CBpMNZir/H5aBLNtZZ0Av5PkJyoTg8OS9MRY9fEPHvJPXEJeO/6/aTwf
XQKZhKRD7PdV9f18K9CrjuOZvEXCNvigNggBvAIDyx6XIhjDwXXoidFvcOKboNBH
h648jwZt0pIrqnL95wpe58H/cSXARZFz4zIMSHL5KrHBL1QmhDMMBUWf+Vl8HsDE
fu8IUVE6RQCjswQdW+Q3HwMJDBjQ/VQpKwCvtjsJCXTggHDQB1Z7BkeaPF8sKFo9
6f9V4n84YV95VW0E5ux+KxJ/1APWQkT4ZqUFmC+GAqppwYUuaqfQqt5S174jx6ED
WpHsBklXRm7IjJNzBzkeSY4nZb/J4ROeEakDIZiNpqihrKB8JECJXQrC7ELnLwBH
PdcfYpASaa8SvVIR/3RB/m9FN3lhLnjCcBL2UB03zo+dtJjsPEScpm/xLOinNpLG
SINvSR+0C4xWmx2n0zTAusDKm7YuRwf/3i52Q0U2H8AVlJB2DXj9c4FxbCe7g9U5
A8Q=
-----END CERTIFICATE REQUEST-----
`

const PrivateKey = `-----BEGIN PRIVATE KEY-----
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
SfY1Wi5vbO2siizZUuyyr7jqIQr7bg==
-----END PRIVATE KEY-----
`

//pass an empty file into the loaders
func TestEmptyFile(t *testing.T) {
	empty := ""
	//Pass an empty string into loading the request
	_, err := LoadCSR(empty)
	//It should not have generated a CSR object
	if err == nil {
		t.Error("Generated a certificate request from an empty file!")
	}
	//Pass the empty string into loading the certificate
	_, err = LoadCertificate(empty)
	if err == nil {
		t.Error("Generated a certificate from an empty file!")
	}

	//Pass the empty string into loading the private key
	_, err = LoadPrivateKey(empty)
	if err == nil {
		t.Error("Generated a private key from an empty file!")
	}
}

//Pass incorrectly formated contents into the loaders
func TestLoadIncorrectly(t *testing.T) {
	//Pass the private key into the certificate loader
	_, err := LoadCertificate(PrivateKey)
	if err == nil {
		t.Error("Failed to detect passing in a non-certificate into LoadCertificate")
	}
	//Pass the cert into the CSR loader
	_, err = LoadCSR(Cert)
	if err == nil {
		t.Error("Failed to detect passing a non-CSR into LoadCSR")
	}
	//Pass the request into the private key loader
	_, err = LoadPrivateKey(CertReq)
	if err == nil {
		t.Error("Failed to detect passing a non-private key into LoadPrivateKey")
	}
}

//pass everything as intended. No errors should occur in this test
func TestTLS_SmokeTest(t *testing.T) {
	cert, err := LoadCertificate(Cert)
	if err != nil {
		t.Error(err.Error())
	}
	csr, err := LoadCSR(CertReq)
	if err != nil {
		t.Error(err.Error())
	}

	privKey, err := LoadPrivateKey(PrivateKey)

	if csr == nil {
		t.Error("Failed to load a correctly formatted CSR")
	}

	if cert == nil {
		t.Error("Failed to load a correctly formatted Certificate")
	}

	if privKey == nil {
		t.Error("Failed to load a correctly formatted private key")

	}

}
