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
}

func TestLoadIncorrectly(t *testing.T) {
	//Pass the CSR into the certificate request loader
	_, err := LoadCertificate(CertReq)
	if err == nil {
		t.Error("Failed to detect passing in a non-certificate into LoadCertificate")
	}
	//Pass the cert into the CSR loader
	_, err = LoadCSR(Cert)
	if err == nil {
		t.Error("Failed to detect passing a non-CSR into LoadCSR")
	}
}

func TestTLS_SmokeTest(t *testing.T) {
	cert, err := LoadCertificate(Cert)
	if err != nil {
		t.Error(err.Error())
	}
	csr, err := LoadCSR(CertReq)
	if err != nil {
		t.Error(err.Error())
	}

	if csr == nil  {
		t.Error("Failed to load a correctly formatted CSR")
	}

	if  cert == nil {
		t.Error("Failed to load a correctly formatted Certificate")
	}

}

