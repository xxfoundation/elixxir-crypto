////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////
package tls

import (
	"fmt"
	"testing"
)

const DsaCert = `-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----
`

const Cert = `-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----
`

const PrivateKeyPKCS1 = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA5Aq+qN2Hfmj4wQIGELCiknM+VA2araI9t7BE20jTZtQ0reQt
BRsWVh3M0ZlLgZhcZzk76N2LxKXHzavWR2PPk88I0UEBEiw4/8vyvcMZ5b7J4l2A
FmObWzfKWRqa3gCOKr9s2PKxLov9ZI6n6xW6YPG0ETM79RNTU7pBGfNSmEtqJYQ2
YSsa+wfQJlWrfwhrnyT9CMIDOlRxiLiPaXV9vTvGoVxAPwfpKZQzb3tTJCiwOuny
6R0ijfUqjGvhcOec02xhK0Lbq3Mcx4q4nZaX7djOxLJ+V8zZgRwoTfWyoH0NLfpS
Qnwnzh4uwc0iYaDdah0UC+IMHrv6NcNsHfQ2QwIDAQABAoIBAQCJTuLwQLtF5STq
6jIGuKSa8+MyryJUrFznDq7XLqmDwACcN8jXyzCO19Cs39W0Ca6RxMeK9mMjHAML
lw0l3TZutHmFrdNcQt5rPz1A/4nHaTKcJ1ppoL45lYU0U62uQL1ZhfufQbpn4YjI
lJENHv8jQkX/GU9fyKwivQJYAsfXxGW5ymvj3Pny9QP0WaNAFkfgAWoL5PnHCR0j
FxmK8oP9p9jrEMnQiJj1N43TFTPwAsoFz25iBGpIjWlQtUwwdzPE+vdS6vRNFMx/
UTOYfJBVwiFNe0LM3aqvaBd024tkGbhtWk6ICHrStIdaQRWgz3u8ExQz63zQ8N1T
BxMxXW/pAoGBAPyx8HboR87Trxz0qczXhKYlEBJXhwrkyxuOZzbAblOzr5w9DQ5M
DwQRsDsMR4oGSDe1YgklUzjQUex9rR3WivdGFlZYJpnz05kfeEY2TzlIhMSsguHp
OFSJRDW8EYuPFvfX2fN+7Jm02bDrESRto4sXbhRIuplagirVxs0bjwOfAoGBAOcG
Q2CcgTIqYFe9EAtoBoGO6TKdxkHN1wCJhP0SEmab9OUODE3bG92JZBwGdueAnFH7
ghYQgPXIGOzO805sGqRlagwpbHWQgoMDdlc5Ifvfbt1QeUEgkOBbHY70tswmK7Zu
eA4LlYFFmavFaPx7KsnRTmSkRP5kdeu2ctIJWirdAoGBAI3jYDF0RfXVmOs6WinC
DiK4hui1qwcr5vwHHt94d7qaF440HaOcg4X2ZK0TPQw8cMqPF4gpJCyvlIClJNKv
SAKGoT5EaxBg/7xoFkHeduekV6CTeT5elRmqpdlCS9vAMdZipmf6KeI40U9s/ogk
5ALS2iWbnONFFff1Z5Z91fTjAoGAdthf/OlGBTqLiVc3U8bV4fxUtrc3cE6l1h7o
jQ+o66Q7HUJWzg5zjUnKeChTLtCYmgwaZaNj1Ax11gy4WZV/Nyb8oPkGVIxct20m
icRYWSwd6jglyH0qSmBVGl+FUgwo3JaDqCYJaREW9qh9U7VA08Wa4GcpHv0rNHEN
LEOnYPkCgYBdsi+iAu6KY3yeTylNKXeCY0Zj0Rj8240nAHBLZnsQW7NmCkzRrP6o
HoNrw93o8aWMfoTaHbFiIrEq/Nd/7i2iQurZL+SI2Tyu5S7bqp2Lzr3kknMVlRAs
jYe9f2NtMJWhPUps3+5Y+iFSn/FV0iy2bxw5BKN6Ovx9ztuCurY8Dg==
-----END RSA PRIVATE KEY-----
`

//An ECDSA PKCS8 private key
const ECDSA_PRIVATEKEY = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVTfeWQAwaQ2fX1RM
rzhicau6dkfnTZmRXMhSgHn1O/2hRANCAAQaG9n2s+E/HxSbEx4xn9lKQkOL7MzS
XSlHvlSAyk3CY3kfptxz2n6ybXO0tKgmQ7D3JqZ7fhRxCmqOSSqHftWc
-----END PRIVATE KEY-----
`

const RSAPrivateKeyPKCS8 = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC0evor0jCNWanE
GfkvyLno7GxsmY7fTN50BY12fIpJkaPbO+e3xheJkj4/aS4zyznDjqjp7z5X0W9u
S9l/fvfi4F87E1GYAhUQFeI8XkETYz8fyAUb9xhghWiC6h4dJoctX9G+2PYW7zTW
GL6E0PLQdQX/7yIfq5qQMMoWogg+UhosmbaRaHY9jpYwRnz24VYfzqtKQDqIhAQi
hHtU3lLVVeo+YUwGTektsMz5ZytfGqFIxuwAEf6DXSFHYKleFcfE3Qh25dDSzlIB
HZzBYweTQ1/LuwPciQ0uJiiRhsy0vZXd7cYoumrQ4uxNqBK2Lz4i1/E4hFs31hWT
x5PDcaovAgMBAAECggEBAKq8uFSiaNof29GvvKQu4Wlv2Ha4ooevIbdi1VwlH3HP
vNKXDnQ1i2jTF95HM7U96ayOFlAQy8qqUB9o1B6gUAOqvYyWjxcdyS1Jdpgjlq6v
sjTvtZ2qGb6eFqvarZhoLXOIdVV1zQEPVM3B5OKjBUKdoopngMGzRupnrZbRvLiu
vbMrXwjvWGSA+CX8LsXfM21WgDqtxlZkix2L86ZhW3H80WFp2isgjq3T0FNKV4Ng
TX6InUccZ78X+tqfumfYqsFYnbarEegJb9PMnLCeKEHt5Xo42G0nLgMCvYGFUGnC
pUo7OSi56y18UP6vXeeHBP2S0/EUqrUvOliVFxAnvBkCgYEA5EsttJQz1t8MZT8e
oE6bcfWRpQseMt7UfPhUBkGVabBNbcVwk+3G9QKUjkJfaojt9rI4M/7Ed8ezc3Od
FWT1oyIdTGH6VwJZ15eI3PCBC9uVlnphywEOqeqZhZFdxGlAaohlYVncS4tDBQZa
RVmGVLp7cHr0tAhz9Y7S8uv5N3MCgYEAymJLf5+4n9UOwFM9t+AFJEI+yQHYPiys
bdc17GaaC0p3asUgFwHiYp23L0WORqdTlFuTti1SAchDBpRmioHC4oqL+efRjhu9
S57ZRyVuSVPi2ySBU0q1mS09qVRXSW5c8hFyKkyIR1GEvYAT2Q1HOCFvwkYWWFtp
goURPHQ6e1UCgYAxm4h+AepV2bgW1CVyjkJG/Ca+53CTe0pPMaMIjP3LrozUup+g
9X1TRlFDrHaRbtnOzqFZ4xWMNa/v+YJ74Klj3ojhTTUZ7R/askoCQJy6F+gkf8l6
VGt8Tsc3eAQZJwnhXGwzQFSXcdaJY/z/rtl61d727TD5YhDYnkWGlfJcswKBgAEU
sU6HLdc8rg185FF9Esn0yJ0OM3dxiaI0igcvLRduWGDrmJZG3kykhvvrpSzfa+TY
8FsCtvNnfGQmmr2Wn9HR55l4EXhu0X375TEqFAK0Pfvpn/8v4PRmd3PWDXlI65on
WbK8IeYvm0Pf0TtRhNXZ59zjvu7N3ixiRYtLG5zZAoGAfRs2nTzAT9xl8jgrG8o+
Ht2ZSDbcmqcD+7GWCoR/aro23EYMV6DZv1HvC73Gr6ofmDZ/H+i1kuRhHawOQRJt
P/MjtbfUUWKnjVfxrrpI+IsaaHHiSvjeYi2/ATtCYF4GL6lfR2DpBXTF8cV78DYf
T3UnhGjI6VSYfYYJIhqwaqk=
-----END PRIVATE KEY-----
`

const ed25519Key = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIOCWuyHuYHEEUa334Qriq9PK9fwwtda1YJrjzqWwY9o6
-----END PRIVATE KEY-----`

//Error path: pass an empty file into the loaders
func TestEmptyFile(t *testing.T) {
	empty := ""
	//Pass the empty string into loading the certificate
	_, err := LoadCertificate(empty)
	if err == nil {
		t.Error("Generated a certificate from an empty file!")
	}

	//Pass the empty string into loading the private key
	_, err = LoadRSAPrivateKey(empty)
	if err == nil {
		t.Error("Generated a private key from an empty file!")
	}
}

//Error path: Pass incorrectly formated contents into the loaders
func TestLoadIncorrectly(t *testing.T) {
	//Pass the private key into the certificate loader
	_, err := LoadCertificate(PrivateKeyPKCS1)
	if err == nil {
		t.Error("Failed to detect passing in a non-certificate into LoadCertificate")
	}
	//Pass the request into the private key loader
	_, err = LoadRSAPrivateKey(Cert)
	if err == nil {
		t.Error("Failed to detect passing a non-private key into LoadRSAPrivateKey")
	}
}

//Happy Path: pass everything as intended. No errors should occur in this test
func TestTLS_SmokeTest(t *testing.T) {

	// Load the PKCS#1 Key
	privKey, err := LoadRSAPrivateKey(PrivateKeyPKCS1)
	if err != nil {
		t.Errorf("Unable to load private key: %+v", err.Error())
	}
	if privKey == nil || err != nil {
		t.Error("Failed to load a correctly formatted private key")

	}

	cert, err := LoadCertificate(Cert)
	if err != nil {
		t.Error(err.Error())
	}

	if cert == nil || err != nil {
		t.Error("Failed to load a correctly formatted Certificate")
	}

	//Load the PKCS#8 private key
	privKey, err = LoadRSAPrivateKey(RSAPrivateKeyPKCS8)
	if err != nil {
		t.Errorf("%+v", err)
	}

	if privKey == nil {
		t.Errorf("Failed to pull private key from PEM-encoded string")
	}

}

//Error path: Passes in an ecdsa pkcs#8 private key.
func TestTLS_IncorrectPrivateKey(t *testing.T) {
	_, err := LoadRSAPrivateKey(ECDSA_PRIVATEKEY)
	if err == nil {
		t.Errorf("Expected Error case: Should not load key of type ECDSA")

	}

	_, err = LoadRSAPrivateKey(ed25519Key)
	if err == nil {
		t.Errorf("Expected Error case: Should not load key of type ed25519")
	}
}

func TestExtractPublicKeyFromCert(t *testing.T) {
	x509Cert, err := LoadCertificate(Cert)
	if err != nil {
		t.Errorf("Failed to load certificate: %+v", err)
	}

	_, err = ExtractPublicKey(x509Cert)
	if err != nil {
		t.Errorf("Failed to extract public key from certificate: %+v", err)
	}

	dsaCert, err := LoadCertificate(DsaCert)
	if err != nil {
		t.Errorf("Failed to load certificate: %+v", err)
	}
	_, err = ExtractPublicKey(dsaCert)
	if err != nil {
		return
	}

	t.Errorf("Expected error case, should not return a DSA key!")

}
