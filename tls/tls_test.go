////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////
package tls

import (
	"testing"
)

const Cert = `-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----
`

const PrivateKey = `-----BEGIN RSA PRIVATE KEY-----
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

//pass an empty file into the loaders
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

//Pass incorrectly formated contents into the loaders
func TestLoadIncorrectly(t *testing.T) {
	//Pass the private key into the certificate loader
	_, err := LoadCertificate(PrivateKey)
	if err == nil {
		t.Error("Failed to detect passing in a non-certificate into LoadCertificate")
	}
	//Pass the request into the private key loader
	_, err = LoadRSAPrivateKey(Cert)
	if err == nil {
		t.Error("Failed to detect passing a non-private key into LoadRSAPrivateKey")
	}
}

//pass everything as intended. No errors should occur in this test
func TestTLS_SmokeTest(t *testing.T) {
	cert, err := LoadCertificate(Cert)
	if err != nil {
		t.Error(err.Error())
	}

	privKey, err := LoadRSAPrivateKey(PrivateKey)
	if err != nil {
		t.Errorf("Unable to load private key: %+v", err.Error())
	}

	if cert == nil {
		t.Error("Failed to load a correctly formatted Certificate")
	}

	if privKey == nil {
		t.Error("Failed to load a correctly formatted private key")

	}

}
