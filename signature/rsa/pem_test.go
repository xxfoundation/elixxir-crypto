////////////////////////////////////////////////////////////////////////////////
// Copyright © 2019 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

// Package rsa pem.go imports and exports to pem files.
package rsa

import (
	"bytes"
	"testing"
)

const pemStr = `-----BEGIN RSA PRIVATE KEY-----
MIIBygIBAAJhALhySvzEqx4l+18WYAqUwiipIU4CixehO75s8Q1W8bNKGNZRoVpW
NDuoTZOvjESzF0wMB5hyaCsLIDiyPRT5EolqkJcy2HVnXKq3HdcMIGu+NVjUFhSZ
8uAH06nfevMBmwIDAQABAmA2wyhkd/feUaSajMgjHBuxetW6laK6d1KHrUy8iy3j
74IET+Q6MBH+DHBMAvkAhLNLAk5oNwgHIVq/xvCsV17WacwD+UEpQTKc5NxHZjij
tCVzqwzQiKkWPukSCIYbpdECMQDcq8u4L4kx/UFKzQcUGINaTVCEWulISKUXfmL7
reX08kYZ4uAnEmHjZ7sMxIhvSFcCMQDV+dS/iP3+biArvDWQyGoqFII6S+GQ0MeL
wW/wrNM2Ze4JtEodjs60lIcCz4g71l0CMG8Pp8BTbGFUbQAQoHdkvvc74kI63x4a
MbzZR0gUBaB6Lv3oSZhgkBO7qVCLuX8IkQIwJHGKlJymdeEXxZsmnGQmAMjBbWBj
KKEGe30Ura8hwhAWPLziKqqZ9hOd8xKZp2dZAjEAwR/qt7tEmsMkxCbAwxxthGCe
swZpBfpbLyN2FfSAD64GQ1N5bOhAS9O2hp0WkNhM
-----END RSA PRIVATE KEY-----`

const junkPemStr = `-----BEGIN JUNK KEY-----
MIIBygIBAAJhALhySvzEqx4l+18WYAqUwiipIU4CixehO75s8Q1W8bNKGNZRoVpW
swZpBfpbLyN2FfSAD64GQ1N5bOhAS9O2hp0WkNhM
-----END JUNK KEY-----
-----BEGIN RSA PUBLIC KEY-----
MIIBygIBAAJhALhySvzEqx4l+18WYAqUwiipIU4CixehO75s8Q1W8bNKGNZRoVpW
swZpBfpbLyN2FfSAD64GQ1N5bOhAS9O2hp0WkNhM
-----END RSA PUBLIC KEY-----
-----BEGIN RSA PRIVATE KEY-----
MIIBygIBAAJhALhySvzEqx4l+18WYAqUwiipIU4CixehO75s8Q1W8bNKGNZRoVpW
swZpBfpbLyN2FfSAD64GQ1N5bOhAS9O2hp0WkNhM
-----END RSA PRIVATE KEY-----`

func TestPemSmoke(t *testing.T) {
	pkBytes := []byte(pemStr)
	// Load and store, make sure we get what we put in
	pk, err := LoadPrivateKeyFromPem(pkBytes)
	if err != nil {
		t.Errorf("%v", err)
	}
	pkBytesOut := CreatePrivateKeyPem(pk)
	if bytes.Compare(pkBytes, pkBytesOut) != 0 {
		t.Errorf("Private Key Mismatch:\n\t%v\n\t%v",
			pkBytes, pkBytesOut)
	}

	pkPub := pk.Public().(*PublicKey)
	pkPubBytes := CreatePublicKeyPem(pkPub)
	pkPubBytesIn, err := LoadPublicKeyFromPem(pkPubBytes)
	if err != nil {
		t.Errorf("%v", err)
	}
	if bytes.Compare(pkBytes, pkBytesOut) != 0 {
		t.Errorf("Private Key Mismatch:\n\t%v\n\t%v",
			pkPubBytes, pkPubBytesIn)
	}

}

func TestEmptyPem(t *testing.T) {
	pkBytes := []byte{0, 0, 0, 0}
	_, err := LoadPrivateKeyFromPem(pkBytes)
	if err == nil {
		t.Errorf("Generated RSA PrivKey from empty file!")
	}
	_, err = LoadPublicKeyFromPem(pkBytes)
	if err == nil {
		t.Errorf("Generated RSA PubKey from empty file!")
	}
}

func TestJunkPem(t *testing.T) {
	pkBytes := []byte(junkPemStr)
	_, err := LoadPrivateKeyFromPem(pkBytes)
	if err == nil {
		t.Errorf("Generated RSA PrivKey from junk file!")
	}
	_, err = LoadPublicKeyFromPem(pkBytes)
	if err == nil {
		t.Errorf("Generated RSA PubKey from junk file!")
	}
}
