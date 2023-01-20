////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package rsa

import (
	"bytes"
	"crypto/rand"
	"testing"
)

const pemStrPKSC1 = `-----BEGIN RSA PRIVATE KEY-----
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

const pemStrPKSC8 = `-----BEGIN PRIVATE KEY-----
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
OfR7UYEP1zZHdxx0mMq8Dpv6wg0P4+g=
-----END PRIVATE KEY-----`

// junkPemStr1 is an un-parseable PEM string. This is invalid from the beginning
// of the string.
const junkPemStr1 = `-----BEGIN JUNK KEY-----
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

// junkPemStr2 is an un-parseable PEM string. This is similar to pemStrPKSC1 but
// the ending of every line has been overwritten with the string "NNNNN".
const junkPemStr2 = `-----BEGIN RSA PRIVATE KEY-----
MIIBygIBAAJhALhySvzEqx4l+18WYAqUwiipIU4CixehO75s8Q1W8bNKGNZRoVpW
NDuoTZOvjESzF0wMB5hyaCsLIDiyPRT5EolqkJcy2HVnXKq3HdcMIGu+NVjNNNNN
8uAH06nfevMBmwIDAQABAmA2wyhkd/feUaSajMgjHBuxetW6laK6d1KHrUyNNNNN
74IET+Q6MBH+DHBMAvkAhLNLAk5oNwgHIVq/xvCsV17WacwD+UEpQTKc5NxNNNNN
tCVzqwzQiKkWPukSCIYbpdECMQDcq8u4L4kx/UFKzQcUGINaTVCEWulISKUNNNNN
reX08kYZ4uAnEmHjZ7sMxIhvSFcCMQDV+dS/iP3+biArvDWQyGoqFII6S+GNNNNN
wW/wrNM2Ze4JtEodjs60lIcCz4g71l0CMG8Pp8BTbGFUbQAQoHdkvvc74kINNNNN
MbzZR0gUBaB6Lv3oSZhgkBO7qVCLuX8IkQIwJHGKlJymdeEXxZsmnGQmAMjNNNNN
KKEGe30Ura8hwhAWPLziKqqZ9hOd8xKZp2dZAjEAwR/qt7tEmsMkxCbAwxxNNNNN
swZpBfpbLyN2FfSAD64GQ1N5bOhAS9O2hp0WkNhM
-----END RSA PRIVATE KEY-----
`

// Some test.
func TestPemSmokePKCS1(t *testing.T) {
	pkBytes := []byte(pemStrPKSC1)
	sLocal := GetScheme()
	// Load and store, make sure we get what we put in
	pk, err := sLocal.UnmarshalPrivateKeyPEM(pkBytes)
	if err != nil {
		t.Error(err)
	}
	pkBytesOut := pk.MarshalPem()
	if !bytes.Equal(pkBytes, pkBytesOut) {
		t.Errorf("Private key mismatch.\nexpected: %v\nreceived: %v",
			pkBytes, pkBytesOut)
	}

	pkPub := pk.Public()
	pkPubBytes := pkPub.MarshalPem()
	pkPubBytesIn, err := sLocal.UnmarshalPublicKeyPEM(pkPubBytes)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(pkBytes, pkBytesOut) {
		t.Errorf("Private key mismatch.\nexpected: %v\nreceived: %v",
			pkPubBytes, pkPubBytesIn)
	}
}

// Smoke test.
func TestPemSmokePKCS8(t *testing.T) {
	pkBytes := []byte(pemStrPKSC8)
	sLocal := GetScheme()
	// Load and store, make sure we get what we put in
	_, err := sLocal.UnmarshalPrivateKeyPEM(pkBytes)
	if err != nil {
		t.Error(err)
	}
}

// Error case.
func TestEmptyPem(t *testing.T) {
	pkBytes := []byte{0, 0, 0, 0}
	sLocal := GetScheme()
	_, err := sLocal.UnmarshalPrivateKeyPEM(pkBytes)
	if err == nil {
		t.Error("Generated RSA PrivKey from empty file!")
	}

	_, err = sLocal.UnmarshalPrivateKeyPEM(pkBytes)
	if err == nil {
		t.Error("Generated RSA PubKey from empty file!")
	}
}

// Error test.
func TestJunkPem(t *testing.T) {
	// Test with the obviously invalid junk
	pkBytes := []byte(junkPemStr1)
	sLocal := GetScheme()

	_, err := sLocal.UnmarshalPrivateKeyPEM(pkBytes)
	if err == nil {
		t.Error("Generated RSA PrivKey from junk file!")
	}

	_, err = sLocal.UnmarshalPublicKeyPEM(pkBytes)
	if err == nil {
		t.Error("Generated RSA PubKey from junk file!")
	}

	// Test with the junk that is subtly invalid.
	// Specifically, these two tests reach the error cases where blocks are
	// continuously read after the first pem.Decode.
	pkBytes = []byte(junkPemStr2)

	_, err = sLocal.UnmarshalPrivateKeyPEM(pkBytes)
	if err == nil {
		t.Errorf("Generated RSA PrivKey from junk file!")
	}

	_, err = sLocal.UnmarshalPublicKeyPEM(pkBytes)
	if err == nil {
		t.Errorf("Generated RSA PubKey from junk file!")

	}
}

// Smoke test.
func TestScheme_GenerateDefault(t *testing.T) {
	sLocal := GetScheme()
	rng := rand.Reader

	privKey, err := sLocal.GenerateDefault(rng)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	if privKey.Size() != defaultRSABitLen/8 {
		t.Fatalf("Scheme.GenerateDefault() error: Did not generate key of "+
			"proper size.\nexpected: %d\nreceived: %d",
			privKey.Size(), defaultRSABitLen/8)
	}
}

// Smoke test.
func TestScheme_GetDefaultKeySize(t *testing.T) {
	sLocal := GetScheme()

	if sLocal.GetDefaultKeySize() != defaultRSABitLen {
		t.Fatalf("GetDefaultKeySize did not return the hardcoded value."+
			"\nexpected: %d\nreceived: %d",
			defaultRSABitLen, sLocal.GetDefaultKeySize())
	}

}

// Smoke test.
func TestScheme_GetSoftMinKeySize(t *testing.T) {
	sLocal := GetScheme()

	if sLocal.GetSoftMinKeySize() != softMinRSABitLen {
		t.Fatalf("GetSoftMinKeySize did not return the hardcoded value."+
			"\nexpected: %d\nreceived: %d",
			softMinRSABitLen, sLocal.GetSoftMinKeySize())
	}
}
