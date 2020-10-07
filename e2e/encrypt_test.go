////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package e2e

import (
	b64 "encoding/base64"
	"errors"
	"fmt"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/large"
	"math/rand"
	"os"
	"reflect"
	"testing"
)

var grp *cyclic.Group
var primeLength int
// Build global group for tests to utilise
func TestMain(m *testing.M) {
	// Create group
	primeString := "E2EE983D031DC1DB6F1A7A67DF0E9A8E5561DB8E8D49413394C049B" +
		"7A8ACCEDC298708F121951D9CF920EC5D146727AA4AE535B0922C688B55B3DD2AE" +
		"DF6C01C94764DAB937935AA83BE36E67760713AB44A6337C20E7861575E745D31F" +
		"8B9E9AD8412118C62A3E2E29DF46B0864D0C951C394A5CBBDC6ADC718DD2A3E041" +
		"023DBB5AB23EBB4742DE9C1687B5B34FA48C3521632C4A530E8FFB1BC51DADDF45" +
		"3B0B2717C2BC6669ED76B4BDD5C9FF558E88F26E5785302BEDBCA23EAC5ACE9209" +
		"6EE8A60642FB61E8F3D24990B8CB12EE448EEF78E184C7242DD161C7738F32BF29" +
		"A841698978825B4111B4BC3E1E198455095958333D776D8B2BEEED3A1A1A221A6E" +
		"37E664A64B83981C46FFDDC1A45E3D5211AAF8BFBC072768C4F50D7D7803D2D4F2" +
		"78DE8014A47323631D7E064DE81C0C6BFA43EF0E6998860F1390B5D3FEACAF1696" +
		"015CB79C3F9C2D93D961120CD0E5F12CBB687EAB045241F96789C38E89D796138E" +
		"6319BE62E35D87B1048CA28BE389B575E994DCA755471584A09EC723742DC35873" +
		"847AEF49F66E43873"
	p := large.NewIntFromString(primeString, 16)
	g := large.NewInt(2)
	grp = cyclic.NewGroup(p, g)
	primeLength = grp.GetP().ByteLen()
	os.Exit(m.Run())
}

// Tests the functionality of Encrypt() and Decrypt() by encrypting a message
// and check that it is the same when decrypting
func TestEncryptDecrypt(t *testing.T) {
	// Create key and message
	key := grp.NewInt(2)
	msg := []byte{5, 12, 11}

	// Encrypt key
	encMsg, err := Encrypt(grp, key, msg)

	if err != nil {
		t.Errorf("Encrypt() produced an unexpected error\n\treceived: %v\n\texpected: %v", err, nil)
	}

	// Decrypt key
	dncMsg, err := Decrypt(grp, key, encMsg)

	if !reflect.DeepEqual(dncMsg, msg) {
		t.Errorf("Encrypt() did not encrypt the message correctly\n\treceived: %v\n\texpected: %v", dncMsg, msg)
	}
}

// Checks that leading zeroes in a message are not stripped
func TestEncryptDecrypt_LeadingZeroes(t *testing.T) {

	// Create key and message
	key := grp.NewInt(3)
	msg := []byte{0, 0, 11, 5, 255, 0}

	// Encrypt key
	encMsg, err := Encrypt(grp, key, msg)

	if err != nil {
		t.Errorf("Encrypt() produced an unexpected error\n\treceived: %v\n\texpected: %v", err, nil)
	}

	// Decrypt key
	dncMsg, err := Decrypt(grp, key, encMsg)

	if !reflect.DeepEqual(dncMsg, msg) {
		t.Errorf("Encrypt() did not encrypt the message correctly\n\treceived: %v\n\texpected: %v", dncMsg, msg)
	}
}

// Ensures that encrypted messages are consistency encrypted to the same value
// (when replacing the random number generater with a pseudo one)
func TestEncrypt_Consistency(t *testing.T) {
	// Set up expected values with base64 encoding
	expectedMsgs := []string{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEfjIUiZFOoMt" +
		"p3sak059svDbzLIWSxPXWZ3sYgpK5ImY4vOxyKinAQaoB2lSqNeENJQxOL9AfIPp6op/pRu" +
		"jO92IyJRkhuriwO5STbbE7dPGhMQh8FbdY5NdZHgvC+PheVaiRjBl0omX9K/772/6LmiePS" +
		"C2zQWr8AD9wCMKpu8UI0VzU5aEeSa6+LS2xhlhZ5YRPFl3CU/xBF+H3HS4pKVQW+l55NG/B" +
		"FByu42/diSZvEX0V2BvgDqjnhKZnGqqZY6+L8sStHRqu+25UF7C0xE7yzwH2QELpmJ1Z39T" +
		"Ht+eoM3slVgQ/PSgaOAoLOJUBLZpeorKHB9aeUZmy55JB+QNOFAlsAAA",
		// Second element
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABxDYvU0XUQGV6d6tEis7PK0LUgXTdCXqNE0h8" +
		"3IqpcV9p3bNjbb69OVL5HS6hVKyXmlE1oWMU2n+3h1tYw04drUgHBO0b33Hq+wNGOg+vwIny8" +
		"iUNQAkkNcxHNwoMtOa81TOwJw+FFzKbTIYXA62ioCOYeFcpLzf0hQew4k42FAA9HWab+D6bsa7" +
		"m6hxACRhzN8g8YbP2RzHGs3iq+YBpkNejCI2pRmzy+rY1FVQdWUl7Ww8jFzFnEvWRcp9VXboPn3" +
		"4mN6RBsPwsgcO4HOEoTFcvgg77IpkcYX01MaGU0cwsIZ0vfBil48v6GJtDy3QY64bztwHQF3sjGC" +
		"XoAYyGZZyWjXLUgAA",
			// Third element
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
		"AAAAAAAAAAAAAAAAAAAAAAAAAAACaikAjDo5cPbfQLaxEUYgzukHf79kIuvl75/hSgowl5kXHUkYHg" +
		"1PezcgZvQNWj32CkYJoCaXqYE8uJY8q/PWoJNyguHbktljoJMqC+sWZ1deM6CV4WdcwntQLfpbNAgm" +
		"EQCQy0PTzVEiav71sLoUF+BlThekxOFnIkB5W/HBmO3gcpTVPfgqXGrqNjaOw8u6CZU/kZaYzCaaUT" +
		"nzha/njg2QyV2mqutN7racgfu04p5GPJjFRgNclYx1je/ratq6rXDXEAsGXMvfWpZwVbBQAXxyiM3C3" +
		"HjataoeCvaFYft4kCWB77hLbC5MFJA2mfon7DwmxvqOW3Wt3YfsD1g/6ZoIGhjGAAA",
			// Fourth element
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
		"AAAAAAAAAAAAAAAAAAAEMiOohkEvDkAJFI16Ca0rLoBuBujPjKws9UqvEM0vhWQtje6y6eEvHfQSDgA0K/Hr" +
		"xbZW5f+5g5f8K2dbtEZ2JizzxMJZ6Z54sB9OC0TVljf0u2WVKEJm600Zs2pn862ZPwaqw8IcfTL6g5YrcWZg" +
		"OHWT0O0S/LduV8Go2oudbJ6nr5LPir/tUtQXY3Y0OpnusgZOOq7/vtMFDEigC7q+HLK0L4Qkq/V/AemW6mxGU" +
		"0nBPqIDIjmw6ktXy/A38A/tTnTN+gBZZ0yP7ASPclSQt31Xn+IXzL0ButOPaYQy2kg2PbdrjpxUFylkz6SQCH" +
		"lhc7JTF7n19kokLreNGvOhu/4C8YoPgAA",
	}
	// Generate keys and messages
	var keys []*cyclic.Int
	var msgs [][]byte
	keyPrng := rand.New(rand.NewSource(42))
	msgPrng := rand.New(rand.NewSource(69))
	for i := 0; i < len(expectedMsgs); i++ {
		msgBytes := make([]byte, 256)
		keys = append(keys, grp.NewInt(keyPrng.Int63()))
		msgPrng.Read(msgBytes[:256-2])
		msgs = append(msgs, msgBytes)
	}

	for i := 0; i < len(msgs); i++ {
		encMsg := EncryptUnsafe(grp, keys[i], msgs[i])

		// Decode base64 encoded expected message
		expectedMsg, _ := b64.StdEncoding.DecodeString(expectedMsgs[i])

		if !reflect.DeepEqual(encMsg, expectedMsg) {
			t.Errorf("EncryptUnsafe() did not produce the correct message on test %v\n\treceived: %#v\n\texpected: %#v", i, encMsg, expectedMsg)
			fmt.Println(b64.StdEncoding.EncodeToString(encMsg))
		}
	}
}

// Checks that Encrypt() correctly responds to errors
func TestEncrypt_ErrorOnLongMessage(t *testing.T) {
	// Create key and message
	rand.Seed(42)
	msgBytes := make([]byte, 4000)
	rand.Read(msgBytes)
	msg := msgBytes
	key := grp.NewInt(65)

	// Encrypt key
	encMsg, err := Encrypt(grp, key, msg)

	if err == nil {
		t.Errorf("Encrypt() did not produce the expected error\n\treceived: %#v\n\texpected: %#v", err, errors.New("message too long"))
	}

	if encMsg != nil {
		t.Errorf("Encrypt() unexpectedly produced a non-nil message on error\n\treceived: %v\n\texpected: %v", encMsg, nil)
	}
}

// Checks that Decrypt() correctly responds to errors
func TestDecrypt_ErrorOnPaddingPrefix(t *testing.T) {
	// Create key and message
	rand.Seed(42)
	msgBytes := make([]byte, 40)
	rand.Read(msgBytes)
	msg := msgBytes
	key := grp.NewInt(65)

	// Decrypt key
	dncMsg, err := Decrypt(grp, key, msg)

	if err == nil {
		t.Errorf("Decrypt() did not produce the expected error\n\treceived: %#v\n\texpected: %#v", err, errors.New("padding prefix invalid"))
	}

	if dncMsg != nil {
		t.Errorf("Decrypt() unexpectedly produced a non-nil message on error\n\treceived: %v\n\texpected: %v", dncMsg, nil)
	}
}
