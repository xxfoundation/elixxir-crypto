package fingerprint

import (
	"bytes"
	"encoding/base64"
	"gitlab.com/xx_network/primitives/id"
	"math/rand"
	"testing"
)

// Test IdentityFP properties.
func TestIdentityFP(t *testing.T) {
	message1 := []byte("I'm an encrypted message!")
	message2 := []byte("I'm an encrypted message?")
	user1 := id.NewIdFromString("zezima", id.User, t)
	user2 := id.NewIdFromString("zez1ma", id.User, t)

	// Check that two fingerprints created from the same data are identical
	fp1 := IdentityFP(message1, user1[:])
	fp2 := IdentityFP(message1, user1[:])
	if !bytes.Equal(fp1, fp2) {
		t.Errorf("ID1 [%+v] and ID2 [%+v] were composed from the same data, "+
			"should have been identical", fp1, fp2)
	}

	// Ensure that changing the message data alters the fingerprint
	fp3 := IdentityFP(message2, user1[:])
	if bytes.Equal(fp1, fp3) {
		t.Errorf("ID1 [%+v] and ID3 [%+v] had different messages, should have "+
			"been different", fp1, fp3)
	}

	// Ensure that changing the user data alters the fingerprint
	fp4 := IdentityFP(message1, user2[:])
	if bytes.Equal(fp1, fp4) {
		t.Errorf("ID1 [%+v] and ID4[%+v] had different users, should have "+
			"been different", fp1, fp4)
	}

	// Extra test case
	fp5 := IdentityFP(message2, user2[:])
	if bytes.Equal(fp5, fp1) || bytes.Equal(fp5, fp3) || bytes.Equal(fp5, fp4) {
		t.Errorf("Something went wrong: IDs generated with different data "+
			"should not be identical.\n\tID1 [%+v]\n\tID2 [%+v]\n\tID3 [%+v]"+
			"\n\tID4 [%+v]\n\tID5 [%+v]\n", fp1, fp2, fp3, fp4, fp5)
	}
}

// Check consistency of IdentityFP output.
func TestIdentityFP_Consistency(t *testing.T) {
	prng := rand.New(rand.NewSource(42))

	expectedFps := []string{
		"RoWR2y1b6oaY753In/TmwWXtMMDxHmXZkQ==",
		"hpwv7hV+cRMmqdiEmSzP4aSwKFozBMxxKw==",
		"1WvBEV8bdzy5uwaqABsYoWybzcEUerSCEQ==",
		"dMN3/g67C/KQa27wrRu314lsmHuoH5P3Bg==",
		"oHklikqdj6/zlWTQQA+flurfg/Mwt+JCaw==",
		"0dQV3uwDPXb/Del7REKvi03wEt/Gk608Ug==",
		"eKAbXHQhjWUPCXeGksG9qyYsHzxr3R5ieQ==",
		"Jhjcx4gz1b8BrXHn8jC8Lo/fC2OJVpTIVQ==",
		"gAhDtiC2i0Lf04zFltRAva8rDGfsjC51Gg==",
		"RcAlS0mM6Onc3lnZuhuGSBuDZ6CrTwkgDw==",
	}

	for i, expected := range expectedFps {
		msg := make([]byte, 255)
		prng.Read(msg)
		rid, _ := id.NewRandomID(prng, id.User)
		fp := IdentityFP(msg, rid[:])
		expectedFp, err := base64.StdEncoding.DecodeString(expected)
		if err != nil {
			t.Errorf("Failed to base 64 decode fingerprint %d: %+v", i, err)
		}

		if !bytes.Equal(expectedFp, fp) {
			t.Errorf("Fingerprint %d does not match expected."+
				"\nexpected: %v\nreceived: %v", i, expectedFp, fp)
		}
	}
}

// Checks that CheckIdentityFP correctly determines a fingerprint to match its
// hashed values.
func TestCheckIdentityFP(t *testing.T) {
	message := []byte("I'm an encrypted message!")
	user := id.NewIdFromString("zezima", id.User, t)

	// Check that two fingerprints created from the same data are identical
	fp := IdentityFP(message, user[:])
	ok := CheckIdentityFP(fp, message, user[:])
	if !ok {
		t.Errorf("Should have gotten ok from CheckIdentityFP. Instead got %v", ok)
	}
}

// Check consistency of GetMessageHash output.
func TestGetMessageHash_Consistency(t *testing.T) {
	prng := rand.New(rand.NewSource(42))

	expectedHashes := []string{
		"8kYNhMXZixz9mIB5shoK5G1cPMMAU2ugw0lPJLiUKN0=",
		"TZ/WFGVQTVNNNLMndvg0P4tWKPmkzQ7oxIIzBJDKn4A=",
		"30Q+aEPEBpsgMIKhs7u+iVVzoZWp0XwAHpaz1e/9LRE=",
		"/zV7LqJYXbN4CcWED8/oZIA0ZVYJsZWXkt6U63ydEvQ=",
		"VpxpxdbfLfJOmCduUSQjg0I6wfetsgS+uwK+jLbMHsE=",
		"8FBwvrMzCyCAo5iDn0mV7/nDXBystXWMXYhPl4THItc=",
		"Oj7TZbf219pGOHQGLWMZfjf5P7Om0j3VETRJIfA4HSQ=",
		"H5XMkZ5+6Cwi/ETN5kfHGWIs8q1rKCBI5c7N/gFskuQ=",
		"qDmLWNRy8IoNCk2IYmWMI3iLJP2lzp0lbA1NYBSIQNQ=",
		"8FHeD1SpMUQDS/DJV9WmjNd/RNWLXSwXtA3py1vaE7w=",
	}

	for i, hashString := range expectedHashes {
		msg := make([]byte, 255)
		prng.Read(msg)
		hashedMsg := GetMessageHash(msg)
		expectedHash, err := base64.StdEncoding.DecodeString(hashString)
		if err != nil {
			t.Errorf("Failed to base 64 decode message hash %d: %+v", i, err)
		}

		if !bytes.Equal(expectedHash, hashedMsg) {
			t.Errorf("Message hash %d does not match expected."+
				"\nexpected: %v\nreceived: %v", i, expectedHash, hashedMsg)
		}
	}
}

// Checks that CheckIdentityFP correctly determines that a fingerprint generated
// from IdentityFP matches the user and a hash of the message is was generated
// from
func TestCheckIdentityFpFromMessageHash(t *testing.T) {
	message := []byte("I'm an encrypted message!")
	user := id.NewIdFromString("zezima", id.User, t)

	// Check that two fingerprints created from the same data are identical
	fp := IdentityFP(message, user[:])
	ok := CheckIdentityFpFromMessageHash(fp, GetMessageHash(message), user[:])
	if !ok {
		t.Error("CheckIdentityFpFromMessageHash() did not correctly determine " +
			"the fingerprint to match the hashed message and user ID.")
	}
}
