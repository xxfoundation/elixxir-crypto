package sih

import (
	"bytes"
	"encoding/base64"
	"gitlab.com/elixxir/primitives/format"
	"gitlab.com/xx_network/crypto/csprng"
	"math/rand"
	"testing"
)

// Tests that Hash returns the same hash when the preimage and contents do not
// change and unique hashes when either value changes. Also checks that the
// length of the hash is format.SIHLen.
func TestHash(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	n := 100
	preimageList := make([]Preimage, n)
	contentsList := make([][]byte, n)
	hashMap := make(map[string]bool, n*n)

	for i := range preimageList {
		preimageList[i] = Preimage{}
		prng.Read(preimageList[i][:])
		contentsList[i] = make([]byte, 64)
		prng.Read(contentsList[i])
	}

	for i, preimage := range preimageList {
		for j, contents := range contentsList {
			hash1 := Hash(preimage, contents)
			hash2 := Hash(preimage, contents)

			// Check that two hashes created from the same data are identical
			if !bytes.Equal(hash1, hash2) {
				t.Errorf("Two hashes that were composed of the same data should "+
					"have been identical (%d, %d).\nhash 1: %q\nhash 2: %q",
					i, j, hash1, hash2)
			}

			// Ensure that changing the preimage or contents creates a unique
			// hash
			if hashMap[string(hash1)] {
				t.Errorf("Hash already exists in map (%d, %d).", i, j)
			}

			// Check that the length of the has is correct
			if len(hash1) != format.SIHLen {
				t.Errorf("Length of hash incorrect.\nexpected: %d\nreceived: %d",
					format.SIHLen, len(hash1))
			}
		}
	}
}

// Check consistency of the output of Hash.
func TestHash_Consistency(t *testing.T) {
	prng := rand.New(rand.NewSource(42))

	expectedHashes := []string{
		"4CpLIy6khImqGclCosBgc4xOshsMkMxUOA==",
		"7dvsR3dJAKaD3i6PgvdcC/wLOskVnpL2Mg==",
		"SRwXsKX2IVOjD/XE/F7/XCfphfP/Wnhr5Q==",
		"F7Vq94kjofLKXUWpACWD31thR8z7j8Cdbg==",
		"RC0PXHFmXm7zxsfvf37E5lvqwqPx8Su2eQ==",
		"tCK1Lr9BCIKcdxQgrPX/2ujPM0vShR6FlQ==",
		"6qhaqbVLGdby+yd+ToIS5+Nrx0FEjgomaw==",
		"AGn9sZ47Yw6wzDP2KrZ2hE5ICKmsKvtKuQ==",
		"YsKwdP7nGpoyw0vL22cajE0yDQLCjdzZyQ==",
		"WdUYc+Mw/snSrCKiGCfBzWps1E/OGVNzyw==",
	}

	for i, expected := range expectedHashes {
		preimage := Preimage{}
		prng.Read(preimage[:])
		contents := make([]byte, 64)
		prng.Read(contents)
		hash := Hash(preimage, contents)
		hashString := base64.StdEncoding.EncodeToString(hash)

		if expected != hashString {
			t.Errorf("Hash does not match expected (%d)."+
				"\nexpected: %s\nreceived: %s", i, expected, hashString)
		}
	}
}

// Tests that HashFromMessageHash returns the same hash when the preimage and
// messageHash do not change and unique hashes when either value changes. Also
// checks that the length of the hash is format.SIHLen.
func TestHashFromMessageHash(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	n := 100
	preimageList := make([]Preimage, n)
	messageHashList := make([][]byte, n)
	hashMap := make(map[string]bool, n*n)

	for i := range preimageList {
		preimageList[i] = Preimage{}
		prng.Read(preimageList[i][:])
		messageHashList[i] = make([]byte, 64)
		prng.Read(messageHashList[i])
		messageHashList[i] = GetMessageHash(messageHashList[i])
	}

	for i, preimage := range preimageList {
		for j, messageHash := range messageHashList {
			hash1 := HashFromMessageHash(preimage, messageHash)
			hash2 := HashFromMessageHash(preimage, messageHash)

			// Check that two hashes created from the same data are identical
			if !bytes.Equal(hash1, hash2) {
				t.Errorf("Two hashes that were composed of the same data should "+
					"have been identical (%d, %d).\nhash 1: %q\nhash 2: %q",
					i, j, hash1, hash2)
			}

			// Ensure that changing the preimage or contents creates a unique
			// hash
			if hashMap[string(hash1)] {
				t.Errorf("Hash already exists in map (%d, %d).", i, j)
			}

			// Check that the length of the has is correct
			if len(hash1) != format.SIHLen {
				t.Errorf("Length of hash incorrect.\nexpected: %d\nreceived: %d",
					format.SIHLen, len(hash1))
			}
		}
	}
}

// Check consistency of the output of HashFromMessageHash.
func TestHashFromMessageHash_Consistency(t *testing.T) {
	prng := rand.New(rand.NewSource(42))

	expectedHashes := []string{
		"4CpLIy6khImqGclCosBgc4xOshsMkMxUOA==",
		"7dvsR3dJAKaD3i6PgvdcC/wLOskVnpL2Mg==",
		"SRwXsKX2IVOjD/XE/F7/XCfphfP/Wnhr5Q==",
		"F7Vq94kjofLKXUWpACWD31thR8z7j8Cdbg==",
		"RC0PXHFmXm7zxsfvf37E5lvqwqPx8Su2eQ==",
		"tCK1Lr9BCIKcdxQgrPX/2ujPM0vShR6FlQ==",
		"6qhaqbVLGdby+yd+ToIS5+Nrx0FEjgomaw==",
		"AGn9sZ47Yw6wzDP2KrZ2hE5ICKmsKvtKuQ==",
		"YsKwdP7nGpoyw0vL22cajE0yDQLCjdzZyQ==",
		"WdUYc+Mw/snSrCKiGCfBzWps1E/OGVNzyw==",
	}

	for i, expected := range expectedHashes {
		preimage := Preimage{}
		prng.Read(preimage[:])
		messageHash := make([]byte, 64)
		prng.Read(messageHash)
		messageHash = GetMessageHash(messageHash)
		hash := HashFromMessageHash(preimage, messageHash)
		hashString := base64.StdEncoding.EncodeToString(hash)

		if expected != hashString {
			t.Errorf("Hash does not match expected (%d)."+
				"\nexpected: %s\nreceived: %s", i, expected, hashString)
		}
	}
}

// Tests that the preimage calculated by TestMakePreimage matches the hash of
// the identifier and tag when the tag is not set to Default.
func TestMakePreimage(t *testing.T) {
	identifier := []byte{0, 1, 2, 3}
	tag := Silent

	h := hasher()
	h.Write(identifier)
	h.Write([]byte(tag))
	var expectedPreimage Preimage
	copy(expectedPreimage[:], h.Sum(nil))

	preimage := MakePreimage(identifier, tag)

	if expectedPreimage != preimage {
		t.Errorf("Returned preimage does not match expected."+
			"\nexpected: %q\nreceived: %q", expectedPreimage, preimage)
	}
}

// Tests that the preimage calculated by TestMakePreimage matches the identifier
// when tag when the tag is set to Default.
func TestMakePreimage_TagDefault(t *testing.T) {
	identifier := []byte{0, 1, 2, 3}
	tag := Default

	var expectedPreimage Preimage
	copy(expectedPreimage[:], identifier)

	preimage := MakePreimage(identifier, tag)

	if expectedPreimage != preimage {
		t.Errorf("Returned preimage does not match the identifier."+
			"\nidentifier: %q\nreceived:   %q", expectedPreimage, preimage)
	}
}

// Tests that the preimages calculated by TestMakePreimage are unique when
// either the identifier or tag change.
func TestMakePreimage_Unique(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	n := 100
	identifierList := make([][]byte, n)
	tagList := make([]string, n)
	preimageMap := make(map[Preimage]bool, n*n)

	for i := range identifierList {
		identifierList[i] = make([]byte, 32)
		prng.Read(identifierList[i])
		tag := make([]byte, 8)
		prng.Read(tag)
		tagList[i] = string(tag)
	}

	for i, identifier := range identifierList {
		for j, tag := range tagList {
			preimage := MakePreimage(identifier, tag)
			if preimageMap[preimage] {
				t.Errorf("Preimage already exists in map (%d, %d).", i, j)
			}
		}
	}
}

// Tests that ForMe returns true for multiple values of preimage and contents.
func TestForMe(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	n := 100
	preimageList := make([]Preimage, n)
	contentsList := make([][]byte, n)

	for i := range preimageList {
		preimageList[i] = Preimage{}
		prng.Read(preimageList[i][:])
		contentsList[i] = make([]byte, 64)
		prng.Read(contentsList[i])
	}

	for i, preimage := range preimageList {
		for j, contents := range contentsList {
			hash := Hash(preimage, contents)
			if !ForMe(preimage, contents, hash) {
				t.Errorf("ForMe returned false (%d, %d).", i, j)
			}
		}
	}
}

// Tests that ForMeFromMessageHash returns true for multiple values of preimage
// and messageHash.
func TestForMeFromMessageHash(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	n := 100
	preimageList := make([]Preimage, n)
	messageHashList := make([][]byte, n)

	for i := range preimageList {
		preimageList[i] = Preimage{}
		prng.Read(preimageList[i][:])
		messageHashList[i] = make([]byte, 64)
		prng.Read(messageHashList[i])
		messageHashList[i] = GetMessageHash(messageHashList[i])
	}

	for i, preimage := range preimageList {
		for j, messageHash := range messageHashList {
			hash := HashFromMessageHash(preimage, messageHash)
			if !ForMeFromMessageHash(preimage, messageHash, hash) {
				t.Errorf("ForMeFromMessageHash returned false (%d, %d).", i, j)
			}
		}
	}
}

// Tests that GetMessageHash returns unique values for different values of the
// messagePayload.
func TestGetMessageHash_Unique(t *testing.T) {
	rng := csprng.NewSystemRNG()
	m := make(map[string]bool)

	for i := 0; i < 100; i++ {
		messagePayload := make([]byte, 32)
		_, err := rng.Read(messagePayload)
		if err != nil {
			t.Errorf("Read fail (%d): %+v", i, err)
		}

		messageHash := GetMessageHash(messagePayload)

		if m[string(messageHash)] {
			t.Errorf("Message hash already exists (%d).", i)
		} else {
			m[string(messageHash)] = true
		}
	}
}
