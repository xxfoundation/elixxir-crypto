///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package contact

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"fmt"
	"github.com/liyue201/goqr"
	"github.com/skip2/go-qrcode"
	"git.xx.network/elixxir/crypto/cyclic"
	"git.xx.network/elixxir/primitives/fact"
	"git.xx.network/xx_network/crypto/csprng"
	"git.xx.network/xx_network/crypto/large"
	"git.xx.network/xx_network/primitives/id"
	"image"
	"math/rand"
	"reflect"
	"strings"
	"testing"
)

// Tests marshaling and unmarshalling of a common Contact.
func TestContact_Marshal_Unmarshal(t *testing.T) {
	expectedContact := Contact{
		ID:       id.NewIdFromUInt(rand.Uint64(), id.User, t),
		DhPubKey: getCycInt(256),
		Facts: fact.FactList{
			{Fact: "myUsername", T: fact.Username},
			{Fact: "devinputvalidation@elixxir.io", T: fact.Email},
			{Fact: "6502530000US", T: fact.Phone},
			{Fact: "6502530001US", T: fact.Phone},
		},
	}

	buff := expectedContact.Marshal()

	testContact, err := Unmarshal(buff)
	if err != nil {
		t.Errorf("Unmarshal() produced an error: %+v", err)
	}

	if !reflect.DeepEqual(expectedContact, testContact) {
		t.Errorf("Unmarshaled Contact does not match expected."+
			"\nexpected: %s\nreceived: %s", expectedContact, testContact)
	}
}

// Tests marshaling and unmarshalling of a Contact with nil fields.
func TestContact_Marshal_Unmarshal_Nil(t *testing.T) {
	expectedContact := Contact{}

	buff := expectedContact.Marshal()

	testContact, err := Unmarshal(buff)
	if err != nil {
		t.Errorf("Unmarshal() produced an error: %+v", err)
	}

	if !reflect.DeepEqual(expectedContact, testContact) {
		t.Errorf("Unmarshaled Contact does not match expected."+
			"\nexpected: %#v\nreceived: %#v", expectedContact, testContact)
	}
}

// Consistency test.
func TestUnmarshal_Consistency(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	var contacts []Contact
	expectedContact := []string{
		"<xxc(2)r79ksZZ/jFMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADIAB7Ugdw/BAr6QhytEufu5cbHgAAAAAAAAAAAAAAAAAAAAACADtQyzHOSDW8804N0pzSB+pVxxc>",
		"<xxc(2)AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAB7Ugdw/BAr6TEMemGbQnZN+AMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD4AlVXQWcvWWROMXZBSzBIZlQ1R1NuaGo5cWViNExsVG5TT2dlZWVTNzF2NDB6Y3VvUSs2TlkrakUvK0hPdnFWRzJQckJQZEdxd0V6aTZpaDN4VmVjK2l4NDRiQzY4PSxVcm9oYWVHSUdGcGVLN1F6anhzVHpybnZENEVsYlZ4TCsvYjRNRUNpSDRRRGF6UzJJWDJrc3RnZmFBS0VjSEhCeDU1YWkzQzNDV2x0MHN1RXBjRjRuUHdYSkl3PT07GVdceOFLEciG0CGl3UVbeA==xxc>",
		"<xxc(2)8kFE8/1HiUkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAABmAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANQDVUpvS09Ld1U0bGszOXg1Nk5VME56Wmh6OVp0ZFA3QjRiaVVrYXR5TnVTM1VoWXBEUEsrdEN3OG9uTW9WZzhhckFaODZtNkw5RzFLc3JSb0JBTEYreWdnNklYVEpnOGQ2WGdvUFVvSm8yK1d3Z2xCZEc0KzFOcGthcHJvdFBwN1Q4T2lDNitocDE3VEo2aHJpd3c1cnh6OUt6dFJJWjZubFRPcjlFalN4SG5USmdkVE9RV1JUSXpCenduYU9lRHBLZEFrcTh2TEZwT1h1M05PZnZDbTRCOFlWTjYxL2tKUDczckNFSWtmV1g7eDWaja/NF0evpcR3qNxV1A==xxc>",
		"<xxc(2)XMCYoCcs5+sAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADIAB7Ugdw/BAr6QfDMrfm2pchAADUA1VYaWtxb3JpcUhCc2o0UnhJN1JkVG5XaGZkdktubUx4azNnNWRzb1pMS3RQQ2JPWTRJMEoyV2hQV2x1VXQ5MkQydzBaZUthRGNwR3JEb05Wd0V6dkNGWEgxOVVwa01RVlJQOWhDbXhsSzRicWZLb09Hcm5LelpoL29MQ3JHVGI5R0ZSZ2s0akJURW1OOG1jSzRmVzN3M1Y3eWcyY1pCeTFuTDJINm9MNkc5RmVTSHNOOERrWU04TmNEMEgzRjlXWWFSUUV6UUpweEsycG1xOWU2WlNKTW9tbDQyYVhPWXY2eEdvT1BGbUk9O6RVQl36jM1vIRL399UNnYo=xxc>",
		"<xxc(2)mRapMxk8GJwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADIAB7Ugdw/BAr6VYZCbc7GF5Y1gEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAOyN7y1G+sg7KnHPGnZQ3d8A=xxc>",
		"<xxc(2)AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAOz09OSin/a/ZEfCXTcBTWMU=xxc>",
		"<xxc(2)KkZsyvJsulEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADIAB7Ugdw/BAr6TXNRV0vFojthgMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADEA1U0Uy9WNFpxRnU0ZERlMEVETUZvN09HeDlOdGt0SWxTWllLY1U4cWdwNGNJQ0ZuTy9NTVVMWjUxUVZvbFZ5Y0dZQ0oyVjlnT1gwcTlmajhrUkMrT3A0U1hwUklTWGx3aldxbno4WXA2TmtVZlBMMSsyb0ZXUnE0YUhPaDZ0QmFTbVp4MXBVVnlEbmRpdk9qclhkQUxGL1RxRG9FWUlxWWt6QUNGaTNVd2Y5VlIvVjFJREh5RWg0VUVJcWxwWFJXeXVrY0Z6S2ExYXptSHE2YlpTM3pNQXRNS3JXQ2QyMkZ0bzv78oY7D1ubcpBWI+v2HiGvxxc>",
		"<xxc(2)kJxljeRro48AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADIAB7Ugdw/BAr6XPkxwFBc+E/9AEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAOxs5LQEZ2DBTc0kCVtBbABc=xxc>",
		"<xxc(2)F2j1Bc9kkS4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADIAB7Ugdw/BAr6RF2XdaknsjSbgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAsAZVeWpMVnc4OElhajdEMkxOM0FCTDlKNlMyV3dLdWhTVnZjMjdlUGszWVZ5Q1ZkYVNJMVhRTkwzSnBXbGNOdnlaSDhwWGlNNVh1MnMvMk51R3d6eURlYWhEL21VUHR5bStXdjAzYThBdWRUODFxeTl1ejlqR1VVRFdHcUtaWXJtQzE3bE9hdGEwWjhyb2ozS1puMzZaVkUweFpTaXlBYTkrazUxYmtXTFNMcmtrTkJDNEhvMVhwYlB1SnpLdnlnWjE1VFo0U2d2MEtjbFR4czVUMjZyeG1wa2k2Mzl0SDAxQ0thVGdMcGc9PSxVcllhWHB6Ump6U2dHNXE3dStTdGVtLy9rRHBSbW1RK2pyc0VlU255MnJyc1h0LzdTbFJQVEh0VC9IUmJtMVpsV0dWRmZYMU9IYVFEdEQzclI4amk3TTBRSjQ4RmtsWE9sYjBPbzRkSVRja2I4cHNZekpOUS9nK3dOVFMvV1VHL2Y3dUllSkRJOWdPZkxoRjlEMGlNaW1xUWhGRW9uMjdmRVFNSEhtUG1pVFE9PTts5t6AAeict0cNcwR7LKqdxxc>",
		"<xxc(2)qO/kc3tbpXkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADIAB7Ugdw/BAr6R1P1DZOQ0GyhgMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADQBVVMSVh4TENTSUtxWlJsVWlRdk56UFpxMDljNmpocTUrRGgzMG1PN3NuOWJ4SmU5WlVSMDNMaGlxMDNXaWJvRTBOcm1pZ2c5YWw2SFRFSE9TdWRwM2R0aUhCWkRJNXZUZUtMcEdwck9KMzhzQ05jVXZKMmVZc0JXTEtLVzRTcDNZWFJOMjRJNmd2R2JwOUNsSkxWSks3OXlyRFR2eTVDbDdmYmJ3aG43OHc3UEpmcG1iSkpHc0lIVjBzVjQ3dkFBaXdqV0dnbDJRRTlDNm9La2h6K3cxa2gzZDlwa2NHdDBoWHBaOGRLbjgyRjZPODFWcVZuOUdTQk1ManY2emc1Z01MZkFCcHVYeHBESmcwd2lncHVwdlUvNm12V0JsdmQxNHc4OGs3U2V3dkhvbzMsVTVFaUlkLzk2YTd5czQrNmdHOWRaUUEySHVZQ3pVOEVWeThGaXAzamRucUJDTloxTUlQNGhpa1k9O26GkYrTHOby3yFLV7Onzj0=xxc>",
	}

	// Generate test contacts
	for i := 0; i < 10; i++ {
		contacts = append(contacts, Contact{
			ID:             id.NewIdFromUInt(prng.Uint64(), id.User, t),
			DhPubKey:       getGroup().NewInt(prng.Int63()),
			OwnershipProof: make([]byte, prng.Int63n(255)),
			Facts:          fact.FactList{},
		})

		// Add facts to contact
		for j := 0; j < prng.Intn(5); j++ {
			username := make([]byte, prng.Intn(255))
			prng.Read(username)
			newFact, err := fact.NewFact(fact.Username, base64.StdEncoding.EncodeToString(username))
			if err != nil {
				t.Errorf("Failed to generate new fact (%d %d): %+v", i, j, err)
			}
			contacts[i].Facts = append(contacts[i].Facts, newFact)
		}

		// Set some fields to nil for certain contact
		switch i {
		case 1:
			contacts[i].ID = nil
		case 2:
			contacts[i].DhPubKey = nil
		case 3:
			contacts[i].OwnershipProof = nil
		case 4:
			contacts[i].Facts = nil
		case 5:
			contacts[i] = Contact{}
		}

		// Uncomment to print new expectedContact list
		// fmt.Printf("\"%s\",\n", contacts[i].Marshal())
	}

	for i, c := range contacts {
		expected, err := Unmarshal([]byte(expectedContact[i]))
		if err != nil {
			t.Errorf("Unmarshal() failed to unmarshal contact %d: %+v", i, err)
		}
		if !Equal(expected, c) {
			t.Errorf("Contacts %d do not match.\nexpected: %s\nreceived: %s",
				i, expected, c)
		}
	}
}

// Error path: verify that various incorrect buffer produce the expected errors.
func TestUnmarshal_Error(t *testing.T) {
	values := []struct {
		buff []byte
		err  string
	}{
		{
			[]byte{},
			emptyBufferErr,
		},
		{
			[]byte(headTag + openVerTag + currentVersion + closeVerTag + footTag),
			emptyDataErr,
		},
		{
			make([]byte, 255),
			fmt.Sprintf(noTagsErr, noOpenTagErr),
		},
		{
			[]byte(openVerTag + currentVersion + closeVerTag + footTag),
			fmt.Sprintf(noTagsErr, noOpenTagErr),
		},
		{
			[]byte(headTag + openVerTag + currentVersion + closeVerTag),
			fmt.Sprintf(noTagsErr, noCloseTagErr),
		},
		{
			[]byte(footTag + headTag),
			fmt.Sprintf(noTagsErr, swappedTagErr),
		},
		{
			[]byte(headTag + currentVersion + closeVerTag + footTag),
			fmt.Sprintf(noVersionErr, noOpenTagErr),
		},
		{
			[]byte(headTag + openVerTag + currentVersion + footTag),
			fmt.Sprintf(noVersionErr, noCloseTagErr),
		},
		{
			[]byte(headTag + closeVerTag + currentVersion + openVerTag + footTag),
			fmt.Sprintf(noVersionErr, swappedTagErr),
		},
		{
			[]byte(headTag + openVerTag + currentVersion + closeVerTag + "invalidEncoding" + footTag),
			strings.Split(base64DecodeErr, "%")[0],
		},
		{
			[]byte(headTag + openVerTag + currentVersion + closeVerTag + "AA==" + footTag),
			strings.Split(idUnmarshalErr, "%")[0],
		},
		{
			[]byte(headTag + openVerTag + closeVerTag + "AA==" + footTag),
			strings.Split(wrongVersionErr, "%")[0],
		},
		{
			[]byte(headTag + openVerTag + "invalidVersion" + closeVerTag + "AA==" + footTag),
			strings.Split(wrongVersionErr, "%")[0],
		},
		{
			[]byte("<xxc(1)TWWCIQf8/VIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADBAD4rwAAjgFVbXlVc2VybmFtZSxFZGV2aW5wdXR2YWxpZGF0aW9uQGVsaXh4aXIuaW8sUDY1MDI1MzAwMDBVUyxQNjUwMjUzMDAwMVVTO6qH/p+pDZKP8gPt7hmMNKM=xxc>"),
			strings.Split(dhKeyUnmarshalErr, "%")[0],
		},
		{
			[]byte("<xxc(1)TWWCIQf8/VIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADHAD7pJ2Ax5/ElekBw6y8fgAAjgFJTlZBTElEIEZBQ1RTDQSLMk5Iro3+JRm6Zr82Pg==xxc>"),
			strings.Split(factsUnmarshalErr, "%")[0],
		},
	}

	for i, val := range values {
		_, err := Unmarshal(val.buff)
		if err == nil || !strings.Contains(err.Error(), val.err) {
			t.Errorf("Unmarshal() did not produce the expected error for an "+
				"invalid buffer(%d).\nexpected: %s\nreceived: %+v",
				i, val.err, err)
		}
	}
}

// Error path: the checksum is replaced with an invalid one to cause a
// checksumErr error.
func TestUnmarshal_ChecksumError(t *testing.T) {
	c := Contact{
		ID:       id.NewIdFromUInt(rand.Uint64(), id.User, t),
		DhPubKey: getCycInt(256),
		Facts: fact.FactList{
			{Fact: "myUsername", T: fact.Username},
			{Fact: "devinputvalidation@elixxir.io", T: fact.Email},
			{Fact: "6502530000US", T: fact.Phone},
			{Fact: "6502530001US", T: fact.Phone},
		},
	}

	buff := c.Marshal()
	buff[len(buff)-6] = byte('F')

	_, err := Unmarshal(buff)
	if err == nil || !strings.Contains(err.Error(), checksumErr) {
		t.Errorf("Unmarshal() did not produce the expected error for an "+
			"invalid checksum.\nexpected: %s\nreceived: %+v", checksumErr, err)
	}
}

// Unit test of Contact.GetChecksum.
func TestContact_GetChecksum(t *testing.T) {
	c := Contact{
		ID:       id.NewIdFromUInt(rand.Uint64(), id.User, t),
		DhPubKey: getCycInt(256),
		Facts: fact.FactList{
			{Fact: "myUsername", T: fact.Username},
			{Fact: "devinputvalidation@elixxir.io", T: fact.Email},
			{Fact: "6502530000US", T: fact.Phone},
		},
	}

	checksum := c.GetChecksum()

	if len(checksum) != checksumLength {
		t.Errorf("GetChecksum() returned checksum with incorrect length."+
			"\nexpected: %d\nreceived: %d", checksumLength, len(checksum))
	}

	// Generate expected checksum
	h := crypto.BLAKE2b_256.New()
	h.Write(c.ID.Marshal())
	h.Write(c.DhPubKey.Bytes())
	h.Write(c.OwnershipProof)
	h.Write([]byte(c.Facts.Stringify()))
	expected := h.Sum(nil)[:checksumLength]

	if !bytes.Equal(expected, checksum) {
		t.Errorf("GetChecksum() returned incorrect checksum."+
			"\nexpected: %v\nreceived: %v", expected, checksum)
	}
}

// Happy path: nil Contact.
func TestContact_GetChecksum_NilContact(t *testing.T) {
	c := Contact{}

	checksum := c.GetChecksum()

	if len(checksum) != checksumLength {
		t.Errorf("GetChecksum() returned checksum with incorrect length."+
			"\nexpected: %d\nreceived: %d", checksumLength, len(checksum))
	}

	// Generate expected checksum
	h := crypto.BLAKE2b_256.New()
	h.Write([]byte(c.Facts.Stringify()))
	expected := h.Sum(nil)[:checksumLength]

	if !bytes.Equal(expected, checksum) {
		t.Errorf("GetChecksum() returned incorrect checksum."+
			"\nexpected: %v\nreceived: %v", expected, checksum)
	}
}

// Unit test of Contact.GetFingerprint.
func TestContact_GetFingerprint(t *testing.T) {
	c := Contact{
		ID:       id.NewIdFromString("Samwise", id.User, t),
		DhPubKey: getCycInt(512),
	}

	testFP := c.GetFingerprint()
	if len(testFP) != fingerprintLength {
		t.Errorf("GetFingerprint() returned fingerprint with unexpected length."+
			"\nexpected: %d\nreceived: %d", fingerprintLength, len(testFP))
	}

	// Generate expected fingerprint
	h := crypto.SHA256.New()
	h.Write(c.ID.Bytes())
	h.Write(c.DhPubKey.Bytes())
	expectedFP := base64.StdEncoding.EncodeToString(h.Sum(nil))[:fingerprintLength]

	if strings.Compare(expectedFP, testFP) != 0 {
		t.Errorf("GetFingerprint() returned expected fingerprint."+
			"\nexpected: %s\nreceived: %s", expectedFP, testFP)
	}
}

// Happy path: the ID and DH key are both nil.
func TestContact_GetFingerprint_NilContact(t *testing.T) {
	c := Contact{}

	testFP := c.GetFingerprint()
	if len(testFP) != fingerprintLength {
		t.Errorf("GetFingerprint() returned fingerprint with unexpected length."+
			"\nexpected length: %d\nreceived length: %d",
			fingerprintLength, len(testFP))
	}

	// Generate expected fingerprint
	h := crypto.SHA256.New()
	expectedFP := base64.StdEncoding.EncodeToString(h.Sum(nil))[:fingerprintLength]

	if strings.Compare(expectedFP, testFP) != 0 {
		t.Errorf("GetFingerprint() returned expected fingerprint."+
			"\nexpected: %s\nreceived: %s", expectedFP, testFP)
	}
}

// Consistency test for changes in underlying dependencies.
func TestContact_GetFingerprint_Consistency(t *testing.T) {
	expected := []string{
		"rBUw1n4jtH4uEYq", "Z/Jm1OUwDaql5cd", "+vHLzY+yH96zAiy",
		"cZm5Iz78ViOIlnh", "9LqrcbFEIV4C4LX", "ll4eykGpMWYlxw+",
		"6YQshWJhdPL6ajx", "Y6gTPVEzow4IHOm", "6f/rT2vWxDC9tdt",
		"rwqbDT+PoeA6Iww", "YN4IFijP/GZ172O", "ScbHVQc2T9SXQ2m",
		"50mfbCXQ+LIqiZn", "cyRYdMKXByiFdtC", "7g6ujy7iIbJVl4F",
	}

	for i := range expected {
		c := Contact{
			ID:       id.NewIdFromUInt(uint64(i), id.User, t),
			DhPubKey: getGroup().NewInt(25),
		}

		fp := c.GetFingerprint()
		if expected[i] != fp {
			t.Errorf("GetFingerprint() did not output the expected fingerprint (%d)."+
				"\nexpected: %s\nreceived: %s", i, expected[i], fp)
		}
	}
}

// Happy path.
func TestContact_MakeQR(t *testing.T) {
	c := Contact{
		ID: id.NewIdFromUInts([4]uint64{rand.Uint64(), rand.Uint64(),
			rand.Uint64(), rand.Uint64()}, id.User, t),
		DhPubKey: getCycInt(256),
		Facts: fact.FactList{
			{Fact: "myUsername", T: fact.Username},
			{Fact: "devinputvalidation@elixxir.io", T: fact.Email},
			{Fact: "6502530000US", T: fact.Phone},
			{Fact: "6502530001US", T: fact.Phone},
		},
	}
	qrCode, err := c.MakeQR(512, qrcode.Medium)
	if err != nil {
		t.Errorf("MakeQR() returned an error: %+v", err)
	}
	img, _, err := image.Decode(bytes.NewReader(qrCode))
	if err != nil {
		t.Fatalf("Failed to decode image: %+v", err)
	}

	qrCodes, err := goqr.Recognize(img)
	if err != nil {
		t.Fatalf("Failed to recognize QR code: %+v", err)
	}

	var qrBytes []byte
	for _, qrCode := range qrCodes {
		qrBytes = append(qrBytes, qrCode.Payload...)
	}

	if !bytes.Equal(c.Marshal(), qrBytes) {
		t.Errorf("Generated QR code data does not match expected."+
			"\nexpected: %s\nreceived: %s", c.Marshal(), qrBytes)
	}

	testContact, err := Unmarshal(qrBytes)
	if err != nil {
		t.Errorf("Failed to unmarshal QR code data: %+v", err)
	}

	if !Equal(c, testContact) {
		t.Errorf("Contact unmarshaled from QR code does not match original."+
			"\nexpected: %s\nreceived: %s", c, testContact)
	}
}

// Error path: marshaled data is too long to be encoded to a QR code.
func TestContact_MakeQR_DataTooLargeError(t *testing.T) {
	c := Contact{
		OwnershipProof: make([]byte, 2953),
	}

	_, err := c.MakeQR(512, qrcode.Medium)
	if err == nil || !strings.Contains(err.Error(), "content too long to encode") {
		t.Errorf("MakeQR() did not return an error when the marshaled data is "+
			"too long: %+v", err)
	}
}

// Consistency test.
func TestContact_String(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	var contacts []Contact
	expectedContact := []string{
		"ID: r79ksZZ/jFMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD  DhPubKey: 6087471365... in GRP: 6SsQ/HAHUn...  OwnershipProof: CcnZND6SugndnVLf15tNdkKbYXoMn58NO6VbDMDWFEyIhTWEGsvgcJsHWAg/YdN1vAK0HfT5GSnhj9qeb4LlTnSOgeeeS71v40zcuoQ+6NY+jE/+HOvqVG2PrBPdGqwEzi6ih3xVec+ix44bC6+uiBuCp1EQikLtPJA8qkNGWnhiBhaX  Facts: Uiv79vgwQKIfhANrNLYhfaSy2B9oAoRwccHHnlqLcLcJaW3Sy4SlwXic/BckjJoKOKwVuOBdljhBhSYlH/fNEQQ7UwRYCP6jjV2tv7Sf/iXS6wMr9mtBWkrE2Gec4lk39x56NU0NzZhz9ZtdP7B4biUkatyNuS3UhYpDPK+tCw8onMoVg8arAZ86m6L9G1KsrRoBALF+ygg6IXTJg8d6XgoPUoJo2+WwglBdG4+1NpkaprotPp7T8OiC6+hp17TJ6hriww5rxz9KztRIZ6nlTOr9EjSxHnTJgdTOQWRTIzBzw,UtzTn7wpuAfGFTetf5CT+96whCJH1l14pKqK4qgR8Yc2zM3Pr5ywnoJjAIZfa5rcyw1HfZo+HTiyfHOCcqGAX5+IX;",
		"ID: 7vJ2X2idUxcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD  DhPubKey: 2332036530... in GRP: 6SsQ/HAHUn...  OwnershipProof: SDA/9OY4I0J2WhPWluUt92D2w0ZeKaDcpGrDoNVwEzvCFXH19UpkMQVRP9hCmxlK4bqfKoOGrnKzZh/oLCrGTb9GFRgk4jBTEmN8mcK4fW3w3V7yg2cZBy1nL2H6oL6G9FeSHsN8DkYM8NcD0H3F9WYaRQEzQJpxK2pmq9e6ZSJMoml42aXOYv6xGoOPFmIutUzuPmdVIpwYPBkzqRZYXhg7twkZLbDmyNcJudc4O5k8aUmZRbCwz+PcLsH8lhDX7rGdCRaidCPCnkQvDjHCyVOWYA==  Facts: U8F+zAEFvphaVuSAuaDY6HHh/R4TgrtnHhWQYThMfHnyBH72IW8xnNOiTPzyy8l1S+fjHVHrX4dYnjJ98hy+ED50=,UlCvsxqp2w7D5SK++YSelz9VrwRs8Lqg3ocZpqCL3aGTsKuDNa/3fIbEURHS/03zSBrUazgUKthmex7OW1hj94OGimZpvPZ+LergUn3Leulxs1P1NOSyStLIayBIDQGLfwwY6emhisP7xBSkZwqh6SZT8HkAeEcWknH6OqeZdbMQEZf01LyxC7D0+9g22l0BR,UfcdlK64b44QTIyjRA/hxr5vNFSM8OTl49cFw,UiejzJnpD0QYzA209RrgZFq5G/xPWprL62QedbfNEBZApZnsutBpAARdVb+XLQFsxcKyspcdbr397cOhhRNO6A2s7H1j+QnlQ59BPTCbr4S/V4SNxmAiiBLhRumzyymxG7YgWL11FzbWgdjrn4YM/t635iTb1Hk3aiihO8ZqFu4dDe0EDMFo7OGx9NtktIlSZYKcU8qgp4cICFnO/MMULZ51QVolVycGYCJ2V9gOX0q9fj8kRC+Op4SXpRISXlwjWqnz8Yp6NkUfPL1+2oFWRq4aHOh6tBaSmZx0=;",
		"ID: NUaggzr9xQIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD  DhPubKey: 2333463841... in GRP: 6SsQ/HAHUn...  OwnershipProof: aVFcg1IDHyEh4UEIqlpXRWyukcFzKa1azmHq6bZS3zMAtMKrWCd22FtoyjLVw3PCZHhYO8SPo2vkjWWcP+FzQQHH5I/Tf7n64/C7Tptt9HUqLpFkzwX1aNLInqTWXXYGDmSHkFkyS7da2xQaL3wv3ngR9IHPCGo+w9izdwAS/SektlsCroUlb3Nu3j5N2FcglXWkiNV0DS9yaVpXDb8mR/KV4jOV7trP9jbhsM8g3moQ/5lD7cpvlr9N2vALnU/Nasvbs/YxlFA1hqimWK5gte5TmrWtGfK6I9ymZ9+mVRNMWUosgGvfpOdW5Fi0i65JDQQuB6NV6Wz7icyr8oGdeU2eEoL9CnJU8bOU9uq8ZqZIut/bR9NQimk4C6YNX/S0Mnv2UOATG49Xda2Gl6c0Y80oBuau7vkrXpv/5A6UZpkPo67BHkp8tq67F7f+0pUT0x7U/w==  Facts: U7Q960fI4uzNECePBZJVzpW9DqOHSE3JG/KbGMyTUP4PsDU0v1lBv3+7iHiQyPYDny4RfQ9IjIpqkIRRKJ9u3xEDBx5j5ok0shfEsJIi/h9LZKaCkeaVbe3Pk77JBQ0421E99eTiNoZ5c/oMhY3WYJt85+DNpXKIqplGVSJC83M9mrT1zqOGrn4OHfSY7uyf1vEl71lRHTcuGKrTdaJugTQ2uaKCD1qXodMQc5K52nd22IcFkMjm9N4oukams4nfywI1xS8nZ5iwFYsopbhKndhdE3bgjqC8Zun0KUktUkrv3KsNO/LkKXt9tvCGfvzDs8l+mZsk=;",
		"ID: lGGNsAgA744AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD  DhPubKey: 3355697978... in GRP: 6SsQ/HAHUn...  OwnershipProof: d32mRwa3SFelnx0qfw==  Facts: UNuDmAwt8AGm5fGkMmDTCKCm6m9T/qa9YGW93XjDzyTtJ7C8eijfkSIh3/2x+JCUf4VDs58xa+yztemu8rOPuoBvXWUANh7mAs1PBFcvBYqd43Z6gQjWdTCD+IYpGb9yqB/NFyUfloJaiP4lnz0/hKL3qnPzGWPLtsSSSnNzPWI9JTr4zRsGa7Xh7l8V3Df7ehFz1sEDctgiU,USGbDl7Oo40e3k0PkPl6U/KXkCEcEbfnYiAK+JBKhNGe2ZVYvModI5IPF6phRI8xCLk96jOl0B1OPYfZ+ga42GtW89w8iiDFrDi6QQ0wrfKLKDYogIyXHuAy2NehdvSM3QNWTeKISlTt5F8x/RdbsAU0fC1kNaLRRMzwAisvlEjH7gJ8hy6AAGVGR4xjQ80nzgiUd4Ds19X3PUrloJgqUXJGcj7k=;",
		"ID: Tpniy8GkRuMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD  DhPubKey: 5811638083... in GRP: 6SsQ/HAHUn...  OwnershipProof: +436hH1mygRoZHScSATHnMmtZLZ2Bw9hP9+WSKJW3DwiOkvOiRWUK9lrAHMdrZWDfD+v/xpMwQIeW0K7dXiccKP3faU8JeBIuQuqHrARGizMUEcrKECJa840U6mtBJct5H/GZEahdvtaE8Jdy7pWu/Y1Xhsq+GZUMfdHKpZhgWafEB9aVyy0GiAUFyBexvVbintbSsYQjuBFVTHkOGRH9fTJGdxLvuMp8Ei+/A7kCstKbG4QctBDAFCN1fNbLPwGgdnQAZaEWYyCdG1Zk/AB99k9z/INedKtTv1e5OyrKPK5thkEWP42xLd1rK9gwVQjlbaM71aNOWA4Tr2KTqoq6+xmTlY4cNuAPSgOPmJwo7D+A4vILZyDD+hE0lawteli8zEznxPYUpc7KcqgPpAUqIfiAe4BFutxC8au4sJO  Facts: ;",
		"ID: 1oKcn8YUNmwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD  DhPubKey: 3236160443... in GRP: 6SsQ/HAHUn...  OwnershipProof: XQ==  Facts: ;",
		"ID: axTLAX4/+QYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD  DhPubKey: 1614413914... in GRP: 6SsQ/HAHUn...  OwnershipProof: kET7EBq5eBYhI2vBK/rFKCQZxqb4PUfN5vH1mzwAd3fIAAtw4cDIkCK52xNm0x0FAN2fAkPW6rUP0gFhx0hJw94sUaubeM+WWRCILcf1O8cyCxz0hHL2SzZB39Npj3NM2Q5cA3hMWMAcrvqWoVNZPxQqYFWLMoCUCnrl2NArseYXnTlaw8HM3BUfxAXR9ykcOirumjokeGAv1lx7Zq3/Nor7+NgAzkvg7A==  Facts: UvJeHltfAZz4b4IuT+oQigYxDRcFmXIeSJhLevueTpWt1dJvStEJQ8fxvrIP9a5Akudp/q8qRN3ROkECcY8qhZZKBX83ad5hGDxWmCMhmu52G4ZphEv7n3VQk8nl1kw5GEQctlA/8ddAcFCGjwC1Oix/aSZ1w5G/Mv150q6KPqRwakPPsQUNT88axEeSzG7Q3;",
		"ID: 8Yxj1sakWu8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD  DhPubKey: 2695834924... in GRP: 6SsQ/HAHUn...  OwnershipProof: Bueor1WImHOvaWnYzREROrO+15NoXHHkJqxZCTRVQFHmr49s2K1+1o7QoynfRvFoNfdi7Gblzd7rv5fIMh2GwIbkoLsFSzm0XzjvEssVbacG55mYkHQDXf8fw3602l3g8VoU1TsV5r0CW99pCsBtT1gRrBaUdSVHJPjLwXONzIjQZ4Hb8XXRrP9rumYtjB57FlrXFrVdeB5xXutFT0vVGBr/l1P4/CXNcUZEpPBbRmoJaX5SWlfqGwlMwz25Iso0/4OcsBSEGlDOTTE8MH8BYiDseHK+POQUolVYYQ/bJqXlsK1TPBnPDwAmUb3oBYSSNA/s1mNoxAozwKm71rcB/6QIUFrdiSxbhPWEtcvhSbu665AYmk3Qh8dbOqR+lAVnJ0rFlfiEcy1HMYvBiehrQXsL77Gipdj5QEAhFD+Na90HwAFsKBX2N2oPZfNAvBe/wL77U2aUcA6rUPqzatLnvpfTkZgoNRucWlpBUIRuAWdMsZggTFqg4Dy08scD0td+SsKx7bBgs42ROekFcJKcM7bt7YBzWtDdfeQBUfO6AjOE/pmH/9rtGaMPQPCLrMJX0IRFAY7pB3av3sKkXxw411/Sn1JdfBAwzprPX0ZCYRAt62a1  Facts: UqvuMBBw9/qOBX+rjhWrgFRjjutdNVdi4bW4/33JPJ3qimfZueTPThEradJSQt+A58swj0bEQmT/NYorArSzhdwgxbbxXbjZQZymy9IeZMyKOUJu/Z44h0hwzuEhAE8URf/HBT/Ddh1otZUTFHcUISyMCBvjsDPt271DoznXbWrzRYLbpUSl4j/p1+6Er+7E3r9YD1rg1UqSUYB6UuZh1FUKRbffLpeCmEz/SRdf0xLtCYkRK0b8OXQKaa3Snl3euAFxCSQA71dlvckUYW0EcQzi20c2q7pHDI43wmp8QDzMHRdq1DfCKL2WbkMKlv7fmojrx5wxZB/LI+T1X;",
		"ID: sij0FdgAF1gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD  DhPubKey: 7970589899... in GRP: 6SsQ/HAHUn...  OwnershipProof: FjUO2mXwsCqY6ZgTgKuJ21XgF9J4y0t3ReeI6n3PCDjFLFDZfFinZpfsfzaUFiyJghZ4xPJBP3AfeYY/K6YZyMlfObuNWqZuYBWR8kwWAqaDvxBfHWv91y22LfCbudWqQq4rCl7FmmdH4DD8/VClzFjPOMEYY+09uu1aK0G7bkwY5RC8UcZZz/iose+IdDSUDNw18vsSxh78UwDrSGjtgjl7En7PBZAsmBI95xJx6EcHnQtqaiyDKCDqIxz+zlXoxLMPr4MN  Facts: ;",
		"ID: Qk08ktHpcTwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD  DhPubKey: 8634899332... in GRP: 6SsQ/HAHUn...  OwnershipProof: C2FxLpJ09wxAzji8zUYo4m9mFEz7A4nSdU9b7RS8tHCjLgjIFbDKheupcpUknOdI0KrwXnoueFNfleBMD9Y1n4WMq8EQR+pd9pAQO7qnK/UJ6Uy+oXMYoDZxyAgw5+5t9axCL+qCA1JXg5ydcWcOuFVreKPSB3ph6BOw/BNTRQJz9lELiUf50YXg2X2J67COYcIwATtZdKohq3QWLP7z7h3UuEdLij8pBdolkZ6ep7EQiuDzA6FlybeM2Ol0JLxzAQnNll+i9YyLkMjai7Uh7ehI/Pjwu9SMF2Acx92JKK6TlZD+B9MUUob7K6YslJw88Xo6OwltKwaSMYl2BmBzQNGVVUxGIxoBskxw8ZYDnpnCfbUGRr/7KLeCpztJCRkbIDeIjz573wi2Y/BfsKqS8ghtePl8pAQF9D4y7YWiIVh765ikj9tGf/uQrx54ZgVXLwA4Xf7jBIj6bjbBvtfTydpCPqhdM10v5l8sC9nJaEizIav6X3DsLuuk+mSgbgkXs4Wn/6MdAQ==  Facts: UrwVSFzs67yCX7w==,UbjwYBN8R5AFUi/hsSHZEa0+E+Bh1xreC7ne1gd5EKq7TVzpT2jFNI4kQNvARtTB+77qyhhm0wcoYRouuoLfaAYcZXKV7J0P81dcBdEpukTouvkq4Q06/,UB4svYp78zmWbHTU5+ClA/W9R/yCwY+xMQDY5JZUK0s8q/MNPwQmmfrt46F9h1mf3Fu1xegZVg8tItYCbeS3Y0I0ewNQXEv/5d5B11w50EAeCWg+CqVSnkZw8Y5Dl0IS/M9tNAfqGeR0hfk8u4q9DittnhjrJ83moTlT6pYalSgms8FksF+vnoPkFwggVcobndU3WOklKgitR29gd4HgveN2F8jNC3K77YoRlenfgkYCRuQRrFARnUY4z+0UPOxaOjz63jGbGEUoldx2u6IhN1DwcpNlgCLUsV4f/re8XrtozQCDeMA==;",
	}

	// Generate test contacts
	for i := 0; i < 10; i++ {
		contacts = append(contacts, Contact{
			ID:             id.NewIdFromUInt(prng.Uint64(), id.User, t),
			DhPubKey:       getGroup().NewInt(prng.Int63()),
			OwnershipProof: make([]byte, prng.Intn(512)),
			Facts:          fact.FactList{},
		})

		prng.Read(contacts[i].OwnershipProof)

		for j := 0; j < prng.Intn(5); j++ {
			username := make([]byte, prng.Intn(255))
			prng.Read(username)
			newFact, err := fact.NewFact(fact.Username, base64.StdEncoding.EncodeToString(username))
			if err != nil {
				t.Errorf("Failed to generate new fact (%d %d): %+v", i, j, err)
			}
			contacts[i].Facts = append(contacts[i].Facts, newFact)
		}

		// Uncomment to print new expectedContact list
		// fmt.Printf("\"%s\",\n", contacts[i].String())
	}

	for i, c := range contacts {
		if expectedContact[i] != c.String() {
			t.Errorf("Contacts %d do not match.\nexpected: %s\nreceived: %s",
				i, expectedContact[i], c)
		}
	}
}

// Tests that String() returns the correct values for nil values.
func TestContact_String_Nil(t *testing.T) {
	c := Contact{}
	expected := "ID: <nil>  DhPubKey: <nil>  OwnershipProof:   Facts: ;"

	if expected != c.String() {
		t.Errorf("String() failed to return the expected string for a nil Contact."+
			"\nexpected: %s\nreceived: %s", expected, c.String())
	}
}

// Happy path.
func TestEqual(t *testing.T) {
	a := Contact{
		ID:             id.NewIdFromUInt(rand.Uint64(), id.User, t),
		DhPubKey:       getCycInt(512),
		OwnershipProof: make([]byte, 1024),
		Facts: fact.FactList{
			{Fact: "myUsername", T: fact.Username},
			{Fact: "devinputvalidation@elixxir.io", T: fact.Email},
		},
	}
	rand.Read(a.OwnershipProof)
	b := Contact{
		ID:             a.ID,
		DhPubKey:       a.DhPubKey,
		OwnershipProof: a.OwnershipProof,
		Facts:          a.Facts,
	}
	c := Contact{
		ID:             id.NewIdFromUInt(rand.Uint64(), id.User, t),
		DhPubKey:       getCycInt(512),
		OwnershipProof: make([]byte, 1024),
	}
	d := Contact{
		ID:             nil,
		DhPubKey:       nil,
		OwnershipProof: nil,
		Facts:          nil,
	}
	e := Contact{
		ID: a.ID,
	}
	f := d

	if !Equal(a, b) {
		t.Errorf("Equal reported two equal contacts as different."+
			"\na: %s\nb: %s", a, b)
	}

	if Equal(a, c) {
		t.Errorf("Equal reported two unequal contacts as the same."+
			"\na: %s\nc: %s", a, c)
	}

	if Equal(b, d) {
		t.Errorf("Equal reported two unequal contacts as the same."+
			"\nb: %s\nd: %s", b, d)
	}

	if Equal(b, d) {
		t.Errorf("Equal reported two unequal contacts as the same."+
			"\nb: %s\nd: %s", b, d)
	}

	if Equal(b, e) {
		t.Errorf("Equal reported two unequal contacts as the same."+
			"\nb: %s\ne: %s", b, e)
	}

	if !Equal(d, f) {
		t.Errorf("Equal reported two equal contacts as different."+
			"\nd: %s\nf: %s", d, f)
	}
}

// Happy path.
func Test_getTagContents(t *testing.T) {
	testData := map[string]string{
		"test1": "adawdawd" + headTag + "test1" + footTag + "awdwdawd",
		"test2": "adawdawd" + headTag + "test2" + footTag + "awdwdawd" + headTag + "test2" + footTag + "awdwdawd",
	}

	for expected, str := range testData {
		received, err := getTagContents([]byte(str), headTag, footTag)
		if err != nil {
			t.Errorf("Failed to get tag contents from string %s", str)
		}

		if expected != string(received) {
			t.Errorf("Failed to get the expected contents."+
				"\nexpected: %s\nreceived: %s", expected, received)
		}
	}
}

// Error path.
func Test_getTagContents_MissingTagsError(t *testing.T) {
	testData := []string{
		"adawdawd" + headTag + "test1" + "awdwdawd",
		"adawdawd" + footTag + "test2" + headTag + "awdwdawd",
		"adawdawd" + headTag + "test3" + "awdwdawd" + headTag + "test3" + "awdwdawd",
	}

	for _, str := range testData {
		_, err := getTagContents([]byte(str), headTag, footTag)
		if err == nil {
			t.Errorf("Retrieved tag contents when tags are missing: %s", str)
		}
	}
}

func getCycInt(size int) *cyclic.Int {
	buff, err := csprng.GenerateInGroup(getGroup().GetPBytes(), size, csprng.NewSystemRNG())
	if err != nil {
		panic(err)
	}

	cycInt := cyclic.NewGroup(large.NewIntFromBigInt(getGroup().GetP().BigInt()),
		large.NewInt(2)).NewIntFromBytes(buff)

	return cycInt
}

func getGroup() *cyclic.Group {
	return cyclic.NewGroup(
		large.NewIntFromString("E2EE983D031DC1DB6F1A7A67DF0E9A8E5561DB8E8D4941"+
			"3394C049B7A8ACCEDC298708F121951D9CF920EC5D146727AA4AE535B0922C688"+
			"B55B3DD2AEDF6C01C94764DAB937935AA83BE36E67760713AB44A6337C20E7861"+
			"575E745D31F8B9E9AD8412118C62A3E2E29DF46B0864D0C951C394A5CBBDC6ADC"+
			"718DD2A3E041023DBB5AB23EBB4742DE9C1687B5B34FA48C3521632C4A530E8FF"+
			"B1BC51DADDF453B0B2717C2BC6669ED76B4BDD5C9FF558E88F26E5785302BEDBC"+
			"A23EAC5ACE92096EE8A60642FB61E8F3D24990B8CB12EE448EEF78E184C7242DD"+
			"161C7738F32BF29A841698978825B4111B4BC3E1E198455095958333D776D8B2B"+
			"EEED3A1A1A221A6E37E664A64B83981C46FFDDC1A45E3D5211AAF8BFBC072768C"+
			"4F50D7D7803D2D4F278DE8014A47323631D7E064DE81C0C6BFA43EF0E6998860F"+
			"1390B5D3FEACAF1696015CB79C3F9C2D93D961120CD0E5F12CBB687EAB045241F"+
			"96789C38E89D796138E6319BE62E35D87B1048CA28BE389B575E994DCA7554715"+
			"84A09EC723742DC35873847AEF49F66E43873", 16),
		large.NewIntFromString("2", 16))
}

// func Test_GenerateContact(t *testing.T) {
// 	intString := "408f6ed2c7fddc4224df972a305dc7ce974ebf821266cee696cb206d21a3" +
// 		"1d7c30fbc2d724fb7b16030adb486ac9d89b8b230a3f479f636a0f24fd0465d224608" +
// 		"cb0a67e5e6682ab14c006330556d10e54447b81acfbd7012a762a95a1c04dd4beb76d" +
// 		"9f94e712f309ca49b9c566a7545e2c8dea85abd40626a176d371950ccab5442bf5954" +
// 		"f0f9136d788b1c938e4f4f29927a931e0dc97033ae5d6a8fc9adfbd774aea6230e1d6" +
// 		"c064c1a995f033d026b050fd955fb1e791d15dd98ee6ff244a5f25c81f753bb82d18c" +
// 		"e071ce5d79646f306d013d2a86555a0847134173fbf3a9b1eec15934d0af3d0405cac" +
// 		"fb6425e7d83b20551230f535f87a4ac92c79e615c29571deeeff0d7b7298e1c03b02e" +
// 		"1bc6e2c56ebea2ec1bffd200358ee52bd330853194632fd5229f08dbcc409b76edb0c" +
// 		"9c6ed70914aea1be2f0baefff4b4b5578fb1f03b8c49f91498cc4dedf7d51c5c89f9e" +
// 		"c31d50924ffa972c4e78d3df7649963adfb96cf267f28af15b42a6697635f9c9dc49c" +
// 		"0ad4b4d45265e8c672643f01b5617a5c35fe24ca1fc92954"
// 	example := Contact{
// 		ID:       id.NewIdFromString("MyContactID", id.User, t),
// 		DhPubKey: getGroup().NewIntFromString(intString, 16),
// 		Facts: fact.FactList{
// 			{Fact: "myUsername", T: fact.Username},
// 			{Fact: "devinputvalidation@elixxir.io", T: fact.Email},
// 			{Fact: "6502530000US", T: fact.Phone},
// 		},
// 	}
//
// 	exampleBase64 := base64.StdEncoding.EncodeToString(example.Marshal())
// 	fmt.Printf("%s\n", example.Marshal())
// 	fmt.Printf("%s\n", exampleBase64)
//
// 	err := utils.WriteFile("testContact.bin", example.Marshal(), utils.FilePerms, utils.DirPerms)
// 	if err != nil {
// 		t.Errorf("Failed to save contact file: %+v", err)
// 	}
//
// 	qrCode, err := example.MakeQR(512, qrcode.Medium)
// 	if err != nil {
// 		t.Errorf("Failed to generate QR code: %+v", err)
// 	}
//
// 	err = utils.WriteFile("testContactQR.png", qrCode, utils.FilePerms, utils.DirPerms)
// 	if err != nil {
// 		t.Errorf("Failed to save contact file: %+v", err)
// 	}
//
// 	path := "newContact.bin"
//
// 	if !utils.FileExists(path) {
// 		return
// 	}
//
// 	newContactData, err := utils.ReadFile(path)
// 	if err != nil {
// 		t.Fatalf("Failed to read contact file: %+v", err)
// 	}
//
// 	if !bytes.Equal(example.Marshal(), newContactData) {
// 		t.Errorf("Contact base64 do not match.\nexpected: %s\nreceived: %s",
// 			example.Marshal(), newContactData)
// 	}
//
// 	newContact, err := Unmarshal(newContactData)
// 	if err != nil {
// 		t.Errorf("Failed to unmarshal contact: %+v", err)
// 	}
//
// 	if !Equal(example, newContact) {
// 		t.Errorf("Contact files do not match.\nexpected: %s\nreceived: %s",
// 			example, newContact)
// 	}
// }
