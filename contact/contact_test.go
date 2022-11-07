////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package contact

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"fmt"
	"github.com/liyue201/goqr"
	"github.com/skip2/go-qrcode"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/primitives/fact"
	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/crypto/large"
	"gitlab.com/xx_network/primitives/id"
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
		"<xxc(2)AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAB7Ugdw/BAr6TEMemGbQnZN+AMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0AFVXQWcvWWROMXZBSzBIZlQ1R1NuaGp3PT070VC4Dw7K0pKK+/0NKg/ArQ==xxc>",
		"<xxc(2)D4S63Ezjb70AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAABYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAjAFVMnA1dmd1WEhqaHNMcjY2SUc0S25VUkNLUXUwOGtEeXFRdz09LFVSbnZENEE9PSxVU1Z0WEVta3N0Z2ZhQUtFY0hBPT0726UuG590SuoxosnNslgHBw==xxc>",
		"<xxc(2)GwU/J15wKeEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADIAB7Ugdw/BAr6S8FK46CJiPJAAACADvKUBFgINED6kQtR2WpM3Psxxc>",
		"<xxc(2)/6g/AhbB1A4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADIAB7Ugdw/BAr6Qj/J+1va1fjsgEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAO7m6OGypIENidTOM8dTAoqc=xxc>",
		"<xxc(2)AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAOz09OSin/a/ZEfCXTcBTWMU=xxc>",
		"<xxc(2)ugKdkg6eo50AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADIAB7Ugdw/BAr6SR7OWmxvLxKhAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcAFVkVE9YWGlrcW9yZz07GlH9+RpHzzyudWw92EYGQg==xxc>",
		"<xxc(2)XMCYoCcs5+sAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADIAB7Ugdw/BAr6QfDMrfm2pchngEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAeABVcWh3YkkrRWNTTzBYVTUxb1gzYnlwdz09LFVtTHhrM2c1ZDFwYmxMZmRnOXNOR1hpbWczS1Jxd3c9PTvz8PKXygJ5mhJFOUX0KQY3xxc>",
		"<xxc(2)jJtC2D9RBTEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADIAB7Ugdw/BAr6T2DKp+64UoZcgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA8AFVvTlZ3RXp0OG1jSzRmVzN3M1Y3eWcyY1pCdz09O8dY3g71/hMqvc/qJ587MVs=xxc>",
		"<xxc(2)WnzDHpJX9IYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADIAB7Ugdw/BAr6WjQA9fwDEYOKAAAAAAAAAAAAAAAAAAAAAAAAAAAAGwAVWFYZz0sVTJhWE9ZdjZjR0E9PSxVUEJrenFSYlhPRHVaUEdsSm1VV3dzTS9qM0M3Qi9KWT07zmmJXN9xJq5gp21nEEkmqg==xxc>",
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
			username := make([]byte, prng.Intn(32))
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
		//fmt.Printf("\"%s\",\n", contacts[i].Marshal())
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
		"ID: r79ksZZ/jFMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD  DhPubKey: 6087471365... in GRP: 6SsQ/HAHUn...  OwnershipProof: CcnZND6SugndnVLf15tNdkKbYXoMn58NO6VbDMDWFEyIhTWEGsvgcJsHWAg/YdN1vAK0HfT5GSnhj9qeb4LlTnSOgeeeS71v40zcuoQ+6NY+jE/+HOvqVG2PrBPdGqwEzi6ih3xVec+ix44bC6+uiBuCp1EQikLtPJA8qkNGWnhiBhaX  Facts: Uiv79vgwQKIfhANrNLYhfaSy2B9oAoRwccHHn,UlqLJIyaCjg==;",
		"ID: 8kFE8/1HiUkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD  DhPubKey: 9198671517... in GRP: 6SsQ/HAHUn...  OwnershipProof: KwWJdLrAyv2a0FaSsTYZ5ziWTf3Hno1TQ3NmHP1m10/sHhuJSRq3I25LdSFikM8r60LDyicyhWDxqsBnzqbov0bUqytGgEAsX7KCDohdMmDx3peCg9Sgmjb5bCCUF0bj7U2mRqmui0+ntPw6ILr6GnXtMnqGuLDDmvHP0rO1EhnqeVM6v0SNLEedMmB1M5BZFMjMHPCdo54Okp0CSry8sWk5e7c05+8KbgHxhU3rX+Qk/vesIQiR9ZdeKSqiuKoEfGHNszNz6+csJ6CYwCGX2ua3MsNR32aPh04snxzgnKhgF+fiF0gwP/QcGyPhHEjtF1OdaF928qeYvGTeDl2yhksq08Js5jgjQnZaE9aW5S33YPbDRl4poNykasOg1XATO8IVcfX1SmQxBVE/2EKbGUrhup8qg4aucrNmH+gsKsZNv0YVGCTiMFMSY3yZwrh9bfDdXvKDZxkHLWcvYfqgvob0V5Iew3wORgzw1wPQfcX1ZhpFATNAmnEramar17plIkyiaXjZpc5i/rEag48WYi61TO4+Z1UinBg8GTOpFlheGDu3CRktsObI1wm51zg7mTxpSZlFsLDP49wuwfyWENfusZ0JFqJ0I8KeRC8OMcLJU5Zg8F+zfkXNG/C8/Bo0bENPEc8AQW+mFpW5IA==  Facts: ULmg2Ohx4fIEfvYhbzGc06JM/PA==,UsnyHL4QPnQ==,UlCvsxqp2w7D5SK8=;",
		"ID: jiKoacahN6gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD  DhPubKey: 7768111407... in GRP: 6SsQ/HAHUn...  OwnershipProof: vmEnpXS/03zSBrUazgUKthmex7OW1hj94OGimZpvPZ+LergUn3Leulxs1P1NOSyStLIayBIDQGLfwwY6emhisP7xBSkZwqh6SZT8HkAeEcWknH6OqeZdbMQEZf01LyxC7D0+9g22l0BRfcdlK57v9RZTWqHJ8z2xPtH3rhvjhBMjKNED+HGvm80VIzw5OXj1wXCJ6PMmegzMfjm/ysesQr4sFyxiQ9EGMwNtPUa4GRau  Facts: URv9mey4=,UtBpAAa8=,Uf3tw6GFETA==;",
		"ID: KkZsyvJsulEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD  DhPubKey: 3876831120... in GRP: 6SsQ/HAHUn...  OwnershipProof: JuvhL9XhP7et+Yk29R5N2oooTvGahbuHQ3tBAzBaOzhsfTbZLSJUmWCnFPKoKeHCAhZzvzDFC2edUFaJVcnBmAidlfYDl9KvX4/JEQvjqeEl6USEl5cI1qp8/GKejZFHzy9ftqBVkauGhzoerQWkpmcdaVFcg53Yrzo613QCxf06g6BGCKmJMwAhYt1MH/VUf1dSAx8hIeFBCKpaV0VsrpHBcymtWs5h6um2Ut8zALTCq1gndthbaMoy1cNzwmR4WDvEj6Nr5I1lnD/hc0EBx+SP03+5+uPwu06bbfR1Ki6RZM8F9WjSyJ6k1l12Bg5kh5BZMku3WtsUGi98L954EfSBzwhqPsPYs3cAEv0npLZbAq6FJW9zbt4+TdhXIJV1pIjVdA0vcmlaVw2/JkfyleIzle7az/Y24bDPIN5qEP+ZQ+3Kb5a/TdrwC51PzWrL27P2MZRQNYaopliuYLXuU5q1rRnyuiPcpmffplUTTFlKLIBr36TnVuRYtIuuSQ0ELgejVels+4nMq/KBnXlNnhKC/QpyVPGzlPbqvGamSLrf20fTUIppOAumDV/0tDJ79lDgExuPV3WthpenNGPNKAbmru75K16b/+QOlGaZD6OuwR5KfLauuxe3/tKVE9Me1P8dFubVmQ==  Facts: ;",
		"ID: Hbs48tF6D+0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD  DhPubKey: 3716987851... in GRP: 6SsQ/HAHUn...  OwnershipProof: VhkTckb8psYzJNQ/g+wNTS/WUG/f7uIeJDI9gOfLhF9D0iMimqQhFEon27fEQMHHmPmiTSyF8SwkiL+H0tkpoKR5pVt7c+TvskFDTjbUT315OI2hnlz+gyFjdZgm3zn4M2lcoiqmUZVIkLzcz2atPXOo4aufg4d9Jju7J/W8SXvWVEdNy4YqtN1om6BNDa5ooIPWpeh0xBzkrnad3bYhwWQyOb03ii6Rqazid/LAjXFLydnmLAViyiluEqd2F0TduCOoLxm6fQpSS1SSu/cqw078uQpe3228IZ+/MOzyX6ZmySRrCB1dLFeO7wAIsI1hoJdkBPQuqCpIc/sNZId3faZHBrdIV6WfHSp/NhejvNValZ/RkgTC47+s4OYDC3wAabl8aQyYNMIoKbqb1P+pr1gZb3deMPPJO0nsLx6KN+RIiHf/bH4kJR/hUOznzFr7LO16a7ys4+6gG9dZQA2HuYCzU8EVy8Fip3jdnqBCNZ1MIP4hikZv3KoH80XJR+WglqI/iWfPT+Eoveqc/MZY8u2xJJKc3M9Yj0lOvjNGwZrteHuXxXcN/g==  Facts: U3g==,UhFz1;",
		"ID: 9fltBEcI5KUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD  DhPubKey: 7683442388... in GRP: 6SsQ/HAHUn...  OwnershipProof: sIdI5IPF6phRI8xCLk96jOl0B1OPYfZ+ga42GtW89w8iiDFrDi6QQ0wrfKLKDYogIyXHuAy2NehdvSM3QNWTeKISlTt5F8x/RdbsAU0fC1kNaLRRMzwAisvlEjH7gJ8hy6AAGVGR4xjQ80nzgiUd4Ds19X3PUrloJgqUXJGcj7n7jfqEfWb7oCNK27w240akwcvimRgUa7oLFqcY1sQKPll2ygRoZHScSATHnMmtZLZ2Bw9hP9+WSKJW3DwiOkvOiRWUK9lrAHMdrZWDfD+v/xpMwQIeW0K7dXiccKP3faU8JeBIuQuqHrARGizMUEcrKECJa840U6mtBJct5H/GZEahdvtaE8Jdy7pWu/Y1Xhsq+GZUMfdHKpZhgWafEB9aVyy0GiAUFyBexvVbintbSsYQjuBFVTHkOGRH9fTJGdxLvuMp8Ei+/A7kCstKbG4QctBDAFCN  Facts: U1fNtWZPwAffZPc/y,UDXnSrQ==;",
		"ID: 5u+MtpUjVMEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD  DhPubKey: 6466410644... in GRP: 6SsQ/HAHUn...  OwnershipProof: TlY4cNuAPSgOPmJwo7D+A4vILZyDD+hE0lawteli8zEznxPYUpc7KcqgPpAUqIfiAe4BFutxC8au4sJOXZBExUpNymRkA2w2FMafnII8W/IhxybpqYvyNAE40iHaU95UyLUG+T9+AcsU15TF3uaMZzKcHTyptNP7EBq5eBYhI2vBK/rFKCQZxqb4PUfN5vH1mzwAd3fIAAtw4cDIkCK52xNm0x0FAN2fAkPW6rUP0gFhx0hJw94sUaubeM+WWRCILcf1O8cyCxz0hHL2SzZB39Npj3NM2Q5cA3hMWMAcrvqWoVNZPxQqYFWLMg==  Facts: UgJQK;",
		"ID: pjqa7io6HCkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD  DhPubKey: 2917027258... in GRP: 6SsQ/HAHUn...  OwnershipProof: 2ADOS+DsvFU5jJEwycAQPGQekacql4eW18BnPhvgi5P6hCKBjENFwWZch5ImEt6+55Ola3V0m9K0QlDx/G+sg/1rkCS52n+rypE3dE6QQJxjyqFlkoFfzdp3mEYPFaYIyGa7nYbhmmES/ufdVCTyeXWTDkYRBy2UD/x10BwUIaPALU6LH9pJnXDkb8y/XnSroo+pHBqQ8+xBQ1PzxrER5LMbtDcG56ivyEf87PsvUe9apMbWY4w9shqnlIdptXihx9TpN1WImHOvaWnYzREROrO+15NoXHHkJqxZCTRVQFHmr49s2K1+1o7QoynfRvFoNfdi7Gblzd7rv5fIMh2GwIbkoLsFSzm0XzjvEssVbacG55mYkHQDXf8fw3602l3g8VoU1TsV5r0CW99pCsBtT1gRrBaUdSVHJPjLwXONzIjQZ4Hb8XXRrP9rumYtjB57FlrXFrVdeB5xXutFT0vVGBr/l1P4/CXNcUZEpPBbRmoJaX5SWlfqGwlMwz25Iso0/4OcsBSEGlDOTQ==  Facts: UMTwwfwHbJqXlsK1TPBnPDwAmUb3oBYSS,UNA+kCFBa3YksW4T1hLXL4Um7uuuQGJo=;",
		"ID: fMVKJ2cFlH4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD  DhPubKey: 3741585045... in GRP: 6SsQ/HAHUn...  OwnershipProof: C++xoqXY+UBAIRQ/jWvdB8ABbCgV9jdqD2XzQLwXv8C++1NmlHAOq1D6s2rS576X05GYKDUbnFpaQVCEbgFnTLGYIExaoOA8tPLHA9LXfkrCse2wYLONkTnpBXCSnDO27e2Ac1rQ3X3kAVHzugIzhP6Zh//a7RmjD0Dwi6zCV9CERQGO6Qd2r97CpF8cONdf0p9SXXwQMM6az19GQmEQLetmtar7jAQcRLGOy8G+be3HkkjbKvQ9/qOBX+rjhWrgFRjjutdNVdi4bW4/33JPJ3qimfZueTPThEradJSQt+A58swj0bEQmT/NYorArSzhdwgxbbxXbjZQZymy9IeZMyKOUJu/Z44h0hwzuEhAE8URf/HBT/Ddh1otZUTFHcUISyMCBvjsDPt271DoznXbWrzRYLbpUSl4j/p1+6Er+7E3r9YD1rg1UqSUYB6UuZh1FUKRbffLpeCmEz/SRdf0xLtCYkRK0b8OXQKa  Facts: Ua3JFGFtBHEM4ttHNqu6RwyON8Jqf,UEKW/t+aiOvHnDFkH8sj5PVcWNQ7aZb9pxUNL;",
		"ID: bp05SImW/twAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD  DhPubKey: 2561339577... in GRP: 6SsQ/HAHUn...  OwnershipProof: dDKAq4nbVeAX0njLS3dF54jqfc8IOMUsUNl8WKdml+x/NpQWLImCFnjE8kE/cB95hj8rphnIyV85u41apm5gFZHyTBYCpoO/EF8da/3XLbYt8Ju51apCrisKXsWaZ0fgMPz9UKXMWM84wRhj7T267VorQbtuTBjlELxRxlnP+Kix74h0NJQM3DXy+xLGHvxTAOtIaO2COXsSfs8FkCyYEj3nEnHoRwedC2pqLIMoIOojHP7OVejEsw+vgw0LYXHwOd8O8GPfPHHp0ZI8TcCHE34xU9WrBfE+h1ekLpJ09wxAzji8zUYo4m8=  Facts: UcKMuCMgVsMqF66lylSSc50jQqvA=;",
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
			username := make([]byte, prng.Intn(32))
			prng.Read(username)
			newFact, err := fact.NewFact(fact.Username, base64.StdEncoding.EncodeToString(username))
			if err != nil {
				t.Errorf("Failed to generate new fact (%d %d): %+v", i, j, err)
			}
			contacts[i].Facts = append(contacts[i].Facts, newFact)
		}

		// Uncomment to print new expectedContact list
		//fmt.Printf("\"%s\",\n", contacts[i].String())
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
