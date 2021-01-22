///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package singleUse

import (
	"encoding/base64"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/diffieHellman"
	"gitlab.com/elixxir/primitives/format"
	"gitlab.com/xx_network/crypto/large"
	"math/rand"
	"testing"
)

// Tests that the generated fingerprints do not change.
func TestTransmitFingerprint_Consistency(t *testing.T) {
	expectedFPs := []string{
		"cxef7y86YmR6+qVBaVghPYbEd0j7seLUxR1v1dxqiNo=",
		"LJ1HQ8zZPY3z+6UkKZMSDN2WymMmwuWW3GCjtAGfUlc=",
		"Fc8CN69uMxT1zBAr3Ed/AOy6Py3XDb3i7LngRsax0K8=",
		"YmvA+dxgIy/UxRVIvzFgGtEuMoWI8RodF7JMFIO5xcI=",
		"XYJPhLeI2+RawlSMUTEwTP1iJrFAa5zboCf5fjc/k3o=",
		"GEOS0pDuNYS5hpNHeJ2IhzlZFf9J5oHRvFpovNwWS7c=",
		"C3k7dv1Nch1oTT4aOxbBDifmf7+mT34ErFFaWW5LDb8=",
		"ck/wkZ3lv0bcQuW+Z2dw37m+Re0URPw4UsWBPAWBEtw=",
		"E/YRXaE2dplVPZSiEY+7C0e6GlDeR3jLrIPRWgeL3cI=",
		"KkT2Hfz8A7jNxOhDYG266b/hvWcQtAx0ay67Az80bAY=",
	}
	grp := getGrp()
	prng := rand.New(rand.NewSource(42))

	for i, expected := range expectedFPs {
		dhKey := diffieHellman.GeneratePublicKey(diffieHellman.GeneratePrivateKey(
			diffieHellman.DefaultPrivateKeyLength, grp, prng), grp)
		testFP := TransmitFingerprint(dhKey)

		if expected != testFP.String() {
			t.Errorf("TransmitFingerprint() did not return the expected "+
				"fingerprint for public key %s at index %d."+
				"\nexpected: %s\nreceived: %s",
				dhKey.Text(10), i, expected, testFP)
		}
	}
}

// Tests that all generated fingerprints are unique.
func TestTransmitFingerprint_Unique(t *testing.T) {
	grp := getGrp()
	prng := rand.New(rand.NewSource(42))
	FPs := make(map[format.Fingerprint]*cyclic.Int, 100)

	for i := 0; i < 100; i++ {
		dhKey := diffieHellman.GeneratePublicKey(diffieHellman.GeneratePrivateKey(
			diffieHellman.DefaultPrivateKeyLength, grp, prng), grp)
		testFP := TransmitFingerprint(dhKey)

		if FPs[testFP] != nil {
			t.Errorf("Generated fingerprint from key %s collides with "+
				"previously generated fingerprint from key %s."+
				"\nfingerprint: %s", dhKey.Text(10), FPs[testFP].Text(10),
				base64.StdEncoding.EncodeToString(testFP[:]))
		} else {
			FPs[testFP] = dhKey
		}
	}
}

func getGrp() *cyclic.Group {
	primeString := "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088" +
		"A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1" +
		"4374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDE" +
		"E386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA4" +
		"8361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077" +
		"096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E8" +
		"6039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE51" +
		"5D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"
	p := large.NewIntFromString(primeString, 16)
	g := large.NewInt(2)
	return cyclic.NewGroup(p, g)
}
