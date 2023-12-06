////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package auth

import (
	"encoding/base64"
	"github.com/cloudflare/circl/dh/sidh"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/diffieHellman"
	"gitlab.com/xx_network/crypto/csprng"
	"io"
	"math/rand"
	"testing"
)

// Consistency test of CreateNegotiationFingerprint.
func TestCreateNegotiationFingerprint_Consistency(t *testing.T) {
	grp := getGrp()

	// Using a PRNG with same source so the output is the same on each run
	prng := rand.New(rand.NewSource(420))

	expectedFingerprints := []string{
		"kYuwgft8OfIHI24A+XqwrxLjCL0PZD1uNGdFiuHe3gg=",
		"jXXvPddttSfFkf9nWrfh2iCfP40izlaX9tq0tCnymBs=",
		"fwOLX5CLBbNbXrAwQplIVDiFpnFnTvFTkavk9P6TH6E=",
		"tORhs25Be5vkm50+1wb0IjufRBdOqmVhLivEyBiWZXA=",
		"jqc7SUdpw9cVvCoPgkzf01Squ+K/R1Lf1RJQfsdQJbk=",
		"ZEy084jM3GOCnlUFaQPogDAHes3z1eeF67J+sSthLbo=",
		"RFDinE/C9Xbidqumy5cQW3399uyh8s+SWhv8akQkl0Y=",
		"S3CsseaqGwzhF/813d+9AounhUShyAJqR81wh5QJYcw=",
		"DDz9FgDSSuvqtL6UlRGk1nbPy4GVolE5S/iucqiBW+E=",
		"VfvY4UHZVw6zBUuxytv/CQ8N5rgdoeVUbd9wMFCo00c=",
		"1mTDL/fFBCqNfAZFoDNu6MdbkMXVqkbsxvBoQ9Iv50A=",
		"+PTQ/o1VIPCDO3UFVfT1gJTBuZksvmgWmmR3s11n3rw=",
		"p1eI8uWTL48sQsdIgQj+VE3WAjdMVk6DHLcxfp3XXK4=",
		"wYQzO55/4gkQFnq/MVdgx1KixgUALju9z20LpMfB6+w=",
		"d4e2XGxB9sOdZSZZVJ/rSYuRl8NYiCxJzrY77HpVAkg=",
		"2K1HJPv+7e84VXrzEePkBhaepZR06bZ9v5IZkenYIqE=",
	}

	for i, expected := range expectedFingerprints {
		partnerDhPubKey := diffieHellman.GeneratePublicKey(
			diffieHellman.GeneratePrivateKey(512, grp, prng), grp)
		partnerSidhPubKey := makeTestSidhPubKey(prng)

		fingerprint := CreateNegotiationFingerprint(
			partnerDhPubKey, partnerSidhPubKey)

		fingerprintString := base64.StdEncoding.EncodeToString(fingerprint)
		if fingerprintString != expected {
			t.Errorf("Unexcted negotiation fingerprint (%d)."+
				"\nexpected: %s\nreceived: %s", i, expected, fingerprintString)
		}

		// fmt.Printf("\"%s\",\n", base64.StdEncoding.EncodeToString(fingerprint))
	}
}

// Tests that any changes to either input to CreateNegotiationFingerprint result
// in different fingerprints.
func TestCreateNegotiationFingerprint_Uniqueness(t *testing.T) {
	grp := getGrp()

	rng := csprng.NewSystemRNG()

	for i := 0; i < 100; i++ {
		dhKeys := []*cyclic.Int{
			diffieHellman.GeneratePublicKey(
				diffieHellman.GeneratePrivateKey(512, grp, rng), grp),
			diffieHellman.GeneratePublicKey(
				diffieHellman.GeneratePrivateKey(512, grp, rng), grp),
		}

		sidhKeys := []*sidh.PublicKey{
			makeTestSidhPubKey(rng), makeTestSidhPubKey(rng),
		}

		fingerprints := make(map[string]bool)

		for _, dhKey := range dhKeys {
			for _, sidhKey := range sidhKeys {
				fingerprint := CreateNegotiationFingerprint(dhKey, sidhKey)
				if fingerprints[string(fingerprint)] {
					t.Errorf("Fingerprint %v already exists.", fingerprint)
				}

				fingerprints[string(fingerprint)] = true
			}
		}
	}
}

func makeTestSidhPubKey(rand io.Reader) *sidh.PublicKey {
	partnerSidhPivKey := sidh.NewPrivateKey(sidh.Fp503, sidh.KeyVariantSidhA)
	_ = partnerSidhPivKey.Generate(rand)
	partnerSidhPubKey := sidh.NewPublicKey(sidh.Fp503, sidh.KeyVariantSidhA)
	partnerSidhPivKey.GeneratePublicKey(partnerSidhPubKey)
	return partnerSidhPubKey
}
