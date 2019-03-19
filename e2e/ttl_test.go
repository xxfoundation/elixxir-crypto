////////////////////////////////////////////////////////////////////////////////
// Copyright © 2019 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package e2e

import (
	"gitlab.com/elixxir/crypto/cyclic"
	"testing"
)

// Verify GenerateKeyTTL panics when min and max are equal
func TestGenerateKeyTTL_PanicOnMinMaxEq(t *testing.T) {

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("GenerateKeyTTL should panic on when min == max!")
		}
	}()

	sessionKey := *cyclic.NewInt(23)

	min := uint16(200)
	max := uint16(200)

	params := TTLParams{
		1.2,
		400,
	}

	GenerateKeyTTL(&sessionKey, min, max, params)
}

// Verify GenerateKeyTTL panics when min is greater than max
func TestGenerateKeyTTL_PanicOnMinGreaterThanMax(t *testing.T) {

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("GenerateKeyTTL should panic on when min == max!")
		}
	}()

	sessionKey := *cyclic.NewInt(23)

	min := uint16(2000)
	max := uint16(200)

	params := TTLParams{
		1.2,
		400,
	}

	GenerateKeyTTL(&sessionKey, min, max, params)
}

// Verify GenerateKeyTTL generated expected TTL and NumKeys
func TestGenerateKeyTTL_ValidTTL(t *testing.T) {

	sessionKey := *cyclic.NewInt(23)

	min := uint16(2000)
	max := uint16(20000)

	params := TTLParams{
		1.2,
		400,
	}

	ttl, numKeys := GenerateKeyTTL(&sessionKey, min, max, params)

	expectedTTL := uint16(8115)
	expectedNumKeys := uint32(9738)

	if ttl != expectedTTL {
		t.Errorf("TTL generated doesn't match expected value")
	}
	if numKeys != expectedNumKeys {
		t.Errorf("Num keys generated doesn't match expected value")
	}

}

// If the number of keys is smaller than the threshold (TTL + the min. time offset)
// then set the num keys to that threshold
func TestComputeNumKeys_MinThreshold(t *testing.T) {

	ttl := uint16(1000)

	params := TTLParams{
		1.01,
		57000,
	}

	actualNumKeys := computeNumKeys(ttl, params)
	expectedNumKeys := uint32(ttl + params.minNumKeys)

	if expectedNumKeys != actualNumKeys {
		t.Errorf("Compute num keys did not set it to min. threshold")
	}
}

// TTL scalar should never equal zero
func TestGenerateKeyTTL_KeysPerTimeEqZeroShouldPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("GenerateKeyTTL should panic when ttlScalar is zero")
		}
	}()

	sessionKey := *cyclic.NewInt(23)

	min := uint16(20)
	max := uint16(200)

	params := TTLParams{
		0,
		400,
	}

	GenerateKeyTTL(&sessionKey, min, max, params)
}

// TTL scalar should never be negative
func TestGenerateKeyTTL_KeysPerTimeIsLessThanZeroShouldPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("GenerateKeyTTL should panic when ttlScalar is negative")
		}
	}()

	sessionKey := *cyclic.NewInt(23)

	min := uint16(20)
	max := uint16(200)

	params := TTLParams{
		-2.5,
		400,
	}

	GenerateKeyTTL(&sessionKey, min, max, params)
}