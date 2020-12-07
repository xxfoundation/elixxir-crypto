/* Copyright 2020 xx network SEZC

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
   AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
   ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
   LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
   CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
   SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
   CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
   ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
   POSSIBILITY OF SUCH DAMAGE.

*/

package e2e

import (
	"gitlab.com/xx_network/crypto/large"
	"testing"
)

// Verify GenerateKeyTTL panics when min and max are equal
func TestGenerateKeyTTL_PanicOnMinMaxEq(t *testing.T) {

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("GenerateKeyTTL should panic on when min == max!")
		}
	}()

	sessionKey := large.NewInt(23)

	min := uint16(200)
	max := uint16(200)

	params := TTLParams{
		1.2,
		400,
	}

	GenerateKeyTTL(sessionKey, min, max, params)
}

// Verify GenerateKeyTTL panics when min is greater than max
func TestGenerateKeyTTL_PanicOnMinGreaterThanMax(t *testing.T) {

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("GenerateKeyTTL should panic on when min == max!")
		}
	}()

	sessionKey := large.NewInt(23)

	min := uint16(2000)
	max := uint16(200)

	params := TTLParams{
		1.2,
		400,
	}

	GenerateKeyTTL(sessionKey, min, max, params)
}

// Verify GenerateKeyTTL generated expected TTL and NumKeys
func TestGenerateKeyTTL_ValidTTL(t *testing.T) {

	sessionKey := large.NewInt(23)

	min := uint16(2000)
	max := uint16(20000)

	params := TTLParams{
		1.2,
		400,
	}

	ttl, numKeys := GenerateKeyTTL(sessionKey, min, max, params)

	expectedTTL := uint16(15950)
	expectedNumKeys := uint32(19140)

	if ttl != expectedTTL {
		t.Errorf("TTL generated doesn't match expected value, Expected %v, Received %v", expectedTTL, ttl)
	}
	if numKeys != expectedNumKeys {
		t.Errorf("Num keys generated doesn't match expected value, Expected %v, Received %v", expectedNumKeys, numKeys)
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
	expectedNumKeys := uint32(ttl + params.MinNumKeys)

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

	sessionKey := large.NewInt(23)

	min := uint16(20)
	max := uint16(200)

	params := TTLParams{
		0,
		400,
	}

	GenerateKeyTTL(sessionKey, min, max, params)
}

// TTL scalar should never be negative
func TestGenerateKeyTTL_KeysPerTimeIsLessThanZeroShouldPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("GenerateKeyTTL should panic when ttlScalar is negative")
		}
	}()

	sessionKey := large.NewInt(23)

	min := uint16(20)
	max := uint16(200)

	params := TTLParams{
		-2.5,
		400,
	}

	GenerateKeyTTL(sessionKey, min, max, params)
}
