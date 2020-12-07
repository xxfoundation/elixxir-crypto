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

// Packagee 2e contains functions used in the end-to-end encryption algorithm, including
// the end-to-end key rotation.
package e2e

import (
	"encoding/binary"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/hash"
	"gitlab.com/xx_network/crypto/large"
	"math"
)

type TTLParams struct {
	TTLScalar  float64 // A scalar to convert a TTL key retrigger to max num keys that can be used
	MinNumKeys uint16  // The min. threshold number keys that can be used
}

// GenerateKeyTTL generates Key TTL and num keys given a key and a range.
// Returns fair key TTL (num keys before retrigger happens) and num keys (usage capacity)
func GenerateKeyTTL(key *large.Int, min uint16, max uint16, params TTLParams) (uint16, uint32) {

	h, err := hash.NewCMixHash()

	if err != nil {
		jww.ERROR.Panicf("Failed to create hash: %v", err.Error())
	}

	// Generate hash from key
	h.Write(key.Bytes())
	hashed := h.Sum(nil)

	// Compute a fair TTL computed deterministically using the hash which is within the range
	fairTTL := computeTTL(hashed, min, max)

	// Compute number of keys using TTL and TTL params
	numKeys := computeNumKeys(fairTTL, params)

	return fairTTL, numKeys
}

// computeTTL compute fair TTL from key hash within range defined by min and max (inclusively).
// Return a 16 bit fair TTL number (num keys before retrigger happens) between min and max
func computeTTL(hashed []byte, min uint16, max uint16) uint16 {

	if min >= max {
		jww.ERROR.Panicf("Min must be greater than or equal to max in computeTTL")
	}

	keyHash := binary.BigEndian.Uint64(hashed[:8])
	mod := uint64(max - min)

	// The formula used is: ttl = (keyHash % mod) + min | s.t. mod = (max - min)
	ttl := uint16(keyHash%mod) + min

	return ttl
}

// computeNumKeys compute number of keys (number of key uses before triggering re-key)
// given a fairly generated TTL and TTL Params.
// TTL params contains the keys per use conversion factor and minimum use threshold
// Returns the total capacity of the number of keys that can be used
func computeNumKeys(ttl uint16, params TTLParams) uint32 {

	if params.TTLScalar <= 0.0 {
		jww.ERROR.Panicf("Keys per time unit must be greater than zero")
	}

	// Convert ttl to TTL (num keys before trig. rekeye) based by using ttl scalar
	numKeys := uint32(math.Ceil(params.TTLScalar * float64(ttl)))

	// If the number of keys to be gen. is smaller than the TTL + the min. time offset threshold
	// then set the num keys to be generated to that min threshold
	threshold := uint32(ttl + params.MinNumKeys)
	if numKeys < threshold {
		numKeys = threshold
	}

	return numKeys
}
