////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package sih

import (
	"math"

	"gitlab.com/elixxir/crypto/bloomfilter"
	"gitlab.com/xx_network/primitives/id"
	"golang.org/x/crypto/blake2b"
)

// filterSize is SIH, which is 200 bits, so that must be our filter size.
var filterSize = uint64(200)

// The recommendate number of hash ops is (m / float64(elements)) * math.Log(2),
// where m is the number of bits. We take a guess here that # of elements is 20.
var numHashOps = uint64((float64(filterSize) / 20.0) * math.Log(2))

// evaluatablesimpleService is a service hash which has multiple entries in
// it (i.e., "this notification applies to these user IDs in a
// channel", or "these tags are a part of this message")
type evaluatableService interface {
	Hash(contents []byte) []byte
	Tag() string
}

// MakeCompressedSIH creates an SIH with multiple services that can be
// checked for by stuffing each Hash into a bloom filter. It then uses
// the pick ID as the key and the msgHash as the nonce to encrypt
// the filter and returns the result.
func MakeCompessedSIH(pickup *id.ID, msgHash []byte,
	services []evaluatableService) ([]byte, error) {
	filter, err := makeFilter(pickup, msgHash)
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(services); i++ {
		// Should we be using hash here? with what inputs?
		// doesn't the hash defeat the purpose of murmurhash?
		filter.Add([]byte(services[i].Tag()))
	}
	return filter.Seal()
}

// EvaluatedCompressedSIH decrypts an encrypted bloomfilter using the
// pickup ID and msgHash as the key and nonce, respectively. It
// decodes the result into a bloom filter, then it returns the .Tag()
// of any services passed in which are marked as present in the bloom
// filter.
func EvaluateCompessedSIH(pickup *id.ID, msgHash []byte,
	services []evaluatableService, sih []byte) ([]string, error) {
	filter, err := makeFilter(pickup, msgHash)
	if err != nil {
		return nil, err
	}
	err = filter.Unseal(sih)
	if err != nil {
		return nil, err
	}

	results := make([]string, 0)
	for i := 0; i < len(services); i++ {
		curTag := services[i].Tag()
		if filter.Test([]byte(curTag)) {
			results = append(results, curTag)
		}
	}
	return results, nil
}

func makeFilter(pickup *id.ID, msgHash []byte) (bloomfilter.Sealed, error) {
	key := makeFilterKey(pickup)
	nonce := makeFilterNonce(msgHash)
	return bloomfilter.InitByParameters(key, nonce, filterSize,
		uint64(numHashOps))
}

func makeFilterKey(pickup *id.ID) []byte {
	data := blake2b.Sum256(pickup.Bytes())
	return data[:]
}
func makeFilterNonce(msgHash []byte) []byte {
	data := blake2b.Sum256(msgHash)
	return data[:24]
}
