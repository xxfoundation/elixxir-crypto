////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package sih

// An evaluatable service is a service hash which has multiple tag entries in
// it (i.e., "this notification applies to these user IDs in a
// channel", or "these tags are a part of this message"). These functions
// support matching on such a construction.

import (
	"math"

	bloomfilter "gitlab.com/elixxir/crypto/sealedBloomfilter"
	"gitlab.com/elixxir/primitives/format"
	"gitlab.com/xx_network/primitives/id"
)

// filterSize is SIH, which is 200 bits, so that must be our filter size.
var filterSize = uint64(format.SIHLen * 8)

// The recommendate number of hash ops is (m / float64(elements)) * math.Log(2),
// where m is the number of bits. Our design assumes that # of elements is 5.
var numHashOps = uint64((float64(filterSize) / 5.0) * math.Log(2))

var compressedTag = "CompressedSIH"

// MakeCompressedSIH creates an SIH with multiple services that can be
// checked for by stuffing each Hash into a bloom filter. It then uses
// the pickup ID as the key and the msgHash as the nonce to encrypt
// the filter and returns the result. The identifier is added to the
// bloom like an SIH (hash of msgHash + identifier) to confirm it
// belongs to the SIH quickly on evaluation.
func MakeCompessedSIH(pickup *id.ID, msgHash, identifier []byte,
	tags []string) ([]byte, error) {
	filter, err := makeFilter(pickup, msgHash)
	if err != nil {
		return nil, err
	}

	filter.Add(makeSIHEntry(msgHash, identifier))
	for i := 0; i < len(tags); i++ {
		filter.Add([]byte(tags[i]))
	}
	return filter.Seal()
}

// EvaluatedCompressedSIH decrypts an encrypted bloomfilter using the
// pickup ID and msgHash as the key and nonce, respectively. It
// decodes the result into a bloom filter, then it returns the tags
// passed in which are marked as present in the bloom filter.
func EvaluateCompessedSIH(pickup *id.ID, msgHash, identifier []byte,
	tags []string, sih []byte) ([]string, bool, error) {
	filter, err := makeFilter(pickup, msgHash)
	if err != nil {
		return nil, false, err
	}
	err = filter.Unseal(sih)
	if err != nil {
		return nil, false, err
	}

	// If the identifier entry doesn't exist, skip processing tags
	if !filter.Test(makeSIHEntry(msgHash, identifier)) {
		return nil, false, nil
	}
	results := make([]string, 0, len(tags))
	for i := 0; i < len(tags); i++ {
		curTag := tags[i]
		if filter.Test([]byte(curTag)) {
			results = append(results, curTag)
		}
	}
	return results, true, nil
}

func makeFilter(pickup *id.ID, msgHash []byte) (bloomfilter.Sealed, error) {
	key := makeFilterKey(pickup)
	nonce := makeFilterNonce(msgHash)
	return bloomfilter.InitByParameters(key, nonce, filterSize,
		uint64(numHashOps))
}

func makeFilterKey(pickup *id.ID) []byte {
	blake := hasher()
	data := blake.Sum(pickup.Bytes())
	return data[:32]
}

// return up to 24 bytes of the msgHash as the nonce
func makeFilterNonce(msgHash []byte) []byte {
	data := msgHash
	if len(data) > 24 {
		data = data[:24]
	}
	return data
}

func makeSIHEntry(msgHash, identifier []byte) []byte {
	return HashFromMessageHash(MakePreimage(identifier, compressedTag),
		msgHash)
}
