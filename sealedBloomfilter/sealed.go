////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package bloomfilter

import (
	"github.com/pkg/errors"
	bloomfilter "gitlab.com/elixxir/bloomfilter"
	"golang.org/x/crypto/chacha20"
)

var ErrNonceSize = errors.Errorf("nonce size must be %d", chacha20.NonceSizeX)
var ErrKeySize = errors.Errorf("key size must be %d", chacha20.KeySize)

type Sealed interface {
	// Seal generates a ciphertext of the the bit array only,
	// excluding extraneous information of the bloom filter.
	// Included for efficient DB storage purposes
	Seal() ([]byte, error)

	// Unseal decrypts a ciphertext of the Sealed bloom filter it uses
	// the bit array only, excluding extraneous information of the bloom
	// filter and cipher which should be set through Init/InitByParams
	Unseal(ciphertext []byte) error

	// Add adds the data to the ring of the bloom filter.
	Add(data []byte)

	// Returns the size of the bloom filter.
	GetSize() uint64

	// Returns the number the hash operations
	GetHashOpCount() uint64

	// Reset clears the ring in the bloom filter.
	Reset()

	// Test returns a bool if the data is in the ring. True
	// indicates that the data may be in the ring, while false
	// indicates that the data is not in the ring.
	Test(data []byte) bool

	// Merge merges the sent Bloom into itself.
	Merge(m Sealed) error

	// Return the underlying, unencrypted bloom filter.
	Bloom() *bloomfilter.Bloom
}

type sealed struct {
	// NOTE: we can't put the cipher here, because the object doesn't
	// allow rollbacks that are needed for the unseal operation.
	key   []byte
	nonce []byte
	// NOTE: we don't wrap here because we do not want to expose
	// all the underlying functions, particularly the marshallers,
	// which will not work as expected.
	filter bloomfilter.Bloom
}

// Init initializes and returns a new sealed bloom filter, or an
// error. Given a number of elements, it accurately states if data is
// not added. Within a falsePositive rate, it will indicate if the
// data has been added.
//
// WARNING: the (key, nonce) must never been repeated between bloom
// filters, otherwise the seal can be trivially decrypted.
func Init(key, nonce []byte, elements int,
	falsePositive float64) (Sealed, error) {
	if len(nonce) != chacha20.NonceSizeX {
		return nil, ErrNonceSize
	}
	if len(key) != chacha20.KeySize {
		return nil, ErrKeySize
	}

	bloom, err := bloomfilter.Init(elements, falsePositive)
	if err != nil {
		return nil, err
	}
	return &sealed{
		key:    key,
		nonce:  nonce,
		filter: *bloom,
	}, nil
}

// InitByParameters initializes a sealed bloom filter allowing the
// user to explicitly set the size of the bit array and the amount of
// hash functions
//
// WARNING: the (key, nonce) must never been repeated between bloom
// filters, otherwise the seal can be trivially decrypted.
func InitByParameters(key, nonce []byte, size,
	hashFunctions uint64) (Sealed, error) {
	if len(nonce) != chacha20.NonceSizeX {
		return nil, ErrNonceSize
	}
	if len(key) != chacha20.KeySize {
		return nil, ErrKeySize
	}

	bloom, err := bloomfilter.InitByParameters(size, hashFunctions)
	if err != nil {
		return nil, err
	}
	return &sealed{
		key:    key,
		nonce:  nonce,
		filter: *bloom,
	}, nil
}

func (s *sealed) Seal() ([]byte, error) {
	data, err := s.filter.MarshalStorage()
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(data))
	cipher, err := chacha20.NewUnauthenticatedCipher(s.key, s.nonce)
	if err != nil {
		return nil, err
	}
	cipher.XORKeyStream(ciphertext, data)
	return ciphertext, nil
}

func (s *sealed) Unseal(ciphertext []byte) error {
	plaintext := make([]byte, len(ciphertext))
	cipher, err := chacha20.NewUnauthenticatedCipher(s.key, s.nonce)
	if err != nil {
		return err
	}
	cipher.XORKeyStream(plaintext, ciphertext)
	return s.filter.UnmarshalStorage(plaintext)
}

func (s *sealed) Add(data []byte) {
	s.filter.Add(data)
}

func (s *sealed) GetSize() uint64 {
	return s.filter.GetSize()
}

func (s *sealed) GetHashOpCount() uint64 {
	return s.filter.GetHashOpCount()
}

func (s *sealed) Reset() {
	s.filter.Reset()
}

func (s *sealed) Test(data []byte) bool {
	return s.filter.Test(data)
}

func (s *sealed) Merge(m Sealed) error {
	return s.filter.Merge(m.Bloom())
}

func (s *sealed) Bloom() *bloomfilter.Bloom {
	return &s.filter
}
