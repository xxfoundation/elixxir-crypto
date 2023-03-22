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
var ErrInvalidMetadataLen = errors.Errorf("Metadata size is incorrect, " +
	"does not match passed size")
var ErrInvalidSealedLen = errors.Errorf("Sealed data size is incorrect, " +
	"does not match the expected size")

type Sealed interface {
	// Seal encrypts the filter in order to hide metadata, specifically
	// the hamming weight of the filter. it returns the encrypted filter
	// with the appended metadata inside the encrypted payload.
	// Note: the length of the metadata must be the same as
	// the passed size on initialization otherwise an error will
	// be returned
	Seal(metadata []byte) ([]byte, error)

	// Unseal decrypted the sealed filter and stored it in the filter, returning
	// the appended metadata.
	// Will error if the passed in ciphertext is not the correct length of the
	// filter+metadataSize. The size can be retrieved using sealed.SealedSize()
	// Note: the length of the metadata must be the same as
	// the passed size on initialization otherwise an error will
	// be returned
	Unseal(ciphertext []byte) ([]byte, error)

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

	// Bloom Return the underlying, unencrypted bloom filter.
	Bloom() *bloomfilter.Bloom

	// SealedSize returns the size in bytes of a sealed payload this
	// filter is expecting/ will return
	SealedSize() int
}

type sealed struct {
	// NOTE: we can't put the cipher here, because the object doesn't
	// allow rollbacks that are needed for the unseal operation.
	key   []byte
	nonce []byte

	// size of the optionally appendable metadata
	metadataSize uint

	// NOTE: we don't wrap here because we do not want to expose
	// all the underlying functions, particularly the marshallers,
	// which will not work as expected.
	filter bloomfilter.Bloom
}

// Init initializes and returns a new sealed bloom filter, or an
// error. Given a number of elements, it accurately states if data is
// not added. Within a falsePositive rate, it will indicate if the
// data has been added.
// metadataSize is the size of optional data appended to the bloomfilter
// which is inside the seal and will be returned on unsealing.
// It must be known a-priori by both sides
//
// WARNING: the (key, nonce) must never been repeated between bloom
// filters, otherwise the seal can be trivially decrypted.
func Init(key, nonce []byte, elements int,
	falsePositive float64, metadataSize uint) (Sealed, error) {
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

		metadataSize: metadataSize,
	}, nil
}

// InitByParameters initializes a sealed bloom filter allowing the
// user to explicitly set the size of the bit array and the amount of
// hash functions
// metadataSize is the size of optional data appended to the bloomfilter
// which is inside the seal and will be returned on unsealing.
// It must be known a-priori by both sides
//
// WARNING: the (key, nonce) must never been repeated between bloom
// filters, otherwise the seal can be trivially decrypted.
func InitByParameters(key, nonce []byte, size,
	hashFunctions uint64, metadataSize uint) (Sealed, error) {
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
		key:          key,
		nonce:        nonce,
		filter:       *bloom,
		metadataSize: metadataSize,
	}, nil
}

// Seal encrypts the filter in order to hide metadata, specifically
// the hamming weight of the filter. it returns the encrypted filter
// with the appended metadata inside the encrypted payload.
// Note: the length of the metadata must be the same as
// the passed size on initialization otherwise an error will
// be returned
func (s *sealed) Seal(metadata []byte) ([]byte, error) {
	// check the metadata
	if (s.metadataSize == 0 && metadata != nil) ||
		uint(len(metadata)) != s.metadataSize {
		return nil, ErrInvalidMetadataLen
	}

	// append the metadata to the marshaled filter
	data, err := s.filter.MarshalStorage()
	if err != nil {
		return nil, err
	}
	if metadata != nil {
		data = append(data, metadata...)
	}

	// seal the filter by encrypting it
	ciphertext := make([]byte, len(data))
	cipher, err := chacha20.NewUnauthenticatedCipher(s.key, s.nonce)
	if err != nil {
		return nil, err
	}
	cipher.XORKeyStream(ciphertext, data)
	return ciphertext, nil
}

// Unseal decrypted the sealed filter and stored it in the filter, returning
// the appended metadata.
// Will error if the passed in ciphertext is not the correct length of the
// filter+metadataSize. The size can be retrieved using sealed.SealedSize()
// Note: the length of the metadata must be the same as
// the passed size on initialization otherwise an error will
// be returned
func (s *sealed) Unseal(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) != s.SealedSize() {
		return nil, ErrInvalidSealedLen
	}
	plaintext := make([]byte, len(ciphertext))
	cipher, err := chacha20.NewUnauthenticatedCipher(s.key, s.nonce)
	if err != nil {
		return nil, err
	}
	cipher.XORKeyStream(plaintext, ciphertext)
	return plaintext[s.filter.BufferSize():],
		s.filter.UnmarshalStorage(plaintext[:s.filter.BufferSize()])
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

func (s *sealed) SealedSize() int {
	return int(s.metadataSize) + s.filter.BufferSize()
}
