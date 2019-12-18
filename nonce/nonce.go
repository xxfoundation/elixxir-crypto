////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package nonce

import (
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/csprng"
	"time"
)

const (
	// Length of Nonce in bytes
	// 256 bits
	NonceLen = 32

	// TTL of registration nonce in seconds
	RegistrationTTL = 180
)

type Value [NonceLen]byte

type Nonce struct {
	Value
	GenTime    time.Time
	ExpiryTime time.Time
	TTL        time.Duration
}

// Generate a fresh nonce with the given TTL in seconds
func NewNonce(ttl uint) (Nonce, error) {
	if ttl == 0 {
		jww.FATAL.Panicf("TTL cannot be 0")
	}
	newValue := make([]byte, NonceLen)
	randGen := csprng.SystemRNG{}
	size, err := randGen.Read(newValue)
	if err != nil || size != len(newValue) {
		jww.FATAL.Panicf("Could not generate nonce: %v", err.Error())
	}
	newNonce := Nonce{GenTime: time.Now(),
		TTL: time.Duration(ttl) * time.Second}
	copy(newNonce.Value[:], newValue)
	newNonce.ExpiryTime = newNonce.GenTime.Add(newNonce.TTL)
	return newNonce, err
}

func (n Nonce) Bytes() []byte {
	return n.Value[:]
}

func (n Nonce) IsValid() bool {
	return time.Now().Before(n.ExpiryTime)
}
