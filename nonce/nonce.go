////////////////////////////////////////////////////////////////////////////////
// Copyright © 2019 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package nonce

import (
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/csprng"
	"time"
)

// Length of Nonce in bytes
// 256 bits
const NonceLen = 32

type Value [NonceLen]byte

type Nonce struct {
	Value
	GenTime    time.Time
	ExpiryTime time.Time
	TTL        time.Duration
}

// Generate a fresh nonce with the given TTL in minutes
func NewNonce(ttl uint) Nonce {
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
		TTL: time.Duration(ttl) * time.Minute}
	copy(newNonce.Value[:], newValue)
	newNonce.ExpiryTime = newNonce.GenTime.Add(newNonce.TTL)
	return newNonce
}

func (n Nonce) Bytes() []byte {
	return n.Value[:]
}

func (n Nonce) IsValid() bool {
	return time.Now().Before(n.ExpiryTime)
}

func (n Nonce) GenTimeStr() string {
	return n.GenTime.Format(time.RFC3339)
}

func (n Nonce) ExpiryTimeStr() string {
	return n.ExpiryTime.Format(time.RFC3339)
}

func (n Nonce) TTLStr() string {
	return n.TTL.String()
}
