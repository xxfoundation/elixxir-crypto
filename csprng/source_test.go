////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package csprng

import (
	"gitlab.com/elixxir/crypto/large"
	"testing"
	"time"
)

const MODP4096 = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
	"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
	"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
	"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
	"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
	"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
	"15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" +
	"ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
	"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" +
	"F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
	"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" +
	"43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7" +
	"88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA" +
	"2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6" +
	"287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED" +
	"1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9" +
	"93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199" +
	"FFFFFFFFFFFFFFFF"

const P107 = "6B"

// TestInGroup_0 tests if 0 is ever in the group
func TestInGroup_0(t *testing.T) {
	p107 := large.NewIntFromString(P107, 16).Bytes()
	modp4096 := large.NewIntFromString(MODP4096, 16).Bytes()
	zero := []byte{0, 0, 0, 0} // a whopping 32 bits of 0

	//Note these test different code paths because of the slice len
	if InGroup(zero, p107) {
		t.Errorf("Zero is never in the group! Not even p107!")
	}
	if InGroup(zero, modp4096) {
		t.Errorf("Zero is never in the group! Not even modp4096!")
	}
}

// TestInGroup_P tests if the prime is ever in the group.
func TestInGroup_P(t *testing.T) {
	p107 := large.NewIntFromString(P107, 16).Bytes()
	modp4096 := large.NewIntFromString(MODP4096, 16).Bytes()

	//Note these test different code paths because of the slice len
	if InGroup(p107, p107) {
		t.Errorf("p107 is never in the group for p107!")
	}
	if InGroup(modp4096, modp4096) {
		t.Errorf("modp4096 is never in the group for modp4096!")
	}
	if !InGroup(p107, modp4096) {
		t.Errorf("p107 is always in the group for modp4096!")
	}
	if InGroup(modp4096, p107) {
		t.Errorf("modp4096 is never in the group for p107!")
	}
}

// TestInGroup_1 tests that 1 is always in the group.
func TestInGroup_1(t *testing.T) {
	p107 := large.NewIntFromString(P107, 16).Bytes()
	modp4096 := large.NewIntFromString(MODP4096, 16).Bytes()
	one32 := []byte{0, 0, 0, 1}
	one := []byte{1}

	// one32 is not in p107 because it's 4 bytes (longer than 107)
	if InGroup(one32, p107) {
		t.Errorf("32bit 1 is never in the group for p107!")
	}

	if !InGroup(one, p107) {
		t.Errorf("1 is always in the group for p107!")
	}
	if !InGroup(one32, modp4096) {
		t.Errorf("1 is always in the group for modp4096!")
	}
	if !InGroup(one, modp4096) {
		t.Errorf("1 is always in the group for modp4096!")
	}
}

// TestInGroupPsub1 tests that P - 1 is in the group
func TestInGroup_Psub1(t *testing.T) {
	p107 := large.NewIntFromString(P107, 16)
	modp4096 := large.NewIntFromString(MODP4096, 16)
	one := large.NewInt(1)

	p107sub1 := large.NewInt(0)
	p107sub1.Sub(p107, one)

	p4096sub1 := large.NewInt(0)
	p4096sub1.Sub(modp4096, one)

	if !InGroup(p107sub1.Bytes(), p107.Bytes()) {
		t.Errorf("p107sub1 is always in group for p107!")
	}
	if !InGroup(p4096sub1.Bytes(), modp4096.Bytes()) {
		t.Errorf("p4096sub1 is always in group for modp4096!")
	}
}

// TestInGroupPsub1 tests that P - 1 is in the group
func TestGenerateInGroup_LargeSize(t *testing.T) {
	p107 := large.NewIntFromString(P107, 16)
	rng := NewSystemRNG()

	timeout := time.After(3 * time.Second)
	done := make(chan bool)
	go func() {
		// do your testing
		b, err := GenerateInGroup(p107.Bytes(), 32, rng)
		if err != nil {
			t.Errorf("%v", err)
		}
		if !InGroup(b, p107.Bytes()) {
			t.Errorf("b not in p107: %v", b)
		}
		done <- true
	}()

	select {
	case <-timeout:
		t.Fatal("GenerateInGroup took too long to complete!")
	case <-done:
	}
}
