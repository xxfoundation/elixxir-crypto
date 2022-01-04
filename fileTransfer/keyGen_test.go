////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package fileTransfer

import (
	"testing"
)

// Consistency test: tests that NewTransferKey returns the expected values. If
// the expected values no longer match, then some underlying dependency has made
// a potentially breaking change.
func TestNewTransferKey_Consistency(t *testing.T) {
	expectedTransferKeys := []string{
		"U4x/lrFkvxuXu59LtHLon1sUhPJSCcnZND6SugndnVI=",
		"39ebTXZCm2F6DJ+fDTulWwzA1hRMiIU1hBrL4HCbB1g=",
		"CD9h03W8ArQd9PkZKeGP2p5vguVOdI6B555LvW/jTNw=",
		"uoQ+6NY+jE/+HOvqVG2PrBPdGqwEzi6ih3xVec+ix44=",
	}

	prng := NewPrng(42)

	for i, expected := range expectedTransferKeys {
		key, err := NewTransferKey(prng)
		if err != nil {
			t.Errorf("NewTransferKey returned an error: %+v", err)
		}

		if key.String() != expected {
			t.Errorf("New TransferKey #%d does not match expected."+
				"\nexpected: %s\nreceived: %s", i, expected, key)
		}
	}
}

// Tests that a TransferKey serialised via TransferKey.Bytes and unmarshalled
// via UnmarshalTransferKey matches the original
func TestTransferKey_Bytes_UnmarshalTransferKey(t *testing.T) {
	prng := NewPrng(42)

	for i := 0; i < 10; i++ {
		key, err := NewTransferKey(prng)
		if err != nil {
			t.Errorf("Failed to create new transfer key (%d): %+v", i, err)
		}

		keyBytes := key.Bytes()
		newKey := UnmarshalTransferKey(keyBytes)

		if key != newKey {
			t.Errorf("Unmarshalled TransferKey #%d does not match original."+
				"\nexpected: %s\noriginal: %s", i, key, newKey)
		}
	}
}

// Consistency test of TransferKey.String.
func TestTransferKey_String(t *testing.T) {
	prng := NewPrng(42)
	expectedStrings := []string{
		"U4x/lrFkvxuXu59LtHLon1sUhPJSCcnZND6SugndnVI=",
		"39ebTXZCm2F6DJ+fDTulWwzA1hRMiIU1hBrL4HCbB1g=",
		"CD9h03W8ArQd9PkZKeGP2p5vguVOdI6B555LvW/jTNw=",
		"uoQ+6NY+jE/+HOvqVG2PrBPdGqwEzi6ih3xVec+ix44=",
		"GwuvrogbgqdREIpC7TyQPKpDRlp4YgYWl4rtDOPGxPM=",
		"rnvD4ElbVxL+/b4MECiH4QDazS2IX2kstgfaAKEcHHA=",
		"ceeWotwtwlpbdLLhKXBeJz8FySMmgo4rBW44F2WOEGE=",
		"SYlH/fNEQQ7UwRYCP6jjV2tv7Sf/iXS6wMr9mtBWkrE=",
		"NhnnOJZN/ceejVNDc2Yc/WbXT+weG4lJGrcjbkt1IWI=",
		"kM8r60LDyicyhWDxqsBnzqbov0bUqytGgEAsX7KCDog=",
		"XTJg8d6XgoPUoJo2+WwglBdG4+1NpkaprotPp7T8OiA=",
		"uvoade0yeoa4sMOa8c/Ss7USGep5Uzq/RI0sR50yYHU=",
	}

	for i, expected := range expectedStrings {
		key, err := NewTransferKey(prng)
		if err != nil {
			t.Errorf("Failed to create new transfer key (%d): %+v", i, err)
		}

		if expected != key.String() {
			t.Errorf("TransferKey #%d string does not match expected."+
				"\nexpected: %s\nreceived: %s", i, expected, key.String())
		}
	}
}

// Tests that a partKey serialised via partKey.Bytes and unmarshalled via
// unmarshalPartKey matches the original
func Test_partKey_Bytes_unmarshalPartKey(t *testing.T) {
	prng := NewPrng(42)
	transferKey, err := NewTransferKey(prng)
	if err != nil {
		t.Errorf("Failed to create new transfer key: %+v", err)
	}

	for i := 0; i < 10; i++ {
		key := getPartKey(transferKey, uint16(i))
		if err != nil {
			t.Errorf("Failed to create new part key (%d): %+v", i, err)
		}

		partKeyBytes := key.Bytes()
		newPartKey := unmarshalPartKey(partKeyBytes)

		if key != newPartKey {
			t.Errorf("Unmarshalled partKey does not match original (%d)."+
				"\nexpected: %s\noriginal: %s", i, key, newPartKey)
		}
	}
}

// Consistency test of partKey.String.
func Test_partKey_String(t *testing.T) {
	prng := NewPrng(42)
	expectedStrings := []string{
		"bIXfKQN7q2W0PNlGOp3fPT9neM50vWHvYEO5rBhE8Bk=",
		"TcBI0W5FBvD+3e3Cw7muEtxClgzZ8rO9qmEFTN97w2g=",
		"eS1F1G24i4Tl6F0yqD1X5geyTLhE3/WRcwh7vbWudC8=",
		"PA4xiRJeWICRfGaauP8S2r/VD/fBXeY5S89wFlQoWtg=",
		"8OElrP7AQ2SeH4/dXlqKxHjTY7ASWWYS1K7xWlTBKro=",
		"18hrMB1qhn4EfnD29DsfPusWavzI+hLO3s674nubPNE=",
		"NdjPM9YHApBBKjMte9J0XuAqDJJLXuXA1aaWqAVX+fI=",
		"TLdFgikkNwcqWd4p6Wgwo1kymO0bg7xeOjArM9FVneo=",
		"ZtiNe5ZDd8KHgIQSii1gtqolO12Ywg03hXLoLymRB0g=",
		"5XvHZTSSa82pR286Q4ZmAc3qvn6Ar16hC2BuCGrHXRo=",
		"aSotw5EpjiTXTR5KI/m0xmWFP3wRnJLzckKqNvqTKYk=",
		"jPG1NDGFf6O9cQN6HEP9cKQgpH3zI6ll5k2MOOM75x0=",
	}
	key, err := NewTransferKey(prng)
	if err != nil {
		t.Errorf("Failed to create new transfer key: %+v", err)
	}

	for i, expected := range expectedStrings {
		partKey := getPartKey(key, uint16(i))
		if err != nil {
			t.Errorf("Failed to create new part key (%d): %+v", i, err)
		}

		if expected != partKey.String() {
			t.Errorf("partKey #%d string does not match expected."+
				"\nexpected: %s\nreceived: %s", i, expected, partKey.String())
		}
	}
}
