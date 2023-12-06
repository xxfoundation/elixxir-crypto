////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package fileTransfer

import (
	"encoding/json"
	"reflect"
	"testing"
)

// Consistency test: tests that NewTransferID returns the expected values. If
// the expected values no longer match, then some underlying dependency has made
// a potentially breaking change.
func TestNewTransferID_Consistency(t *testing.T) {
	expectedTransferIDs := []string{
		"U4x/lrFkvxuXu59LtHLon1sUhPJSCcnZND6SugndnVI=",
		"39ebTXZCm2F6DJ+fDTulWwzA1hRMiIU1hBrL4HCbB1g=",
		"CD9h03W8ArQd9PkZKeGP2p5vguVOdI6B555LvW/jTNw=",
		"uoQ+6NY+jE/+HOvqVG2PrBPdGqwEzi6ih3xVec+ix44=",
	}

	prng := NewPrng(42)

	for i, expected := range expectedTransferIDs {
		tid, err := NewTransferID(prng)
		if err != nil {
			t.Fatalf("NewTransferID returned an error: %+v", err)
		}

		if tid.String() != expected {
			t.Errorf("New TransferID #%d does not match expected."+
				"\nexpected: %s\nreceived: %s", i, expected, tid)
		}
	}
}

// Tests that a TransferID serialised via TransferID.Bytes and unmarshalled via
// UnmarshalTransferID matches the original
func TestTransferID_Bytes_UnmarshalTransferID(t *testing.T) {
	prng := NewPrng(42)

	for i := 0; i < 10; i++ {
		tid, err := NewTransferID(prng)
		if err != nil {
			t.Errorf("Failed to create new transfer ID (%d): %+v", i, err)
		}

		tidBytes := tid.Bytes()
		newTID := UnmarshalTransferID(tidBytes)

		if tid != newTID {
			t.Errorf("Unmarshalled TransferID #%d does not match original."+
				"\nexpected: %s\noriginal: %s", i, tid, newTID)
		}
	}
}

// Consistency test of TransferID.String.
func TestTransferID_String(t *testing.T) {
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
		tid, err := NewTransferID(prng)
		if err != nil {
			t.Errorf("Failed to create new transfer ID (%d): %+v", i, err)
		}

		if expected != tid.String() {
			t.Errorf("TransferID #%d string does not match expected."+
				"\nexpected: %s\nreceived: %s", i, expected, tid.String())
		}
	}
}

// Tests that a TransferID JSON marshalled and unmarshalled matches the
// original.
func TestTransferID_JSON_Marshal_Unmarshal(t *testing.T) {
	prng := NewPrng(42)
	tid, err := NewTransferID(prng)
	if err != nil {
		t.Errorf("Failed to create new TransferID: %+v", err)
	}

	data, err := json.MarshalIndent(&tid, "", "\t")
	if err != nil {
		t.Errorf("Failed to JSON marshal TransferID: %+v", err)
	}

	var newTid TransferID
	err = json.Unmarshal(data, &newTid)
	if err != nil {
		t.Errorf("Failed to JSON unmarshal TransferID: %+v", err)
	}

	if !reflect.DeepEqual(tid, newTid) {
		t.Errorf("JSON marshalled and unmarshalled TransferID does not "+
			"match original.\nexpected: %+v\nreceived: %+v", tid, newTid)
	}
}
