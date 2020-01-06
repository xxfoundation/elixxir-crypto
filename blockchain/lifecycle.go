////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

// Package blockchain contains the implementation of our simple blockchain.
package blockchain

import "errors"

type BlockLifecycle uint32

const (
	Raw   BlockLifecycle = iota //Initial state of a newly created block
	Baked                       //State of a block ready for the block chain. Internal data is now accessible & immutable
)

var ErrRaw = errors.New("block is not raw, data or function cannot be accessed")
var ErrBaked = errors.New("block is not baked, data or function cannot be accessed")
