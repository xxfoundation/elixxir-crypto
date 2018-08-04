package blockchain

import "errors"

type BlockLifecycle uint32

const (
	Raw BlockLifecycle = iota
	Baked
)

var ErrRaw = errors.New("block is not raw, data or function cannot be accessed")
var ErrBaked = errors.New("block is not baked, data or function cannot be accessed")
