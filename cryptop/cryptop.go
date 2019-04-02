package cryptop

type Cryptop interface {
	GetFuncName() string
	GetMinSize() uint32
}
