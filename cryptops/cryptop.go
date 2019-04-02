package cryptops

type Cryptop interface {
	GetFuncName() string
	GetMinSize() uint32
}
