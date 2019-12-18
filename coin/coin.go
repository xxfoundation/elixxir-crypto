////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package coin

// An individual coin in the system
type Coin [CoinLen]byte

// Returns the denomination of the coin
func (c Coin) GetDenomination() Denomination {
	return Denomination(c[CoinDenominationLoc])
}

// Returns the value of the coin
func (c Coin) Value() uint64 {
	return c.GetDenomination().Value()
}
