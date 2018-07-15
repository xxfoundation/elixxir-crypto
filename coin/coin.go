package coin

// An individual coin in the system
type Coin [CoinLen]byte

// Returns the prefix of the coin
func (c Coin) GetPrefix() byte {
	return c[CoinPrefixLoc]
}

// Returns the denomination of the coin
func (c Coin) GetDenomination() Denomination {
	return Denomination(c[CoinDenominationLoc] & (DenominationMask))
}

// Returns the value of the coin
func (c Coin) GetValue() uint64 {
	return c.GetDenomination().Value()
}
