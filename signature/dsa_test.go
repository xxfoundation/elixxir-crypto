////////////////////////////////////////////////////////////////////////////////
// Copyright © 2019 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package signature

import (
	cryptoRand "crypto/rand"
	"errors"
	"gitlab.com/elixxir/crypto/cyclic"
	"math/big"
	"math/rand"
	"testing"
)

func TestCustomDSAParams(t *testing.T) {

	var pExpected, qExpected, gExpected int64 = 1, 1, 1

	p := cyclic.NewInt(pExpected)
	q := cyclic.NewInt(qExpected)
	g := cyclic.NewInt(gExpected)

	dsaParams := CustomDSAParams(p, q, g)

	pActual := dsaParams.params.P.Int64()
	qActual := dsaParams.params.Q.Int64()
	gActual := dsaParams.params.G.Int64()

	if pActual != pExpected {
		t.Errorf("p value doesn't match")
	}
	if qActual != qExpected {
		t.Errorf("q value doesn't match")
	}
	if gActual != gExpected {
		t.Errorf("g value doesn't match")
	}

	pExpected, qExpected, gExpected = 1, 2, 3

	p = cyclic.NewInt(pExpected)
	q = cyclic.NewInt(qExpected)
	g = cyclic.NewInt(gExpected)

	dsaParams = CustomDSAParams(p, q, g)

	pActual = dsaParams.params.P.Int64()
	qActual = dsaParams.params.Q.Int64()
	gActual = dsaParams.params.G.Int64()

	if pActual != pExpected {
		t.Errorf("p value doesn't match")
	}
	if qActual != qExpected {
		t.Errorf("q value doesn't match")
	}
	if gActual != gExpected {
		t.Errorf("g value doesn't match")
	}

	pExpected, qExpected, gExpected = 123, 456, 789

	p = cyclic.NewInt(pExpected)
	q = cyclic.NewInt(qExpected)
	g = cyclic.NewInt(gExpected)

	dsaParams = CustomDSAParams( p, q, g)

	pActual = dsaParams.params.P.Int64()
	qActual = dsaParams.params.Q.Int64()
	gActual = dsaParams.params.G.Int64()

	if pActual != pExpected {
		t.Errorf("p value doesn't match")
	}
	if qActual != qExpected {
		t.Errorf("q value doesn't match")
	}
	if gActual != gExpected {
		t.Errorf("g value doesn't match")
	}

}

type AlwaysErrorReader struct{}

func (r *AlwaysErrorReader) Read(b []byte) (int, error) {
	return 1, errors.New("external system error")
}

func TestNewDSAParamsPanic(t *testing.T) {

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("NewDSAParams should panic on reader error!")
		}
	}()

	r := AlwaysErrorReader{}
	NewDSAParams(&r, L1024N160)

}

func TestPrivateKeyGenValid(t *testing.T) {

	source := rand.NewSource(42)
	rand := rand.New(source)

	p := cyclic.NewInt(1)
	q := cyclic.NewInt(2)
	g := cyclic.NewInt(3)

	sizes := L1024N160

	params := CustomDSAParams(p, q, g)

	privateKey := params.PrivateKeyGen(rand, sizes)

	k := privateKey.GetKey()

	if k.Int64() != 6619692607800168046 {
		t.Errorf("Invalid private key generated")
	}

}

func TestPrivateKeyGenPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("AlwaysErrorReader should panic on reader error!")
		}
	}()

	r := AlwaysErrorReader{}
	params := DSAParameters{}

	params.PrivateKeyGen(&r, L1024N160)
}

func TestDSAParamsGetters(t *testing.T) {

	r := rand.New(rand.NewSource(0))

	params := NewDSAParams(r, L1024N160)

	// Verify

	p := params.GetP()
	q := params.GetQ()
	g := params.GetG()

	pActual := p.TextVerbose(16, 40)
	if pActual != "d99d2415ea76c2d9853e10285f47c26e644cb3e3..." {
		t.Errorf("Invalid p")
	}

	qActual := q.TextVerbose(16, 40)
	if qActual != "9a67144642e88f4b76cdabfa7a9c828765081f9d" {
		t.Errorf("Invalid q")
	}

	gActual := g.TextVerbose(16, 40)
	if gActual != "82b9856ebad01214503a5bfe28c5cda17e455c21..." {
		t.Errorf("Invalid g")
	}

}

func TestDSAPublicKeyGetters(t *testing.T) {
	r := rand.New(rand.NewSource(0))

	params := NewDSAParams(r, L1024N160)

	key := cyclic.NewInt(500)

	pubKey := ReconstructPublicKey(params, key)

	actualParams := pubKey.GetParams()

	p := actualParams.GetP()
	q := actualParams.GetQ()
	g := actualParams.GetG()

	y := pubKey.GetY()

	pActual := p.TextVerbose(16, 40)
	if pActual != "d99d2415ea76c2d9853e10285f47c26e644cb3e3..." {
		t.Errorf("Invalid p")
	}

	qActual := q.TextVerbose(16, 40)
	if qActual != "9a67144642e88f4b76cdabfa7a9c828765081f9d" {
		t.Errorf("Invalid q")
	}

	gActual := g.TextVerbose(16, 40)
	if gActual != "82b9856ebad01214503a5bfe28c5cda17e455c21..." {
		t.Errorf("Invalid g")
	}

	yActual := y.TextVerbose(16, 40)
	if yActual != "1f4" {
		t.Errorf("Invalid y")
	}


}

func TestDSAPublicKeyGen(t *testing.T) {

	source := rand.NewSource(42)
	rand := rand.New(source)

	p := cyclic.NewInt(1)
	q := cyclic.NewInt(2)
	g := cyclic.NewInt(3)

	sizes := L1024N160

	params := CustomDSAParams( p, q, g)

	privateKey := params.PrivateKeyGen(rand, sizes)

	pubKey := privateKey.PublicKeyGen()

	pubKeyVal := privateKey.GetPublicKey()
	pubKeyVal2 := pubKey.GetY()
	if pubKeyVal2.TextVerbose(10, 16) != pubKeyVal.TextVerbose(10,16) {
		t.Errorf("Public key generation failed")
	}

}

func fromHex(s string) *cyclic.Int {
	result, ok := new(big.Int).SetString(s, 16)

	if !ok {
		panic(s)
	}

	return cyclic.NewIntFromBigInt(result)
}

func TestSignAndVerify(t *testing.T) {

	p := fromHex("A9B5B793FB4785793D246BAE77E8FF63CA52F442DA763C440259919FE1BC1D6065A9350637A04F75A2F039401D49F08E066C4D275A5A65DA5684BC563C14289D7AB8A67163BFBF79D85972619AD2CFF55AB0EE77A9002B0EF96293BDD0F42685EBB2C66C327079F6C98000FBCB79AACDE1BC6F9D5C7B1A97E3D9D54ED7951FEF")
	q := fromHex("E1D3391245933D68A0714ED34BBCB7A1F422B9C1")
	g := fromHex("634364FC25248933D01D1993ECABD0657CC0CB2CEED7ED2E3E8AECDFCDC4A25C3B15E9E3B163ACA2984B5539181F3EFF1A5E8903D71D5B95DA4F27202B77D2C44B430BB53741A8D59A8F86887525C9F2A6A5980A195EAA7F2FF910064301DEF89D3AA213E1FAC7768D89365318E370AF54A112EFBA9246D9158386BA1B4EEFDA")


	y := fromHex("32969E5780CFE1C849A1C276D7AEB4F38A23B591739AA2FE197349AEEBD31366AEE5EB7E6C6DDB7C57D02432B30DB5AA66D9884299FAA72568944E4EEDC92EA3FBC6F39F53412FBCC563208F7C15B737AC8910DBC2D9C9B8C001E72FDC40EB694AB1F06A5A2DBD18D9E36C66F31F566742F11EC0A52E9F7B89355C02FB5D32D2")
	x := fromHex("5078D4D29795CBE76D3AACFE48C9AF0BCDBEE91A")

	params := CustomDSAParams(p, q, g)

	pubKey := ReconstructPublicKey(params, y)

	privKey := ReconstructPrivateKey(pubKey, x)

	testSignAndVerify(t, 0, privKey)

}

func testSignAndVerify(t *testing.T, i int, priv *DSAPrivateKey) {

	hashed := []byte("testing")

	signature, err := priv.Sign(hashed, cryptoRand.Reader)

	if err != nil {
		t.Errorf("%d: error signing: %s", i, err)
		return
	}

	publicKey := priv.PublicKeyGen()

	if !publicKey.Verify(hashed, *signature) {

		t.Errorf("%d: Verify failed", i)
	}

}

//func TestSigningWithDegenerateKeys(t *testing.T) {
//
//	// Signing with degenerate private keys should not cause an infinite
//
//	// loop.
//
//	badKeys := []struct {
//		p, q, g, y, x string
//	}{
//
//		{"00", "01", "00", "00", "00"},
//
//		{"01", "ff", "00", "00", "00"},
//	}
//
//	for i, test := range badKeys {
//
//		const base = 10
//		p := cyclic.NewIntFromString(test.p, base)
//		q := cyclic.NewIntFromString(test.q, base)
//		g := cyclic.NewIntFromString(test.g, base)
//		y := cyclic.NewIntFromString(test.y, base)
//		x := cyclic.NewIntFromString(test.x, base)
//
//		params := CustomDSAParams(p, q, g)
//		publicKey := ReconstructPublicKey(params, y)
//		privateKey := ReconstructPrivateKey(publicKey, x)
//
//		hashed := []byte("testing")
//
//		_, err := privateKey.Sign(hashed, cryptoRand.Reader)
//
//		if err == nil {
//
//			t.Errorf("#%d: unexpected success", i)
//
//		}
//
//	}
//
//}

//func TestParameterGeneration(t *testing.T) {
//
//	//if testing.Short() {
//	//
//	//	t.Skip("skipping parameter generation test in short mode")
//	//
//	//}
//
//
//	testParameterGeneration(t, L1024N160, 1024, 160)
//
//	testParameterGeneration(t, L2048N224, 2048, 224)
//
//	testParameterGeneration(t, L2048N256, 2048, 256)
//
//	testParameterGeneration(t, L3072N256, 3072, 256)
//
//}
//
//
//func testParameterGeneration(t *testing.T, sizes ParameterSizes, L, N int) {
//
//	var priv PrivateKey
//
//	params := &priv.Parameters
//
//
//	err := GenerateParameters(params, rand.Reader, sizes)
//
//	if err != nil {
//
//		t.Errorf("%d: %s", int(sizes), err)
//
//		return
//
//	}
//
//	if params.P.BitLen() != L {
//
//		t.Errorf("%d: params.BitLen got:%d want:%d", int(sizes), params.P.BitLen(), L)
//
//	}
//
//	if params.Q.BitLen() != N {
//
//		t.Errorf("%d: q.BitLen got:%d want:%d", int(sizes), params.Q.BitLen(), L)
//
//	}
//
//	one := new(big.Int)
//
//	one.SetInt64(1)
//
//	pm1 := new(big.Int).Sub(params.P, one)
//
//	quo, rem := new(big.Int).DivMod(pm1, params.Q, new(big.Int))
//
//	if rem.Sign() != 0 {
//
//		t.Errorf("%d: p-1 mod q != 0", int(sizes))
//
//	}
//
//	x := new(big.Int).Exp(params.G, quo, params.P)
//
//	if x.Cmp(one) == 0 {
//
//		t.Errorf("%d: invalid generator", int(sizes))
//
//	}
//
//
//	err = GenerateKey(&priv, rand.Reader)
//
//	if err != nil {
//
//		t.Errorf("error generating key: %s", err)
//
//		return
//
//	}
//
//
//	testSignAndVerify(t, int(sizes), &priv)
//
//}
