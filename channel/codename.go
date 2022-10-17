////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package channel

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"hash"
	"math"

	jww "github.com/spf13/jwalterweatherman"
)

const (
	honorificSalt = "honorificSalt"
	adjectiveSalt = "adjectiveSalt"
	nounSalt      = "nounSalt"
	colorSalt     = "colorSalt"
	extensionSalt = "extensionSalt"
)

// Codeset versions.
const (
	// currentCodesetVersion should always point to the newest codeset version
	// that new Identity objects should be generated with.
	currentCodesetVersion = codesetV0
	codesetV0             = 0
)

type identityConstructor func(pub ed25519.PublicKey, codeset uint8) (Identity, error)

// identityConstructorCodesets is a map of codeset version to its constructor.
var identityConstructorCodesets = map[uint8]identityConstructor{
	codesetV0: constructIdentityV0,
}

type sampler struct {
	sampleFrom       [][]string
	bitDepthLanguage uint8
	bitDepthEach     []uint8
}

var honorifics = sampler{
	sampleFrom:       [][]string{engHonorifics},
	bitDepthLanguage: 0,
	bitDepthEach:     []uint8{getBitDepth(len(engHonorifics))},
}

var adjectives = sampler{
	sampleFrom:       [][]string{engAdjV0[:]},
	bitDepthLanguage: 0,
	bitDepthEach:     []uint8{getBitDepth(len(engAdjV0))},
}

var nouns = sampler{
	sampleFrom:       [][]string{engNounV0[:]},
	bitDepthLanguage: 0,
	bitDepthEach:     []uint8{getBitDepth(len(engNounV0))},
}

var depthBlinders = makeDepthBlinders()

type CodeNamePart struct {
	Lang      Language
	Generated string
}

var colorBitDepth = getBitDepth(len(colorsV0))

func generateCodeNamePart(h hash.Hash, data []byte, c string, s sampler) CodeNamePart {

	// only one language currently, we will upgrade this
	lang := English

	d := uint64(math.MaxUint64)

	for d > uint64(len(s.sampleFrom[lang]))-1 {
		data = hasher(h, data, c)
		d = binary.BigEndian.Uint64(data)
		d = d & depthBlinders[s.bitDepthEach[lang]]
	}

	return CodeNamePart{
		Lang:      lang,
		Generated: s.sampleFrom[lang][d],
	}
}

func generateColor(h hash.Hash, data []byte) string {

	d := uint64(math.MaxUint64)

	for d > uint64(len(colorsV0))-1 {
		data = hasher(h, data, colorSalt)
		d = binary.BigEndian.Uint64(data)
		d = d & depthBlinders[colorBitDepth]
	}

	return colorsV0[d]
}

func generateExtension(h hash.Hash, data []byte) string {
	data = hasher(h, data, extensionSalt)
	return base64.StdEncoding.EncodeToString(data)[:30]
}

func hasher(h hash.Hash, data []byte, c string) []byte {
	h.Reset()
	h.Write(data)
	h.Write([]byte(c))
	return h.Sum(nil)
}

func getBitDepth(l int) uint8 {
	bd := int(math.Ceil(math.Log2(float64(l))))
	if float64(bd)/float64(l) < .5 {
		jww.WARN.Printf("The received bit depth is less than half " +
			"generation will be inefficent")
	}
	return uint8(bd)
}

func makeDepthBlinders() []uint64 {
	blinders := make([]uint64, 65)
	for i := 1; i <= 64; i++ {
		blinders[i] = math.MaxUint64 >> (64 - i)
	}
	return blinders
}
