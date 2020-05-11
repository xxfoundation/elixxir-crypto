////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package csprng

import (
	"gitlab.com/elixxir/crypto/large"
	"os"
	"testing"
	"time"
)

const MODP4096 = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
	"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
	"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
	"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
	"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
	"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
	"15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" +
	"ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
	"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" +
	"F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
	"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" +
	"43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7" +
	"88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA" +
	"2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6" +
	"287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED" +
	"1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9" +
	"93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199" +
	"FFFFFFFFFFFFFFFF"

const MODP2048 = "9DB6FB5951B66BB6FE1E140F1D2CE5502374161FD6538DF1" +
	"648218642F0B5C48C8F7A41AADFA187324B87674FA1822B0" +
	"0F1ECF8136943D7C55757264E5A1A44FFE012E9936E00C1D" +
	"3E9310B01C7D179805D3058B2A9F4BB6F9716BFE6117C6B5" +
	"B3CC4D9BE341104AD4A80AD6C94E005F4B993E14F091EB51" +
	"743BF33050C38DE235567E1B34C3D6A5C0CEAA1A0F368213" +
	"C3D19843D0B4B09DCB9FC72D39C8DE41F1BF14D4BB4563CA" +
	"28371621CAD3324B6A2D392145BEBFAC748805236F5CA2FE" +
	"92B871CD8F9C36D3292B5509CA8CAA77A2ADFC7BFD77DDA6" +
	"F71125A7456FEA153E433256A2261C6A06ED3693797E7995" +
	"FAD5AABBCFBE3EDA2741E375404AE25B"

const P107 = "6B"

const LARGE_PRIME = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
	"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
	"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
	"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
	"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
	"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
	"15728E5A8AACAA68FFFFFFFFFFFFFFFF"

const NONBYTEALIGNED_PRIME = "E2EE983D031DC1DB6F1A7A67DF0E9A8E5561DB8E8D49413394C049B" +
	"7A8ACCEDC298708F121951D9CF920EC5D146727AA4AE535B0922C688B55B3DD2AE" +
	"DF6C01C94764DAB937935AA83BE36E67760713AB44A6337C20E7861575E745D31F" +
	"8B9E9AD8412118C62A3E2E29DF46B0864D0C951C394A5CBBDC6ADC718DD2A3E041" +
	"023DBB5AB23EBB4742DE9C1687B5B34FA48C3521632C4A530E8FFB1BC51DADDF45" +
	"3B0B2717C2BC6669ED76B4BDD5C9FF558E88F26E5785302BEDBCA23EAC5ACE9209" +
	"6EE8A60642FB61E8F3D24990B8CB12EE448EEF78E184C7242DD161C7738F32BF29" +
	"A841698978825B4111B4BC3E1E198455095958333D776D8B2BEEED3A1A1A221A6E" +
	"37E664A64B83981C46FFDDC1A45E3D5211AAF8BFBC072768C4F50D7D7803D2D4F2" +
	"78DE8014A47323631D7E064DE81C0C6BFA43EF0E6998860F1390B5D3FEACAF1696" +
	"015CB79C3F9C2D93D961120CD0E5F12CBB687EAB045241F96789C38E89D796138E" +
	"6319BE62E35D87B1048CA28BE389B575E994DCA755471584A09EC723742DC35873" +
	"847AEF49F66E43873"

var p107 []byte
var modp2048 []byte
var modp4096 []byte
var largePrime []byte
var nonByteAlignedPrime []byte

func TestMain(m *testing.M) {
	nonByteAlignedPrime = large.NewIntFromString(NONBYTEALIGNED_PRIME, 16).Bytes()
	largePrime = large.NewIntFromString(LARGE_PRIME, 16).Bytes()
	p107 = large.NewIntFromString(P107, 16).Bytes()
	modp2048 = large.NewIntFromString(MODP2048, 16).Bytes()
	modp4096 = large.NewIntFromString(MODP4096, 16).Bytes()
	os.Exit(m.Run())
}

// TestInGroup_Empty tests if empty slice is ever in the group
func TestInGroup_Empty(t *testing.T) {
	zero := []byte{}

	//Note these test different code paths because of the slice len
	if InGroup(zero, p107) {
		t.Errorf("Empty slice is never in the group! Not even p107!")
	}
	if InGroup(zero, modp2048) {
		t.Errorf("Empty slice is never in the group! Not even modp2048!")
	}
	if InGroup(zero, modp4096) {
		t.Errorf("Empty slice is never in the group! Not even modp4096!")
	}
}

// TestInGroup_0 tests if 0 is ever in the group
func TestInGroup_0(t *testing.T) {
	zero := []byte{0}

	if InGroup(zero, p107) {
		t.Errorf("Zero is never in the group! Not even p107!")
	}
	if InGroup(zero, modp2048) {
		t.Errorf("Zero is never in the group! Not even modp2048!")
	}
	if InGroup(zero, modp4096) {
		t.Errorf("Zero is never in the group! Not even modp4096!")
	}
}

// TestInGroup_P tests if the prime is ever in the group.
func TestInGroup_P(t *testing.T) {
	//Note these test different code paths because of the slice len
	if InGroup(p107, p107) {
		t.Errorf("p107 is never in the group for p107!")
	}
	if InGroup(modp2048, modp2048) {
		t.Errorf("modp2048 is never in the group for modp2048!")
	}
	if InGroup(modp4096, modp4096) {
		t.Errorf("modp4096 is never in the group for modp4096!")
	}
	if !InGroup(p107, modp2048) {
		t.Errorf("p107 is always in the group for modp2048!")
	}
	if !InGroup(p107, modp4096) {
		t.Errorf("p107 is always in the group for modp4096!")
	}
	if !InGroup(modp2048, modp4096) {
		t.Errorf("modp2048 is always in the group for modp4096!")
	}
	if InGroup(modp2048, p107) {
		t.Errorf("modp2048 is never in the group for p107!")
	}
	if InGroup(modp4096, p107) {
		t.Errorf("modp4096 is never in the group for p107!")
	}
	if InGroup(modp4096, modp2048) {
		t.Errorf("modp4096 is never in the group for modp2048!")
	}
}

// TestInGroup_1 tests that 1 is always in the group.
func TestInGroup_1(t *testing.T) {
	one32 := []byte{0, 0, 0, 1}
	one := []byte{1}

	// one32 is not in p107 because it's 4 bytes (longer than 107)
	if InGroup(one32, p107) {
		t.Errorf("32bit 1 is never in the group for p107!")
	}

	if !InGroup(one, p107) {
		t.Errorf("1 is always in the group for p107!")
	}
	if !InGroup(one32, modp2048) {
		t.Errorf("1 is always in the group for modp2048!")
	}
	if !InGroup(one, modp2048) {
		t.Errorf("1 is always in the group for modp2048!")
	}
	if !InGroup(one32, modp4096) {
		t.Errorf("1 is always in the group for modp4096!")
	}
	if !InGroup(one, modp4096) {
		t.Errorf("1 is always in the group for modp4096!")
	}
}

// TestInGroupPsub1 tests that P - 1 is in the group
func TestInGroup_Psub1(t *testing.T) {
	one := large.NewInt(1)

	p107sub1 := large.NewInt(0)
	p107sub1.Sub(large.NewIntFromString(P107, 16), one)

	p2048sub1 := large.NewInt(0)
	p2048sub1.Sub(large.NewIntFromString(MODP2048, 16), one)

	p4096sub1 := large.NewInt(0)
	p4096sub1.Sub(large.NewIntFromString(MODP4096, 16), one)

	if !InGroup(p107sub1.Bytes(), p107) {
		t.Errorf("p107sub1 is always in group for p107!")
	}
	if !InGroup(p2048sub1.Bytes(), modp2048) {
		t.Errorf("p2048sub1 is always in group for modp2048!")
	}
	if !InGroup(p4096sub1.Bytes(), modp4096) {
		t.Errorf("p4096sub1 is always in group for modp4096!")
	}
}

// TestInGroupPplus1 tests that P + 1 is not in the group
func TestInGroup_Pplus1(t *testing.T) {
	one := large.NewInt(1)

	p107plus1 := large.NewInt(0)
	p107plus1.Add(large.NewIntFromString(P107, 16), one)

	p2048plus1 := large.NewInt(0)
	p2048plus1.Add(large.NewIntFromString(MODP2048, 16), one)

	p4096plus1 := large.NewInt(0)
	p4096plus1.Add(large.NewIntFromString(MODP4096, 16), one)

	if InGroup(p107plus1.Bytes(), p107) {
		t.Errorf("p107plus1 is never in group for p107!")
	}
	if InGroup(p2048plus1.Bytes(), modp2048) {
		t.Errorf("p2048plus1 is never in group for modp2048!")
	}
	if InGroup(p4096plus1.Bytes(), modp4096) {
		t.Errorf("p4096plus1 is never in group for modp4096!")
	}
}

// TestGenerateInGroup_LargeSize tests that GenerateInGroup
// eventually generates a number in the small group
func TestGenerateInGroup_LargeSize(t *testing.T) {
	rng := NewSystemRNG()

	timeout := time.After(3 * time.Second)
	done := make(chan bool)
	go func() {
		// do your testing
		b, err := GenerateInGroup(p107, 32, rng)
		if err != nil {
			t.Errorf("%v", err)
		}
		if !InGroup(b, p107) {
			t.Errorf("b not in p107: %v", b)
		}
		done <- true
	}()

	select {
	case <-timeout:
		t.Fatal("GenerateInGroup took too long to complete!")
	case <-done:
	}
}

//Happy path with a large, byte aligned path
func TestGenerate(t *testing.T) {
	rng := NewSystemRNG()

	b, err := GenerateInGroup(largePrime, len(largePrime), rng)
	if err != nil {
		t.Errorf("%v", err)
	}
	if !InGroup(b, largePrime) {
		t.Errorf("b not in largePrime: %v", b)
	}
	if len(b) != len(largePrime) {
		t.Errorf("Failed to generate a value of same length of prime! "+
			"Expected %v bytes, generated %v bytes", len(largePrime), len(b))
	}

}

//Happy path with a non byte aligned prime
func TestGenerate_Padding(t *testing.T) {
	rng := NewSystemRNG()

	b, err := GenerateInGroup(nonByteAlignedPrime, len(nonByteAlignedPrime), rng)
	if err != nil {
		t.Errorf("%v", err)
	}
	if !InGroup(b, nonByteAlignedPrime) {
		t.Errorf("b not in largePrime: %v", b)
	}
	if len(b) != len(nonByteAlignedPrime) {
		t.Errorf("Failed to generate a value of same length of prime! "+
			"Expected %v bytes, generated %v bytes", len(nonByteAlignedPrime), len(b))
	}
}
