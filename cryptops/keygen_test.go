package cryptops

import (
	"gitlab.com/privategrity/crypto/cyclic"
	"testing"
)

func TestGenerateSharedKey(t *testing.T) {
	primes := []*cyclic.Int{cyclic.NewIntFromString(
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
			"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
			"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
			"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
			"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"+
			"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"+
			"83655D23DCA3AD961C62F356208552BB9ED529077096966D"+
			"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"+
			"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"+
			"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"+
			"15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"+
			"ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"+
			"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"+
			"F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"+
			"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"+
			"43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7"+
			"88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA"+
			"2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6"+
			"287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED"+
			"1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9"+
			"93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199"+
			"FFFFFFFFFFFFFFFF", 16),
		cyclic.NewIntFromString("17", 10)}

	tests := 2
	pass := 0

	var g []cyclic.Group
	for i := 0; i < tests; i++ {
		g = append(g, cyclic.NewGroup(primes[i], cyclic.NewInt(55), cyclic.NewInt(33), cyclic.NewRandom(cyclic.NewInt(2), cyclic.NewInt(1000))))
	}

	// 65536 bits for the long key
	outSharedKeyStorage := make([]byte, 0, 8192)

	recursiveKeys := []*cyclic.Int{cyclic.NewIntFromString(
		"ef9ab83927cd2349f98b1237889909002b897231ae9c927d1792ea0879287ea3",
		16), cyclic.NewIntFromString(
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		16)}

	outSharedKey := cyclic.NewMaxInt()

	baseKey := []*cyclic.Int{cyclic.NewIntFromString(
		"da9f8137821987b978164932015c105263ae769310269b510937c190768e2930",
		16),
		cyclic.NewIntFromString(
			"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			16)}

	expectedSharedKeys := []*cyclic.Int{cyclic.NewIntFromString(
		"4de2e3e634b726d210afd0284a2cac0653eb37a347b34aac683b335653fd"+
			"28fb4ca84073c1ce65ed54b04c64e8033635b40ebbc0c2ce6e406ed8f688"+
			"9a9e28920fef9c048ed92cddae1e8859afc77da66a7a7cd77932c52efa20"+
			"c2fc1bc848f44e541874062692afeaeb17d62bdbc75e34681274fe129b8e"+
			"a7bed6a980cea7746e865af076c48de8b19940253a6ee658aed316affa29"+
			"1c5385b51b1105855a4aaf2c362b16f209f8ca45486dcc257cb2d88f9ad6"+
			"62c33bc1e9ac27e23e193ca38e2b560dd18a4b3da22e668bbc54d7820f29"+
			"7ceebacbb22003ae87b85c534498f7ddc039cd991246d9d0352d8cedc321"+
			"8c8f729488858cf3dfa6147003c1948a68b65e55e73cdc8f81eaf5780c85"+
			"b7bc6beb3ad3cf36caaaca464804d2409f936c997909e29de89808a42e14"+
			"508012c5e06a4449b396aa01eba6ea8b563a55df3f43d472ea2aec7078a9"+
			"914ab391d0032c59abbd1eeb65d03bc532ac6130f830ed29380a0b2d40f4"+
			"0f33e7acfb739f243fcc7f8070186641f6e1b8d9e3e051663521a4b1e898"+
			"2337b3ea818d2df6aeb3256d118ba6b2695301c81f1230d057ca1fdcbfd5"+
			"205580e4ca71b190548f88c7b058c1dee515bbde6c6b4eb7c78ddb1fd5d6"+
			"3b224be2d8b066b0d00744365fde76f086992a942a669881e4302615c6d4"+
			"c4204c07bb05766cbcd8cbac7ac0d862a3f5e02036543af53684c63412b6"+
			"9b8f", 16),
		cyclic.NewIntFromString("d", 16)}

	expectedRecursiveKeys := []*cyclic.Int{
		cyclic.NewIntFromString("5577eca469086dd710d29d28117d7014c0ebbfb28fe488c2a2297e33f5dc6441", 16),
		cyclic.NewIntFromString("a957f9b2863d5575eb23092f846a8addd669b6caaec02df65b2d174648f28179", 16)}

	for i := 0; i < tests; i++ {
		GenerateSharedKey(&g[i], baseKey[i],
			recursiveKeys[i], outSharedKey, outSharedKeyStorage)
		if outSharedKey.Cmp(expectedSharedKeys[i]) != 0 {
			t.Errorf("Shared key didn't match at index %d. Expected 0x%v, actual 0x%v\n", i, expectedSharedKeys[i].Text(16), outSharedKey.Text(16))
		} else if recursiveKeys[i].Cmp(expectedRecursiveKeys[i]) != 0 {
			t.Errorf("Recursive key didn't match at index %d. Expected 0x%v, actual 0x%v\n", i, expectedRecursiveKeys[i].Text(16), recursiveKeys[i].Text(16))
		} else {
			pass++
		}
	}

	println("GenerateSharedKey():", pass, "out of", tests, "tests passed.")
}
