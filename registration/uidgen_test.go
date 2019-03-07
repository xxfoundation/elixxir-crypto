package registration

import (
	"encoding/hex"
	"gitlab.com/elixxir/crypto/cyclic"
	"testing"
)

func TestGenUserID(t *testing.T) {
	pkeys := []*cyclic.Int{
		//4096 bit key
		cyclic.NewIntFromString("9dce0aff905924e77043dd70321bb47f7b598dde9cb085f00e067ccee56fcb26"+
			"b5a627f880100943f97872e4e667d6525f61331e6a6462e3a42edd6342bc1625"+
			"dd44b486fc681ffed77e7b119a14845f2f8c76a92179d0db9d9f5844d7b5ee80"+
			"83fffb3f887807283ce62088855c5e83cd7a408762a1c2326322f6cdd577aba8"+
			"8a5cb4fe27fb2b5f2d3958b7d136febc86ff3d4102081952cb59ada25defc6f0"+
			"9be805222e1577a9ac2ac7ffe5774a85a76ed86629071c4873452b8cf135da27"+
			"4ff8a9c4693d45ad9a0789c3d471a936d30fa2e1211303d931f06bf4eb91b613"+
			"e81a6e37bf5919475c5ede97b9db77e8ac9d0e77f18322877a99d786aea36376"+
			"84454b1c0be652118054ca88e6f861e427a027f8c3909bdf85f23c8ccdef1d4e"+
			"020ed13faa4586e08051322f08ddf6b245a4c96fcc9b4676e682081c1541dab9"+
			"15f69cef8b321ff0975e733a44480bc13971e82b2607759cb654592376c8e204"+
			"7ffec4b72c68e3fb751cf7c196edb782c9ef283ece059a3e553b3bd372c35000"+
			"3074eb044910346490e192723c6937ef29b03f3df214379f93d9353e253862df"+
			"46a21faa97e33c7b357cf50310c0f39fdb1972cb758bb4f9f49bf8e55251c95d"+
			"71328e3d52a35ae09bf8cc393a82bc9a822bb86836e0c4fc217d3ebee5f13843"+
			"dff097c80060ab74ff0704c2b582667763dbce07dfb760a227131189de571f6d", 16),
		//3072 bit key
		cyclic.NewIntFromString("63d10305bbed3de62aef3e6d0485ed110cf2db0a7e89038aa6fef44e126d18bb"+
			"4b62e8cd4ca12c7284bb5e1fcb80e65c7a324ed59f4fb242b15a2d399ad1501b"+
			"a33ef0f896fb12f6bb5f0f07f96dc4b2bc84f5c292d75d6a6069fddaf2a5df37"+
			"2dada7b9da659581ea6709cf287a6b4284d196e2b9e15a2ff34432ab2de53edc"+
			"e7f5ad82c54192f958dd1b1ed8e60ce533b5c16ec942ccaa11609fb498b77d48"+
			"ba3dc6171a4700d6430c59c04b4c7042d44156ec27606475fb1ef9f31bfa2d24"+
			"4356ec71e5a9446ab0756bdae70ba70fafe3a5dc9a96c09ea2d38622ac23a78e"+
			"3fe6f50f14e1077273e8a56e980d4646479d47a8a3f28aed3273233f369d234c"+
			"764beaa1f21741068121fe892ec4fc06fc1d76bc1a8a9261f4093e7e42f4014d"+
			"62d901abf2fe873df4d8db7f91f4f54d4ffe81332a25518f3754614c508ebd0c"+
			"8a7b70bf193af01a31dbf863fc4c38756c46800151ccc4a1796662686185de8d"+
		//2048 bit key
			"d2fcd9ffd855c5ed501cecba3b61b33245b681822d32923dd1ad86b5daeec9b8", 16),
		cyclic.NewIntFromString("8d8d79614fa2ca9a6bafa37d547e77a8f0bd3301332f350a3ac994f7e611c497"+
			"a087bebc8e7ecab7c888b6d31dbeb88910be29a2ccb32821c769f51d202baf75"+
			"33b40493588c3ae64eede47e08fc4ee4fe2c93459a2cfd95cf168505c20846b5"+
			"0812a3582ecf177817fbf4bceb123cd5141479cc0e4109a500cd70f9f820dacb"+
			"2ea108453880da187dba4151eb692bc775fe7916a41db59e3f6c4851ac0f1350"+
			"c2a5ad515b89c0876273c1bed2348f8181f6dbca0f3d0c892bff9717670ac79a"+
			"c016917f00b90aa52e3108c22995f89bbb52ae0eac21985e4539a64f1e79fa10"+
			"81a7458a0840a58082b30f8d9b251d7b60ae18905e74e17982c53f7fe8763b72", 16),
		//1024 bit key
		cyclic.NewIntFromString("106d98c7ea987c3aa10aa03d8aae653694f0cba42d190e1d49650136af7c594e"+
			"ac628aa06fd6835427f4e2c6c18a9f0873ab9b2b666a5a9d6f36e922b6fae349"+
			"de6ae91cb1a518544371d2f9a04c411ca4f50aeef9c8553d86103cec8687055c"+
			"25bda9ae2587bfe35e36cbb99a0eb1281c765304fc72bd9cd9662e9486aa93ac", 16),
		cyclic.NewIntFromBytes(make([]byte, 0)),
		nil,
	}
	salts := [][]byte{
		[]byte("0123456789ABCDEF0123456789ABCDEF"),
		[]byte("0123456789ABCDEF"),
		[]byte(""),
		nil,
	}

	tests := len(pkeys) * len(salts)
	pass := 0

	for i := 0; i < tests; i++ {
		user, err := GenUserID(pkeys[i%len(pkeys)], salts[i/len(pkeys)])
		if i%len(pkeys) >= 4 || i/len(pkeys) >= 2 {
			if user != nil || err == nil {
				t.Errorf("UserID generation should have returned error")
			} else {
				pass++
			}
		} else {
			if err != nil {
				t.Errorf("UserID generation returned error: %s", err.Error())
			} else {
				pass++
			}
		}
	}
}

func TestGenUserID_Random(t *testing.T) {
	rng := cyclic.NewRandom(cyclic.NewInt(2), cyclic.NewIntFromBytes(cyclic.Max4kBitInt))

	tests := 10000

	userMap := make(map[string]bool)
	pkey := cyclic.NewInt(1)

	for i := 0; i < tests; i++ {
		rng.Rand(pkey)
		salt, _ := cyclic.GenerateRandomBytes(32)
		user, err := GenUserID(pkey, salt)
		if err != nil {
			t.Errorf("UserID generation returned error: %s", err.Error())
		} else {
			userMap[hex.EncodeToString(user.Bytes())] = true
		}
	}

	if len(userMap) < tests {
		t.Errorf("At least 2 out of %d UserIDs have the same value", tests)
	}
}
