package format

import (
	"gitlab.com/privategrity/crypto/cyclic"
	"testing"
)

func TestMessagePayload(t *testing.T) {
	tests := 3

	testStrings := make([]string, tests)

	testStrings[0] = "short test"
	testStrings[1] = "Perfect test: Lorem ipsum dolor sit amet, consectetur " +
		"adipiscing elit. Curabitur congue, tellus non rhoncus tincidunt, " +
		"tortor mi rhoncus arcu, quis commodo diam elit nec nisl. Phasellus " +
		"luctus velit a tempus rutrum. Etiam sollicitudin a lorem eget " +
		"consequat. Nunc volutpat diam a vulputate blandit. Fusce congue " +
		"laoreet dignissim. Curabitur fermentum lacus vel mauris mollis, in " +
		"tempor ligula ornare. Ut sit amet arcu tellus. Aenean luctus massa " +
		"lorem, id tempus odio faucibus quis. Cura"

	testStrings[2] = "long test: Lorem ipsum dolor sit amet, consectetur " +
		"adipiscing elit. Quisque vitae elit venenatis, tincidunt tellus " +
		"non, efficitur eros. Maecenas vel fermentum magna, ac varius velit." +
		"Mauris eleifend ullamcorper velit, at aliquam magna semper cursus." +
		"Mauris finibus mauris in suscipit placerat. Mauris fermentum dolor " +
		"nisi, a condimentum lacus imperdiet at. Interdum et malesuada fames " +
		"ac ante ipsum primis in faucibus. Mauris hendrerit nisi in suscipit " +
		"ornare. Maecenas imperdiet luctus tincidunt. Vivamus tortor turpis, " +
		"aliquam facilisis bibendum a, efficitur lobortis dolor. Etiam " +
		"iaculis nunc nec convallis condimentum. Vivamus et mauris vel " +
		"sapien efficitur elementum. Vestibulum ante ipsum primis in " +
		"faucibus orci luctus et ultrices posuere cubilia Curae;  " +
		"Ut fermentum aliquet ornare. Sed tincidunt interdum est sed " +
		"vestibulum. Integer ultricies vitae magna ac venenatis. Curabitur " +
		"a velit sit amet erat tincidunt ullamcorper a id nulla. " +
		"Pellentesque habitant morbi tristique senectus et netus et cras " +
		"amet."

	expectedSlices := make([][][]byte, tests)

	expectedSlices[0] = make([][]byte, 1)

	expectedSlices[0][0] = []byte(testStrings[0])

	expectedSlices[1] = make([][]byte, 2)

	expectedSlices[1][0] = ([]byte(testStrings[1]))[0:DATA_LEN]

	expectedSlices[2] = make([][]byte, 3)

	expectedSlices[2][0] = ([]byte(testStrings[2]))[0:DATA_LEN]
	expectedSlices[2][1] = ([]byte(testStrings[2]))[DATA_LEN : 2*DATA_LEN]
	expectedSlices[2][2] = ([]byte(testStrings[2]))[2*DATA_LEN:]

	for i := 0; i < tests; i++ {
		pldSlc, _ := NewPayload(uint64(i+1), testStrings[i])

		for indx, pld := range pldSlc {
			if uint64(i+1) != pld.senderID.Uint64() {
				t.Errorf("Test of Payload failed on test %v:%v, sID did not "+
					"match;\n  Expected: %v, Received: %v", i, indx, i,
					pld.senderID.Uint64())
			}

			if uint64(i+1) != pld.GetSenderIDUint() {
				t.Errorf("Test of Payload failed on test %v:%v, "+
					"sID UINT did not "+
					"match;\n  Expected: %v, Received: %v", i, indx, i,
					pld.GetSenderIDUint())
			}

			expct := cyclic.NewIntFromBytes(expectedSlices[i][indx])

			if pld.data.Cmp(expct) != 0 {
				t.Errorf("Test of Payload failed on test %v:%v, "+
					"bytes did not "+
					"match;\n Value Expected: %v, Value Received: %v", i, indx,
					string(expct.Bytes()), string(pld.data.Bytes()))
			}

			pld.GetPayloadMIC().SetUint64(uint64(i))
			pld.GetPayloadInitVect().SetUint64(uint64(i * 5))

			serial := pld.SerializePayload()
			deserial := DeserializePayload(serial)

			if deserial.GetPayloadInitVect().Cmp(pld.GetPayloadInitVect()) != 0 {
				t.Errorf("Test of Payload failed on "+
					"test %v: %v, Init Vect did not match post serialization;\n"+
					"  Expected: %v, Recieved: %v ", i, indx,
					pld.GetPayloadInitVect().Text(16),
					deserial.GetPayloadInitVect().Text(16))
			}

			if deserial.GetSenderID().Cmp(pld.GetSenderID()) != 0 {
				t.Errorf("Test of Payload failed on test %v:%v, "+
					"Sender ID did not match post serialization;\n"+
					"  Expected: %v, Recieved: %v ", i, indx,
					pld.GetSenderID().Text(10),
					deserial.GetSenderID().Text(10))
			}

			if deserial.GetData().Cmp(pld.GetData()) != 0 {
				t.Errorf("Test of Payload failed on test %v:%v, "+
					"Data did not match post serialization;\n"+
					"  Expected: %v, Recieved: %v ", i, indx,
					pld.GetData().Text(16),
					deserial.GetData().Text(16))
			}

			if deserial.GetPayloadMIC().Cmp(pld.GetPayloadMIC()) != 0 {
				t.Errorf("Test of Payload failed on test %v:%v, "+
					"Payload MIC did not match post serialization;\n"+
					"  Expected: %v, Recieved: %v ", i, indx,
					pld.GetPayloadMIC().Text(16),
					deserial.GetPayloadMIC().Text(16))
			}
		}

	}

}

func compareByteSlices(a, b *[]byte) bool {
	if len(*a) != len(*b) {
		return false
	}

	for i := 0; i < len(*a); i++ {
		if (*a)[i] != (*b)[i] {

			return false
		}

	}

	return true
}
