////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package format

import (
	"fmt"
	"gitlab.com/privategrity/crypto/cyclic"
	"testing"
)

func TestNewMessage(t *testing.T) {

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
		msglst, _ := NewMessage(uint64(i+1), uint64(i+1), testStrings[i])

		for indx, msg := range msglst {

			if uint64(i+1) != msg.senderID.Uint64() {
				t.Errorf("Test of NewMessage failed on test %v:%v, "+
					"sID did not match;\n  Expected: %v, Received: %v", i,
					indx, i, msg.senderID)
			}

			if uint64(i+1) != msg.recipientID.Uint64() {
				t.Errorf("Test of NewMessage failed on test %v:%v, "+
					"rID did not match;\n  Expected: %v, Received: %v", i,
					indx, i, msg.recipientID)
			}

			expct := cyclic.NewIntFromBytes(expectedSlices[i][indx])

			if msg.data.Cmp(expct) != 0 {
				t.Errorf("Test of NewMessage failed on test %v:%v, "+
					"bytes did not match;\n Value Expected: %v, Value Received: %v", i,
					indx, expct.Text(16), msg.data.Text(16))
			}

			serial := msg.SerializeMessage()
			deserial := DeserializeMessage(serial)

			pldSuccess, pldErr := payloadEqual(msg.Payload, deserial.Payload)

			if !pldSuccess {
				t.Errorf("Test of NewMessage failed on test %v:%v, "+
					"postserial Payload did not match: %s", i, indx, pldErr)
			}

			rcpSuccess, rcpErr := recipientEqual(msg.Recipient,
				deserial.Recipient)

			if !rcpSuccess {
				t.Errorf("Test of NewMessage failed on test %v:%v, "+
					"postserial Recipient did not match: %s", i, indx, rcpErr)
			}

		}

	}

}

func payloadEqual(p1 Payload, p2 Payload) (bool, string) {
	if p1.data.Cmp(p2.data) != 0 {
		return false, fmt.Sprintf("data; Expected %v, Recieved: %v",
			p1.data.Text(16), p2.data.Text(16))
	}

	if p1.senderID.Cmp(p2.senderID) != 0 {
		return false, fmt.Sprintf("sender; Expected %v, Recieved: %v",
			p1.senderID.Text(16), p2.senderID.Text(16))
	}

	if p1.payloadMIC.Cmp(p2.payloadMIC) != 0 {
		return false, fmt.Sprintf("payloadMIC; Expected %v, Recieved: %v",
			p1.payloadMIC.Text(16), p2.payloadMIC.Text(16))
	}

	if p1.payloadInitVect.Cmp(p2.payloadInitVect) != 0 {
		return false, fmt.Sprintf("payloadInitVect; Expected %v, Recieved: %v",
			p1.payloadInitVect.Text(16), p2.payloadInitVect.Text(16))
	}

	return true, ""

}

func recipientEqual(r1 Recipient, r2 Recipient) (bool, string) {
	if r1.recipientID.Cmp(r2.recipientID) != 0 {
		return false, fmt.Sprintf("recipientID; Expected %v, Recieved: %v",
			r1.recipientID.Text(16), r2.recipientID.Text(16))
	}

	if r1.recipientEmpty.Cmp(r2.recipientEmpty) != 0 {
		return false, fmt.Sprintf("empty; Expected %v, Recieved: %v",
			r1.recipientEmpty.Text(16), r2.recipientEmpty.Text(16))
	}

	if r1.recipientMIC.Cmp(r2.recipientMIC) != 0 {
		return false, fmt.Sprintf("recipientMIC; Expected %v, Recieved: %v",
			r1.recipientMIC.Text(16), r2.recipientMIC.Text(16))
	}

	if r1.recipientInitVect.Cmp(r2.recipientInitVect) != 0 {
		return false, fmt.Sprintf("payloadInitVect; Expected %v, Recieved: %v",
			r1.recipientInitVect.Text(16), r2.recipientInitVect.Text(16))
	}

	return true, ""

}

//TODO: Test End cases, messages over 2x length, at max length, and others.
