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

	testStrings[0] = testText[0 : DATA_LEN/2]
	testStrings[1] = testText[0:DATA_LEN]

	testStrings[2] = testText[0 : 2*DATA_LEN]

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
var testText = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed" +
	" maximus convallis libero in laoreet. Aenean venenatis auctor condimentum." +
	" Suspendisse sed sapien purus. Ut molestie, mauris id porta ultrices, justo" +
	" nisi bibendum diam, quis facilisis metus ipsum nec dui. Nunc turpis felis," +
	" tristique nec viverra non, ultricies at elit. Ut pretium erat non porta" +
	" bibendum. Cras diam nulla, lobortis vel commodo luctus, dapibus nec nunc." +
	" Pellentesque ac commodo orci. Pellentesque nec nisi maximus, varius odio" +
	" eget, suscipit est. In viverra pretium lobortis. Fusce quis efficitur " +
	" libero. Sed eleifend dictum nulla sed tempus. Donec a tristique dolor, " +
	" quis mattis tellus. Nullam massa elit, ullamcorper ac consectetur ut, " +
	" tincidunt vel erat. Vivamus ut mauris eu ligula pretium tristique id in " +
	" justo. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Fusce" +
	" porttitor, massa non iaculis faucibus, magna metus venenatis nisi," +
	" sodales fringilla enim nulla a erat. Vestibulum posuere ligula a mi " +
	" mollis, quis sodales ipsum hendrerit. Duis a iaculis felis, at " +
	" tristique ligula. In vulputate arcu quam, sit amet consequat lorem" +
	" convallis varius. Donec efficitur semper metus, a sodales dolor " +
	" vestibulum eu. Aliquam et laoreet massa. Phasellus cursus ligula ac " +
	" gravida vehicula. Etiam vitae malesuada nunc. Nunc vitae massa ex. " +
	" Mauris ullamcorper, nunc et rutrum lacinia, est nulla consectetur ex," +
	" non faucibus nulla eros imperdiet justo. Aenean ut velit a odio pretium" +
	" dictum ac nec dui. Vestibulum vulputate nulla vel elit ornare maximus." +
	" Sed egestas diam vel arcu venenatis, nec pulvinar ligula placerat. " +
	" Praesent sed interdum magna. Integer in diam lacus. Sed congue enim eros," +
	" ut ultricies erat porttitor sed. Nullam neque risus, bibendum eu risus ut," +
	" fermentum viverra dolor. Cras non iaculis augue, id euismod metus. In hac" +
	" habitasse platea dictumst. Aenean convallis dignissim commodo. Duis ut" +
	" ultricies turpis. Duis mollis finibus mi dignissim efficitur. Maecenas" +
	" eleifend mi porttitor convallis sed."
