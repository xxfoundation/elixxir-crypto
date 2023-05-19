package notifications

import (
	"strconv"
	"testing"
)

func TestNotificationTag_String(t *testing.T) {
	expected := make([]string, 256)
	for i := 0; i < 256; i++ {
		expected[i] = "UnknownTag: " + strconv.Itoa(i)
	}
	expected[RegisterTokenTag] = "RegisterTokenTag"
	expected[UnregisterTokenTag] = "UnregisterTokenTag"
	expected[RegisterTrackedIDTag] = "RegisterTrackedIDTag"
	expected[UnregisterTrackedIDTag] = "UnregisterTrackedIDTag"

	for i := 0; i < 256; i++ {
		nt := NotificationTag(i)
		if nt.String() != expected[i] {
			t.Errorf("Notification tag %d returned the wrong result."+
				"expected %s, got %s", i, expected[i], nt)
		}
	}
}
