package notifications

type NotificationTag uint8

// Tags defining which operation is being executed, they ensure that
// the operation cannot be changed
const (
	RegisterTokenTag NotificationTag = iota
	UnregisterTokenTag
	RegisterTrackedIDTag
	UnregisterTrackedIDTag
)

func (nt NotificationTag) String() string {
	switch nt {
	case RegisterTokenTag:
		return "RegisterTokenTag"
	case UnregisterTokenTag:
		return "UnregisterTokenTag"
	case RegisterTrackedIDTag:
		return "RegisterTrackedIDTag"
	case UnregisterTrackedIDTag:
		return "UnregisterTrackedIDTag"
	default:
		return "UnknownTag"
	}
}
