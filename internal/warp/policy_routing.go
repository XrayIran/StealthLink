package warp

const (
	DefaultFWMark       = 51888
	DefaultRoutingTable = 51888
	DefaultRulePriority = 11000
)

type PolicyRoutingConfig struct {
	Mark         int
	Table        int
	RulePriority int
	IfaceName    string
	VPNSubnet    string
}
