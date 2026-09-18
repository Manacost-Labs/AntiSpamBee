package moderation

// CommunityPolicy is the small policy surface required by the decision path.
type CommunityPolicy struct {
	ProtectionLevel         string
	AutomaticActionsEnabled bool
	AutobanEnabled          bool
	IsAllowlisted           bool
}
