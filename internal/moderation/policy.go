package moderation

// CommunityPolicy is the small policy surface required by the decision path.
type CommunityPolicy struct {
	ChatID                  int64
	ProtectionLevel         string
	AutomaticActionsEnabled bool
	AutobanEnabled          bool
	IsAllowlisted           bool
	ModeratorChatID         int64
}
