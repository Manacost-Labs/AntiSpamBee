package moderation

// CommandCommit persists settings and replies with the command decision. Only
// the first committed decision may apply the mutation; replies have their own
// durable delivery lifecycle and do not cause command execution on retry.
type CommandCommit struct {
	Mutation CommandMutation
	Replies  []CommandReply
}

type CommandMutation struct {
	ChatID          int64
	ProtectionLevel string
	ModeratorUserID int64
	SenderChatID    int64
	Allowlist       *AllowlistChange
}

type AllowlistChange struct {
	UserID  int64
	AddedBy int64
	Allowed bool
}

// These replies contain settings confirmations, not archived message content.
type CommandReply struct {
	ChatID        int64  `json:"chat_id"`
	Text          string `json:"text"`
	ReviewEventID string `json:"review_event_id,omitempty"`
}

type ClaimedCommandReply struct {
	ReplyID    string
	TenantID   string
	LeaseOwner string
	Attempts   int
	Reply      CommandReply
}
