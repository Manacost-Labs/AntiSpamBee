package moderation

import (
	"antispambee/internal/detection"
	"time"
)

// Evidence preserves the inputs and policy behind an actionable/review decision.
// It deliberately excludes the raw Telegram envelope and expires after 30 days.
type Evidence struct {
	AuthorUsername string
	Version        string
	Target         ActionTarget
	Message        detection.MessageContent
	Profile        detection.Profile
	Signals        []detection.Signal
	Decision       Decision
	Policy         CommunityPolicy
	Protected      bool
	Truncated      bool
}

func newEvidence(target ActionTarget, message detection.MessageContent, profile detection.Profile, signals []detection.Signal, decision Decision, policy CommunityPolicy, protected bool) *Evidence {
	e := &Evidence{Version: DecisionPolicyVersion, Target: target, Message: message, Profile: profile, Signals: signals, Decision: decision, Policy: policy, Protected: protected}
	bound := func(s string) string {
		r := []rune(s)
		if len(r) > 16384 {
			e.Truncated = true
			return string(r[:16384])
		}
		return s
	}
	e.Message.Text = bound(message.Text)
	e.Message.Caption = bound(message.Caption)
	e.Message.OCRText = bound(message.OCRText)
	e.Message.URLs = append([]string(nil), message.URLs...)
	if len(e.Message.URLs) > 32 {
		e.Message.URLs = e.Message.URLs[:32]
		e.Truncated = true
	}
	for i, url := range e.Message.URLs {
		e.Message.URLs[i] = bound(url)
	}
	e.Profile.Bio = bound(profile.Bio)
	if profile.PersonalChannel != nil {
		channel := *profile.PersonalChannel
		channel.Title = bound(channel.Title)
		channel.Description = bound(channel.Description)
		channel.RecentPosts = append([]string(nil), channel.RecentPosts...)
		if len(channel.RecentPosts) > 5 {
			channel.RecentPosts = channel.RecentPosts[:5]
			e.Truncated = true
		}
		for i, post := range channel.RecentPosts {
			channel.RecentPosts[i] = bound(post)
		}
		e.Profile.PersonalChannel = &channel
	}
	return e
}

type ClaimedNotification struct {
	ActionID        string
	TenantID        string
	CommunityChatID int64
	LeaseOwner      string
	Attempts        int
	Payload         DeletionNotification
}

type HistoryEntry struct {
	EventID   string
	CreatedAt time.Time
	Evidence  Evidence
	Actions   string
}
