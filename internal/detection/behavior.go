package detection

import "time"

const (
	ReasonDuplicateSpam       = "DUPLICATE_SPAM"
	ReasonFlood               = "MESSAGE_FLOOD"
	ReasonPriorViolation      = "PRIOR_MODERATION_VIOLATIONS"
	ReasonBehaviorStoreFailed = "BEHAVIOR_STORE_FAILED"
)

// BehaviorStats is a bounded activity snapshot computed by durable storage.
type BehaviorStats struct {
	DuplicateCount     int
	MessagesInWindow   int
	PreviousViolations int
}

// BehaviorDetector converts message history into an explainable signal.
type BehaviorDetector struct {
	now func() time.Time
}

func NewBehaviorDetector() *BehaviorDetector {
	return &BehaviorDetector{now: time.Now}
}

func (d *BehaviorDetector) Analyze(stats BehaviorStats) Signal {
	score := 0.0
	reasons := []string{}
	rules := []string{}
	if stats.PreviousViolations >= 2 {
		// Historical machine decisions are unconfirmed; they cannot escalate to a ban.
		score = 0.5
		reasons = append(reasons, ReasonPriorViolation)
		rules = append(rules, "BEHAVIOR_REPUTATION_01")
	}
	if stats.DuplicateCount >= 3 {
		if score < 0.95 {
			score = 0.95
		}
		reasons = appendUnique(reasons, ReasonDuplicateSpam)
		rules = append(rules, "BEHAVIOR_DUPLICATE_01")
	}
	if stats.MessagesInWindow >= 5 {
		if score < 0.95 {
			score = 0.95
		}
		reasons = appendUnique(reasons, ReasonFlood)
		rules = append(rules, "BEHAVIOR_FLOOD_01")
	}
	confidence := 0.95
	return Signal{
		SchemaVersion:    "1",
		Detector:         "behavior.spam",
		DetectorVersion:  "behavior-v1",
		Category:         "spam.behavior",
		Status:           StatusAvailable,
		Score:            &score,
		Confidence:       &confidence,
		Severity:         severityFor(score),
		EvidenceCoverage: 1,
		ReasonCodes:      reasons,
		MatchedRules:     rules,
		CreatedAt:        d.now().UTC(),
	}
}
