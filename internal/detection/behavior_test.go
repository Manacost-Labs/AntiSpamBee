package detection

import "testing"

func TestBehaviorDetectorFlagsDuplicateSpam(t *testing.T) {
	detector := NewBehaviorDetector()
	signal := detector.Analyze(BehaviorStats{DuplicateCount: 3, MessagesInWindow: 3})
	if signal.Score == nil || *signal.Score < 0.9 || !containsString(signal.ReasonCodes, ReasonDuplicateSpam) {
		t.Fatalf("signal = %#v", signal)
	}
}

func TestBehaviorDetectorFlagsFlood(t *testing.T) {
	detector := NewBehaviorDetector()
	signal := detector.Analyze(BehaviorStats{MessagesInWindow: 5})
	if signal.Score == nil || *signal.Score != 0.5 || !containsString(signal.ReasonCodes, ReasonFlood) {
		t.Fatalf("signal = %#v", signal)
	}
}

func TestBehaviorDetectorDoesNotEscalateUnconfirmedHistory(t *testing.T) {
	detector := NewBehaviorDetector()
	signal := detector.Analyze(BehaviorStats{PreviousViolations: 2})
	if signal.Score == nil || *signal.Score >= .90 {
		t.Fatalf("signal = %#v", signal)
	}
}
