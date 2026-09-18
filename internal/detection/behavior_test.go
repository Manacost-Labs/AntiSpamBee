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
	if signal.Score == nil || *signal.Score < 0.9 || !containsString(signal.ReasonCodes, ReasonFlood) {
		t.Fatalf("signal = %#v", signal)
	}
}

func TestBehaviorDetectorBansRepeatViolator(t *testing.T) {
	detector := NewBehaviorDetector()
	signal := detector.Analyze(BehaviorStats{PreviousViolations: 2})
	if signal.Score == nil || *signal.Score != 1 {
		t.Fatalf("signal = %#v", signal)
	}
}
