// Package evaluation replays detection without network access or Telegram actions.
package evaluation

import (
	"fmt"
	"math"
	"strings"

	"antispambee/internal/detection"
	"antispambee/internal/moderation"
)

type Example struct {
	ID       string              `json:"id"`
	Label    string              `json:"label"`
	Split    string              `json:"split"`
	Campaign string              `json:"campaign"`
	Source   string              `json:"source"`
	Evidence moderation.Evidence `json:"evidence"`
}

type Report struct {
	Mode                               string
	Source                             string
	Representative                     bool
	TP, FP, TN, FN                     int
	Uncertain, Reviews, ModelAvailable int
	Precision, Recall                  *float64
	Precision95Lower                   *float64
	FalsePositiveIDs, FalseNegativeIDs []string
	PolicyVersion                      string
}

func Evaluate(examples []Example, split, mode string, representative bool) (Report, error) {
	r := Report{Mode: mode, Representative: representative, PolicyVersion: moderation.DecisionPolicyVersion}
	if (split != "test" && split != "dev") || (mode != "rules" && mode != "replay") {
		return r, fmt.Errorf("invalid split or mode")
	}
	ids, campaigns := map[string]bool{}, map[string]string{}
	for _, e := range examples {
		if e.ID == "" || ids[e.ID] || e.Campaign == "" {
			return r, fmt.Errorf("missing or duplicate ID/campaign")
		}
		ids[e.ID] = true
		if e.Split != "test" && e.Split != "dev" {
			return r, fmt.Errorf("invalid split for %s", e.ID)
		}
		if prev := campaigns[e.Campaign]; prev != "" && prev != e.Split {
			return r, fmt.Errorf("campaign crosses dev/test splits: %s", e.Campaign)
		}
		campaigns[e.Campaign] = e.Split
		if e.Label != "spam" && e.Label != "ham" && e.Label != "uncertain" {
			return r, fmt.Errorf("human label required for %s", e.ID)
		}
		if e.Source != "synthetic" && e.Source != "production" {
			return r, fmt.Errorf("invalid source for %s", e.ID)
		}
		if e.Split != split || (representative && (e.Source != "production" || !e.Evidence.EvaluationSample)) {
			continue
		}
		if r.Source != "" && r.Source != e.Source {
			return r, fmt.Errorf("evaluate synthetic and production data separately")
		}
		r.Source = e.Source
		if e.Label == "uncertain" {
			r.Uncertain++
			continue
		}
		if e.Evidence.Truncated {
			return r, fmt.Errorf("truncated evidence cannot be evaluated: %s", e.ID)
		}
		signals := []detection.Signal{detection.NewMessageAdDetector().Analyze(e.Evidence.Message)}
		if mode == "replay" {
			modelSeen := false
			for _, s := range e.Evidence.Signals {
				switch {
				case s.Detector == "model.jev_advertising":
					if modelSeen {
						return r, fmt.Errorf("duplicate model signal: %s", e.ID)
					}
					modelSeen = true
					if s.DetectorVersion != "jev-message-v3" {
						return r, fmt.Errorf("model evidence requires v3 or a fresh evaluation: %s", e.ID)
					}
					signals = append(signals, s)
					if s.Status == detection.StatusAvailable {
						r.ModelAvailable++
					}
				case s.Detector == "behavior.spam" && s.Activity != nil:
					signals = append(signals, detection.NewBehaviorDetector().Analyze(*s.Activity))
				}
			}
		}
		m := e.Evidence.Message
		// Detection quality, not admin policy: allowlists/OBSERVE do not make
		// spam a true negative. No saved action is used as a human label.
		d := moderation.NewDecisionEngine().Decide(moderation.DecisionInput{Target: moderation.ActionTarget{Kind: moderation.TargetMessage}, HasMessageContent: strings.TrimSpace(m.Text+m.Caption+m.OCRText) != "", Signals: signals})
		deleted := d.AuthorizedAction == moderation.ActionDeleteMessage
		if d.AuthorizedAction == moderation.ActionReview {
			r.Reviews++
		}
		switch {
		case deleted && e.Label == "spam":
			r.TP++
		case deleted:
			r.FP++
			r.FalsePositiveIDs = append(r.FalsePositiveIDs, e.ID)
		case e.Label == "spam":
			r.FN++
			r.FalseNegativeIDs = append(r.FalseNegativeIDs, e.ID)
		default:
			r.TN++
		}
	}
	if r.TP+r.FP+r.TN+r.FN == 0 {
		return r, fmt.Errorf("no labeled examples selected")
	}
	if n := r.TP + r.FP; n > 0 {
		p := float64(r.TP) / float64(n)
		r.Precision = &p
		// Wilson lower bound shows why a tiny perfect sample proves little.
		z, total := 1.96, float64(n)
		lower := (p + z*z/(2*total) - z*math.Sqrt(p*(1-p)/total+z*z/(4*total*total))) / (1 + z*z/total)
		r.Precision95Lower = &lower
	}
	if n := r.TP + r.FN; n > 0 {
		recall := float64(r.TP) / float64(n)
		r.Recall = &recall
	}
	return r, nil
}
