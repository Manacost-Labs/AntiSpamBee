package moderation

import (
	"context"
	"fmt"
	"strings"

	"antispambee/internal/detection"
)

const ReasonConfirmedAdvertisingAutoban = "CONFIRMED_ADVERTISING_AUTOBAN"
const ReasonAdvertisingNotConfirmed = "ADVERTISING_NOT_CONFIRMED"

// WithAdvertisingAutoban enables bans for confirmed advertising in one chat.
// Model-only detections need an independent confirmation before they can ban.
func WithAdvertisingAutoban(chatID int64, verifier contentAdAnalyzer) ProcessorOption {
	return func(processor *Processor) error {
		if chatID >= 0 || verifier == nil {
			return fmt.Errorf("advertising autoban requires a group and a verifier")
		}
		processor.advertisingBanChat = chatID
		processor.banVerifier = verifier
		return nil
	}
}

func (p *Processor) verifyAdvertisingAction(ctx context.Context, decision Decision, input DecisionInput, content *detection.SemanticAdContent) (Decision, []detection.Signal) {
	if p.banVerifier == nil || input.Target.ChatID != p.advertisingBanChat ||
		input.Target.Kind != TargetMessage || input.Target.UserID <= 0 || decision.AuthorizedAction != ActionDeleteMessage {
		return decision, nil
	}

	// Check whether local evidence is sufficient without the model.
	check := input
	check.Signals = make([]detection.Signal, 0, len(input.Signals))
	for _, signal := range input.Signals {
		if !strings.HasPrefix(signal.Detector, "model.") {
			check.Signals = append(check.Signals, signal)
		}
	}
	localAction := p.decisions.Decide(check).AuthorizedAction
	accepted := localAction == ActionDeleteMessage || localAction == ActionBanUser
	var confirmation []detection.Signal
	if !accepted && content != nil {
		expectedDetector := detection.SemanticMessageDetector
		if decision.AuthorizationReason == ReasonConfirmedProfileAdvertising {
			expectedDetector = detection.SemanticProfileDetector
		}
		confirmation = p.banVerifier.AnalyzeContent(ctx, *content)
		check.Signals = check.Signals[:0]
		for _, signal := range confirmation {
			if signal.Detector == expectedDetector {
				check.Signals = append(check.Signals, signal)
			}
		}
		accepted = p.decisions.Decide(check).AuthorizedAction == ActionDeleteMessage
		for i := range confirmation {
			confirmation[i].Detector += ".ban_confirmation"
		}
	}
	if !accepted {
		decision.AuthorizedAction = ActionReview
		decision.AuthorizationReason = ReasonAdvertisingNotConfirmed
	} else if input.AllowAdvertisingChannelDeletion && !input.AutobanDisabled {
		decision.RecommendedAction = ActionBanUser
		decision.AuthorizedAction = ActionBanUser
		decision.AuthorizationReason = ReasonConfirmedAdvertisingAutoban
	}
	return decision, confirmation
}
