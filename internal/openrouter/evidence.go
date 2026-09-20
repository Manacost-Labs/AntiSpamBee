package openrouter

import (
	"fmt"
	"strings"

	"antispambee/internal/detection"
)

// Passage IDs let a classification-only model select a real source excerpt
// rather than invent a quote. Bound prompt growth; no match means review.
func messagePassages(message detection.MessageContent) map[string]string {
	passages := map[string]string{}
	for _, field := range []string{message.Text, message.Caption, message.OCRText} {
		for _, line := range strings.Split(field, "\n") {
			runes := []rune(strings.TrimSpace(line))
			for len(runes) > 0 && len(passages) < 32 {
				n := min(len(runes), 400)
				passages[fmt.Sprintf("p%d", len(passages))] = string(runes[:n])
				runes = runes[n:]
			}
		}
	}
	return passages
}
