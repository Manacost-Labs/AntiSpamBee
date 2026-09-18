package detection

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// MessageFingerprint returns a stable, privacy-minimizing digest for duplicate detection.
func MessageFingerprint(content MessageContent) string {
	canonical := normalize(strings.TrimSpace(strings.Join([]string{content.Text, content.Caption, content.OCRText}, " ")))
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}
