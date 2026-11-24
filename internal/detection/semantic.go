package detection

const (
	ReasonOpenRouterFailed                 = "OPENROUTER_REQUEST_FAILED"
	ReasonOpenRouterTemporarilyUnavailable = "OPENROUTER_TEMPORARILY_UNAVAILABLE"
	ReasonNoSemanticContent                = "NO_SEMANTIC_CONTENT"
	ReasonOCRFailed                        = "OCR_FAILED"
	ReasonSemanticEvidenceMissing          = "SEMANTIC_EVIDENCE_UNVERIFIED"
	SemanticMessageDetector                = "model.message_advertising"
	SemanticProfileDetector                = "model.profile_advertising"
	ReasonSemanticImageUnavailable         = "SEMANTIC_IMAGE_UNAVAILABLE"
	ReasonConfirmedProfileAdvertising      = "CONFIRMED_PROFILE_ADVERTISING"
	MaxSemanticImageBytes                  = 4 << 20
	MaxProfileImageBytes                   = 2 << 20
	MaxProfileImages                       = 2
)

// SemanticAdContent contains the content available to a semantic classifier.
// Image bytes are transient and are never written to moderation evidence.
type SemanticAdContent struct {
	Message       MessageContent
	Profile       Profile
	Image         []byte
	ProfileImages []ProfileImage
}

type ProfileImage struct {
	PostNumber int
	Data       []byte
}
