package detection

const (
	ReasonOpenRouterFailed  = "OPENROUTER_REQUEST_FAILED"
	ReasonNoSemanticContent = "NO_SEMANTIC_CONTENT"
	ReasonOCRFailed         = "OCR_FAILED"
)

// SemanticAdContent contains the text-only Telegram context sent to a semantic
// advertising classifier. It deliberately excludes Telegram identifiers.
type SemanticAdContent struct {
	Message MessageContent
	Profile Profile
}
