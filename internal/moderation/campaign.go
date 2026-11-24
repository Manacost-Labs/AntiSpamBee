package moderation

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"antispambee/internal/detection"
)

const ReasonRepeatedCampaign = "REPEATED_ADVERTISING_CAMPAIGN"

type CampaignIndicator struct {
	Kind        string
	Fingerprint []byte
}

type campaignStore interface {
	ObserveCampaign(context.Context, string, ActionTarget, []CampaignIndicator, bool) ([]string, error)
}

func WithModerationOperations(chatID int64, key []byte, store campaignStore) ProcessorOption {
	return func(p *Processor) error {
		if chatID >= 0 || len(key) == 0 || store == nil {
			return fmt.Errorf("moderation operations require a group, campaign key and store")
		}
		p.operationsChatID, p.campaigns = chatID, store
		p.campaignKey = append([]byte(nil), key...)
		return nil
	}
}

var campaignContact = regexp.MustCompile(`(?i)(?:^|[^a-z0-9_.@])@([a-z0-9_]{5,32})(?:$|[^a-z0-9_])`)
var campaignPhone = regexp.MustCompile(`\+[0-9][0-9 ()-]{8,20}[0-9]`)
var telegramContactName = regexp.MustCompile(`(?i)^/[a-z][a-z0-9_]{4,31}$`)

func campaignIndicators(key []byte, message detection.MessageContent, imageID string) []CampaignIndicator {
	var indicators []CampaignIndicator
	seen := map[string]bool{}
	add := func(kind, value string) {
		if value == "" || len(value) > 1024 || len(indicators) >= 8 || seen[kind+":"+value] {
			return
		}
		seen[kind+":"+value] = true
		digest := hmac.New(sha256.New, key)
		_, _ = digest.Write([]byte("antispambee-campaign:" + kind + ":" + value))
		indicators = append(indicators, CampaignIndicator{Kind: kind, Fingerprint: digest.Sum(nil)})
	}
	add("image", imageID)
	text := strings.Join([]string{message.Text, message.Caption, message.OCRText}, " ")
	for _, match := range campaignContact.FindAllStringSubmatch(text, 12) {
		add("contact", "tg:"+strings.ToLower(match[1]))
	}
	for _, match := range campaignPhone.FindAllString(text, 8) {
		digits := strings.Map(func(r rune) rune {
			if r >= '0' && r <= '9' {
				return r
			}
			return -1
		}, match)
		if len(digits) >= 10 && len(digits) <= 15 {
			add("contact", "tel:"+digits)
		}
	}
	for _, value := range append(append([]string(nil), message.URLs...), extractURLs(message.OCRText)...) {
		kind, canonical := campaignURL(value)
		add(kind, canonical)
	}
	return indicators
}

func campaignURL(value string) (string, string) {
	value = strings.TrimSpace(value)
	if !strings.Contains(value, "://") {
		value = "https://" + value
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return "", ""
	}
	host := strings.TrimPrefix(strings.ToLower(parsed.Host), "www.")
	path := strings.TrimRight(parsed.EscapedPath(), "/")
	if host == "telegram.me" {
		host = "t.me"
	}
	if host == "t.me" && telegramContactName.MatchString(path) {
		name := strings.ToLower(strings.TrimPrefix(path, "/"))
		switch name {
		case "share", "proxy", "joinchat", "addstickers", "addemoji", "boost", "invoice", "login":
		default:
			return "contact", "tg:" + name
		}
	}
	query := parsed.Query()
	for key := range query {
		if strings.HasPrefix(strings.ToLower(key), "utm_") {
			query.Del(key)
		}
	}
	if encoded := query.Encode(); encoded != "" {
		path += "?" + encoded
	}
	return "link", host + path
}
