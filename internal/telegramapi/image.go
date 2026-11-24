package telegramapi

import "strings"

// ImageAttachment contains Telegram photos and images sent as documents.
type ImageAttachment struct {
	Photo []struct {
		FileID   string `json:"file_id"`
		UniqueID string `json:"file_unique_id"`
		FileSize int64  `json:"file_size"`
		Width    int64  `json:"width"`
		Height   int64  `json:"height"`
	} `json:"photo"`
	Document *struct {
		FileID   string `json:"file_id"`
		UniqueID string `json:"file_unique_id"`
		FileSize int64  `json:"file_size"`
		MIMEType string `json:"mime_type"`
	} `json:"document"`
}

// StableImageID identifies the published image independently of the bot's download ID.
func (attachment *ImageAttachment) StableImageID() string {
	if attachment == nil {
		return ""
	}
	best := attachment.BestImageFileID(0)
	if best == "" {
		return ""
	}
	for _, photo := range attachment.Photo {
		if photo.FileID == best {
			return photo.UniqueID
		}
	}
	return attachment.Document.UniqueID
}

// BestImageFileID chooses the largest eligible Telegram thumbnail. Downloads
// still enforce the size limit because the declared file size is optional.
func (attachment *ImageAttachment) BestImageFileID(maxBytes int64) string {
	if attachment == nil {
		return ""
	}
	var id string
	var pixels, size int64
	for _, photo := range attachment.Photo {
		if photo.FileID == "" || (maxBytes > 0 && photo.FileSize > maxBytes) {
			continue
		}
		area := photo.Width * photo.Height
		if id == "" || area > pixels || (area == pixels && photo.FileSize >= size) {
			id, pixels, size = photo.FileID, area, photo.FileSize
		}
	}
	if id != "" {
		return id
	}
	if file := attachment.Document; file != nil && strings.HasPrefix(strings.ToLower(file.MIMEType), "image/") &&
		(maxBytes == 0 || file.FileSize <= maxBytes) {
		return file.FileID
	}
	return ""
}
