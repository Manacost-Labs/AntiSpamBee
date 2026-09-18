package mediaocr

import (
	"context"
	"os"
	"testing"
	"time"
)

type downloaderStub struct {
	data     []byte
	err      error
	fileID   string
	maxBytes int64
}

func (d *downloaderStub) DownloadFile(_ context.Context, fileID string, maxBytes int64) ([]byte, error) {
	d.fileID = fileID
	d.maxBytes = maxBytes
	return d.data, d.err
}

func TestExtractorDownloadsBoundedImageAndReturnsTrimmedText(t *testing.T) {
	downloader := &downloaderStub{data: []byte("image-bytes")}
	var temporaryPath string
	extractor, err := newExtractor(downloader, Config{
		MaxBytes: 1024,
		Timeout:  time.Second,
		Language: "rus+eng",
	}, func(_ context.Context, path, language string) ([]byte, error) {
		temporaryPath = path
		if language != "rus+eng" {
			t.Fatalf("language = %q", language)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != "image-bytes" {
			t.Fatalf("temporary image = %q", data)
		}
		return []byte("  ИЩЕМ ПОДРАБОТКУ 5000 РУБЛЕЙ В ЛС\n"), nil
	})
	if err != nil {
		t.Fatal(err)
	}

	text, err := extractor.ExtractText(context.Background(), "telegram-file")
	if err != nil {
		t.Fatalf("ExtractText() error = %v", err)
	}
	if text != "ИЩЕМ ПОДРАБОТКУ 5000 РУБЛЕЙ В ЛС" {
		t.Fatalf("ExtractText() = %q", text)
	}
	if downloader.fileID != "telegram-file" || downloader.maxBytes != 1024 {
		t.Fatalf("download arguments = %q/%d", downloader.fileID, downloader.maxBytes)
	}
	if _, err := os.Stat(temporaryPath); !os.IsNotExist(err) {
		t.Fatalf("temporary file still exists: %v", err)
	}
}

func TestNewRejectsMissingTesseractExecutable(t *testing.T) {
	_, err := New(&downloaderStub{}, Config{Executable: "definitely-not-an-installed-ocr-binary"})
	if err == nil {
		t.Fatal("New() error = nil, want missing executable error")
	}
}
