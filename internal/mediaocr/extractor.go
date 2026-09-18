package mediaocr

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	defaultMaxBytes = int64(8 << 20)
	defaultTimeout  = 12 * time.Second
	maxOCRTextBytes = 1 << 20
)

type fileDownloader interface {
	DownloadFile(context.Context, string, int64) ([]byte, error)
}

type commandRunner func(context.Context, string, string) ([]byte, error)

// Config bounds Telegram downloads and local OCR execution.
type Config struct {
	Executable string
	Language   string
	MaxBytes   int64
	Timeout    time.Duration
}

// Extractor downloads one Telegram image and recognizes its text locally.
type Extractor struct {
	downloader fileDownloader
	language   string
	maxBytes   int64
	timeout    time.Duration
	run        commandRunner
}

// New verifies the Tesseract executable before accepting events.
func New(downloader fileDownloader, config Config) (*Extractor, error) {
	executable := config.Executable
	if executable == "" {
		executable = "tesseract"
	}
	resolved, err := exec.LookPath(executable)
	if err != nil {
		return nil, fmt.Errorf("find Tesseract executable: %w", err)
	}
	return newExtractor(downloader, config, func(ctx context.Context, inputPath, language string) ([]byte, error) {
		// Source: https://tesseract-ocr.github.io/tessdoc/Command-Line-Usage.html
		command := exec.CommandContext(ctx, resolved, inputPath, "stdout", "-l", language, "--psm", "6")
		output, err := command.Output()
		if err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				stderr := strings.TrimSpace(string(exitErr.Stderr))
				if len(stderr) > 500 {
					stderr = stderr[:500]
				}
				return nil, fmt.Errorf("run Tesseract: %w: %s", err, stderr)
			}
			return nil, fmt.Errorf("run Tesseract: %w", err)
		}
		return output, nil
	})
}

func newExtractor(downloader fileDownloader, config Config, run commandRunner) (*Extractor, error) {
	if downloader == nil {
		return nil, fmt.Errorf("Telegram file downloader is required")
	}
	if run == nil {
		return nil, fmt.Errorf("OCR command runner is required")
	}
	language := config.Language
	if language == "" {
		language = "rus+eng"
	}
	maxBytes := config.MaxBytes
	if maxBytes == 0 {
		maxBytes = defaultMaxBytes
	}
	if maxBytes < 0 || maxBytes > 20<<20 {
		return nil, fmt.Errorf("OCR file limit must be between 1 and 20971520 bytes")
	}
	timeout := config.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	if timeout < 0 || timeout > time.Minute {
		return nil, fmt.Errorf("OCR timeout must be between 1ns and 1m")
	}
	return &Extractor{
		downloader: downloader,
		language:   language,
		maxBytes:   maxBytes,
		timeout:    timeout,
		run:        run,
	}, nil
}

// ExtractText recognizes text while keeping file size, duration, and output bounded.
func (e *Extractor) ExtractText(ctx context.Context, fileID string) (string, error) {
	image, err := e.downloader.DownloadFile(ctx, fileID, e.maxBytes)
	if err != nil {
		return "", fmt.Errorf("download image for OCR: %w", err)
	}
	if len(image) == 0 {
		return "", fmt.Errorf("download image for OCR: empty file")
	}
	temporary, err := os.CreateTemp("", "antispambee-ocr-*.img")
	if err != nil {
		return "", fmt.Errorf("create OCR temporary file: %w", err)
	}
	path := temporary.Name()
	defer func() { _ = os.Remove(path) }()
	if _, err := temporary.Write(image); err != nil {
		_ = temporary.Close()
		return "", fmt.Errorf("write OCR temporary file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return "", fmt.Errorf("close OCR temporary file: %w", err)
	}

	ocrCtx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	output, err := e.run(ocrCtx, path, e.language)
	if err != nil {
		return "", err
	}
	if len(output) > maxOCRTextBytes {
		return "", fmt.Errorf("OCR output exceeds %d-byte limit", maxOCRTextBytes)
	}
	return strings.TrimSpace(string(output)), nil
}
