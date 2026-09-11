package trivy

import (
	"fmt"
	"strings"
)

// ScanErrorCategory categorizes scan failures for structured error reporting.
// Harbor can parse the category prefix from error messages to show meaningful
// status to users instead of raw Trivy stderr output.
type ScanErrorCategory string

const (
	ErrCategoryImageFetch  ScanErrorCategory = "image_fetch"
	ErrCategoryManifest    ScanErrorCategory = "manifest"
	ErrCategoryAuth        ScanErrorCategory = "auth"
	ErrCategoryUnscannable ScanErrorCategory = "unscannable_layer"
	ErrCategoryTrivyExec   ScanErrorCategory = "trivy_execution"
	ErrCategoryNetwork     ScanErrorCategory = "network"
	ErrCategoryTimeout     ScanErrorCategory = "timeout"
	ErrCategoryReportParse ScanErrorCategory = "report_parse"
	ErrCategoryCache       ScanErrorCategory = "cache"
)

// ScanError provides structured context about scan failures.
type ScanError struct {
	// Retryable is an execution decision, separate from the diagnostic category.
	// Unknown CLI failures are retried within the worker's attempt limit.
	Retryable bool
	Category  ScanErrorCategory
	ImageRef  string
	Detail    string
	Cause     error
}

func (e *ScanError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Category, e.Detail, e.Cause)
	}
	return fmt.Sprintf("[%s] %s", e.Category, e.Detail)
}

func (e *ScanError) Unwrap() error {
	return e.Cause
}

// Recognize HTTP statuses and registry error prefixes, not arbitrary counts or
// descriptive words in CLI stderr. Typed registry errors use their HTTP status.
func isAuthenticationErrorMessage(message string) bool {
	words := strings.Fields(strings.ToLower(message))
	token := func(i int) string { return strings.Trim(words[i], "\"':;,()[]") }
	for i := range words {
		word := token(i)
		if word == "401" || word == "403" {
			if i+1 < len(words) && ((word == "401" && token(i+1) == "unauthorized") || (word == "403" && token(i+1) == "forbidden")) {
				return true
			}
			if i > 0 && (token(i-1) == "status" || (token(i-1) == "code" && i > 1 && token(i-2) == "status")) {
				return true
			}
		}
		if (word == "unauthorized" || word == "forbidden") && (i == 0 || strings.HasSuffix(words[i-1], ":")) && (strings.HasSuffix(words[i], ":") || i == len(words)-1) {
			return true
		}
	}
	return false
}
