package trivy

import "fmt"

// ScanErrorCategory categorizes scan failures for structured error reporting.
// Harbor can parse the category prefix from error messages to show meaningful
// status to users instead of raw Trivy stderr output.
type ScanErrorCategory string

const (
	ErrCategoryImageFetch    ScanErrorCategory = "image_fetch"
	ErrCategoryManifest      ScanErrorCategory = "manifest"
	ErrCategoryAuth          ScanErrorCategory = "auth"
	ErrCategoryUnscannable   ScanErrorCategory = "unscannable_layer"
	ErrCategoryTrivyExec     ScanErrorCategory = "trivy_execution"
	ErrCategoryNetwork       ScanErrorCategory = "network"
	ErrCategoryTimeout       ScanErrorCategory = "timeout"
	ErrCategoryReportParse   ScanErrorCategory = "report_parse"
)

// ScanError provides structured context about scan failures.
type ScanError struct {
	Category ScanErrorCategory
	ImageRef string
	Detail   string
	Cause    error
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
