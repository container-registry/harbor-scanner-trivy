package trivy

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// sinks prevent the compiler from optimizing away benchmark calls.
var (
	sinkCategory ScanErrorCategory
	sinkStr      string
	sinkReport   ScanReport
)

// BenchmarkClassifyTrivyError_Auth measures error classification for auth errors.
func BenchmarkClassifyTrivyError_Auth(b *testing.B) {
	input := "unauthorized: access denied, response code 401"
	for b.Loop() {
		sinkCategory = classifyTrivyError(input)
	}
}

// BenchmarkClassifyTrivyError_Network measures error classification for network errors.
func BenchmarkClassifyTrivyError_Network(b *testing.B) {
	input := "dial tcp registry.example.com:443: connection refused"
	for b.Loop() {
		sinkCategory = classifyTrivyError(input)
	}
}

// BenchmarkClassifyTrivyError_Timeout measures error classification for timeout errors.
func BenchmarkClassifyTrivyError_Timeout(b *testing.B) {
	input := "context deadline exceeded: timeout pulling image manifest"
	for b.Loop() {
		sinkCategory = classifyTrivyError(input)
	}
}

// BenchmarkClassifyTrivyError_Default measures error classification for generic errors.
func BenchmarkClassifyTrivyError_Default(b *testing.B) {
	input := "trivy execution failed: unknown error during image analysis"
	for b.Loop() {
		sinkCategory = classifyTrivyError(input)
	}
}

// BenchmarkScanError_Error_NoCause measures formatting of a ScanError without a cause.
func BenchmarkScanError_Error_NoCause(b *testing.B) {
	se := &ScanError{
		Category: ErrCategoryAuth,
		ImageRef: "registry.example.com/library/nginx:1.25",
		Detail:   "unauthorized: authentication required",
	}
	for b.Loop() {
		sinkStr = se.Error()
	}
}

// BenchmarkScanError_Error_WithCause measures formatting of a ScanError with a wrapped cause.
func BenchmarkScanError_Error_WithCause(b *testing.B) {
	se := &ScanError{
		Category: ErrCategoryNetwork,
		ImageRef: "registry.example.com/library/nginx:1.25",
		Detail:   "dial tcp: no such host",
		Cause:    fmt.Errorf("underlying network error"),
	}
	for b.Loop() {
		sinkStr = se.Error()
	}
}

// scanReportSmallJSON is a minimal Trivy scan report used for JSON parsing benchmarks.
var scanReportSmallJSON = []byte(`{
	"SchemaVersion": 2,
	"Results": [
		{
			"Target": "library/nginx:latest",
			"Vulnerabilities": [
				{
					"VulnerabilityID": "CVE-2023-0001",
					"PkgName": "openssl",
					"InstalledVersion": "1.1.1k",
					"FixedVersion": "1.1.1n",
					"Status": "fixed",
					"Severity": "HIGH",
					"Description": "A buffer overflow vulnerability in OpenSSL.",
					"References": ["https://nvd.nist.gov/vuln/detail/CVE-2023-0001"],
					"CVSS": {
						"nvd": {
							"V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
							"V3Score": 9.8
						}
					}
				}
			]
		}
	]
}`)

// BenchmarkParseScanReport_Small measures JSON decoding of a small scan report (1 vulnerability).
func BenchmarkParseScanReport_Small(b *testing.B) {
	for b.Loop() {
		var report ScanReport
		if err := json.Unmarshal(scanReportSmallJSON, &report); err != nil {
			b.Fatal(err)
		}
		sinkReport = report
	}
}

// BenchmarkParseScanReport_Large measures JSON decoding of a large scan report (200 vulnerabilities).
func BenchmarkParseScanReport_Large(b *testing.B) {
	data := buildLargeScanReportJSON(200)
	b.ResetTimer()
	for b.Loop() {
		var report ScanReport
		if err := json.Unmarshal(data, &report); err != nil {
			b.Fatal(err)
		}
		sinkReport = report
	}
}

// buildLargeScanReportJSON constructs a JSON-encoded ScanReport with n vulnerabilities.
func buildLargeScanReportJSON(n int) []byte {
	var sb strings.Builder
	sb.WriteString(`{"SchemaVersion":2,"Results":[{"Target":"library/nginx:latest","Vulnerabilities":[`)
	for i := range n {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb,
			`{"VulnerabilityID":"CVE-2023-%04d","PkgName":"pkg-%d","InstalledVersion":"1.0.%d","FixedVersion":"1.0.%d","Status":"fixed","Severity":"HIGH","Description":"Vulnerability number %d","References":["https://nvd.nist.gov/vuln/detail/CVE-2023-%04d"]}`,
			i, i, i, i+1, i, i,
		)
	}
	sb.WriteString(`]}]}`)
	return []byte(sb.String())
}
