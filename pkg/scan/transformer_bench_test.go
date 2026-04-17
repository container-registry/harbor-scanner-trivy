package scan

import (
	"fmt"
	"testing"
	"time"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/trivy"
)

// sinkScanReport prevents the compiler from optimizing away benchmark calls.
var sinkScanReport harbor.ScanReport

// benchClock is a fixed-time clock used by benchmarks.
type benchClock struct {
	t time.Time
}

func (c *benchClock) Now() time.Time { return c.t }

// makeVulnerabilities returns a slice of n synthetic Trivy vulnerabilities
// cycling through all severity levels.
func makeVulnerabilities(n int) []trivy.Vulnerability {
	severities := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
	vulns := make([]trivy.Vulnerability, n)
	for i := range n {
		v := trivy.Vulnerability{
			VulnerabilityID:  fmt.Sprintf("CVE-2023-%04d", i),
			PkgName:          fmt.Sprintf("package-%d", i),
			InstalledVersion: fmt.Sprintf("1.0.%d", i),
			FixedVersion:     fmt.Sprintf("1.0.%d", i+1),
			Status:           "fixed",
			Severity:         severities[i%len(severities)],
			Description:      fmt.Sprintf("Vulnerability %d affecting package-%d.", i, i),
			References: []string{
				fmt.Sprintf("https://nvd.nist.gov/vuln/detail/CVE-2023-%04d", i),
			},
			Layer: &trivy.Layer{
				Digest: fmt.Sprintf("sha256:%064d", i),
			},
		}
		// Add CVSS info to every other entry to exercise toVendorAttributes.
		if i%2 == 0 {
			score := float32(5.0 + float32(i%50)/10.0)
			v.CVSS = map[string]trivy.CVSSInfo{
				"nvd": {
					V3Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
					V3Score:  &score,
				},
			}
		}
		vulns[i] = v
	}
	return vulns
}

var (
	smallVulns  = makeVulnerabilities(5)
	mediumVulns = makeVulnerabilities(50)
	largeVulns  = makeVulnerabilities(200)
)

var baseRequest = harbor.ScanRequest{
	Capabilities: []harbor.Capability{
		{Type: harbor.CapabilityTypeVulnerability},
	},
	Artifact: harbor.Artifact{
		Repository: "library/nginx",
		Digest:     "sha256:6c3c624b58dbbcd3c0dd82b4c53f04194d1247c6eebdaab7c610cf7d66709b3b",
	},
}

// BenchmarkTransformer_Transform_Small measures transformation of 5 vulnerabilities.
func BenchmarkTransformer_Transform_Small(b *testing.B) {
	tf := NewTransformer(&benchClock{t: time.Now()})
	src := trivy.Report{Vulnerabilities: smallVulns}
	b.ResetTimer()
	for b.Loop() {
		sinkScanReport = tf.Transform("", baseRequest, src)
	}
}

// BenchmarkTransformer_Transform_Medium measures transformation of 50 vulnerabilities.
func BenchmarkTransformer_Transform_Medium(b *testing.B) {
	tf := NewTransformer(&benchClock{t: time.Now()})
	src := trivy.Report{Vulnerabilities: mediumVulns}
	b.ResetTimer()
	for b.Loop() {
		sinkScanReport = tf.Transform("", baseRequest, src)
	}
}

// BenchmarkTransformer_Transform_Large measures transformation of 200 vulnerabilities.
func BenchmarkTransformer_Transform_Large(b *testing.B) {
	tf := NewTransformer(&benchClock{t: time.Now()})
	src := trivy.Report{Vulnerabilities: largeVulns}
	b.ResetTimer()
	for b.Loop() {
		sinkScanReport = tf.Transform("", baseRequest, src)
	}
}

// BenchmarkTransformer_ToHarborSeverity measures the severity map lookup across all levels.
func BenchmarkTransformer_ToHarborSeverity(b *testing.B) {
	t := &transformer{clock: &benchClock{t: time.Now()}}
	severities := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
	var (
		sink  harbor.Severity
		index int
	)
	b.ResetTimer()
	for b.Loop() {
		sink = t.toHarborSeverity(severities[index%len(severities)])
		index++
	}
	_ = sink
}

// BenchmarkTransformer_ToVendorAttributes measures CVSS map wrapping.
func BenchmarkTransformer_ToVendorAttributes(b *testing.B) {
	t := &transformer{clock: &benchClock{t: time.Now()}}
	score := float32(9.8)
	cvss := map[string]trivy.CVSSInfo{
		"nvd": {
			V3Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			V3Score:  &score,
		},
		"redhat": {
			V2Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P",
			V2Score:  &score,
		},
	}
	var sink map[string]any
	b.ResetTimer()
	for b.Loop() {
		sink = t.toVendorAttributes(cvss)
	}
	_ = sink
}
