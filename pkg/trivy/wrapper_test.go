package trivy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/fake"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/samber/lo"
	"github.com/stretchr/testify/mock"

	"github.com/container-registry/harbor-scanner-trivy/pkg/etc"
	"github.com/container-registry/harbor-scanner-trivy/pkg/ext"
	"github.com/container-registry/harbor-scanner-trivy/pkg/metrics"
	"github.com/stretchr/testify/require"
)

func TestCacheConfigurationReachesTrivyWithoutCredentialsInArgs(t *testing.T) {
	ambassador := ext.NewMockAmbassador()
	ambassador.On("Environ").Return([]string{"TRIVY_CACHE_BACKEND=fs", "TRIVY_CACHE_TTL=0", "KEEP=yes"})
	ambassador.On("LookPath", "trivy").Return("/usr/local/bin/trivy", nil)
	w := &wrapper{config: etc.Trivy{CacheBackend: "rediss://user:private@cache:6379/0", CacheTTL: 48 * time.Hour}, ambassador: ambassador}
	cmd, err := w.prepareScanCmd(context.Background(), ScanTarget{kind: TargetImage, ref: ImageRef{Name: "alpine", Auth: NoAuth{}}}, "report.json", ScanOption{Format: FormatJSON})
	require.NoError(t, err)
	require.Contains(t, cmd.Env, "TRIVY_CACHE_BACKEND=redis://user:private@cache:6379/0")
	require.Contains(t, cmd.Env, "TRIVY_REDIS_TLS=true")
	require.Contains(t, cmd.Env, "TRIVY_CACHE_TTL=48h0m0s")
	require.NotContains(t, cmd.Env, "TRIVY_CACHE_BACKEND=fs")
	require.Contains(t, cmd.Env, "KEEP=yes")
	require.NotContains(t, strings.Join(cmd.Args, " "), "private")
	require.NotContains(t, w.redactCacheCredentials("dial rediss://user:private@cache:6379/0 failed: private"), "private")
}

func TestScanErrorPreservesCauseAndClassificationAfterRedaction(t *testing.T) {
	for _, cause := range []error{context.Canceled, &exec.ExitError{}} {
		t.Run(fmt.Sprintf("%T", cause), func(t *testing.T) {
			ambassador := ext.NewMockAmbassador()
			ambassador.On("Environ").Return([]string{})
			ambassador.On("LookPath", "trivy").Return("/usr/local/bin/trivy", nil)
			fakeImage := &fake.FakeImage{}
			fakeImage.ManifestReturns(&v1.Manifest{}, nil)
			ambassador.On("RemoteImage", mock.Anything, mock.Anything).Return(fakeImage, nil)
			report, err := os.CreateTemp(t.TempDir(), "report")
			require.NoError(t, err)
			ambassador.On("TempFile", mock.Anything, mock.Anything).Return(report, nil)
			ambassador.On("RunCmd", mock.Anything).Return([]byte{}, []byte("redis cache unavailable"), fmt.Errorf("cache: %w", cause))
			w := NewWrapper(etc.Trivy{CacheBackend: "redis://:cache@redis:6379/0", CacheTTL: time.Hour}, ambassador)
			_, err = w.Scan(context.Background(), ImageRef{Name: "alpine", Auth: NoAuth{}}, ScanOption{Format: FormatJSON})
			var scanErr *ScanError
			require.ErrorAs(t, err, &scanErr)
			require.ErrorIs(t, err, cause)
			if _, ok := cause.(*exec.ExitError); ok {
				var exitErr *exec.ExitError
				require.ErrorAs(t, err, &exitErr)
			}
			require.Equal(t, ErrCategoryCache, scanErr.Category)
			require.NotContains(t, scanErr.Detail, "cache")
			require.NotContains(t, scanErr.Cause.Error(), "cache")
		})
	}
}

func TestScanCommandStopsWhenWorkerContextIsCancelled(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "trivy")
	require.NoError(t, os.WriteFile(binary, []byte("#!/bin/sh\nexec sleep 30\n"), 0o700))
	ambassador := ext.NewMockAmbassador()
	ambassador.On("Environ").Return(os.Environ())
	ambassador.On("LookPath", "trivy").Return(binary, nil)
	w := &wrapper{ambassador: ambassador}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd, err := w.prepareScanCmd(ctx, ScanTarget{kind: TargetImage, ref: ImageRef{Name: "alpine", Auth: NoAuth{}}}, "report.json", ScanOption{})
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	cancel()
	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Trivy did not stop on cancellation")
	}
}

func TestNormalizedTLSCacheURLDoesNotLeakEncodedPassword(t *testing.T) {
	w := &wrapper{config: etc.Trivy{CacheBackend: "rediss://user:a%20b@cache:6379/0"}}
	for _, diagnostic := range []string{
		"dial redis://user:a%20b@cache:6379/0 failed",
		"authentication failed for user:a%20b",
		"password a%20b failed", "password a+b failed", "password a b failed",
	} {
		redacted := w.redactCacheCredentials(diagnostic)
		for _, secret := range []string{"a%20b", "a+b", "a b"} {
			require.NotContains(t, redacted, secret)
		}
	}
}

var (
	expectedReportJSON = `{
  "SchemaVersion": 2,
  "Results": [
    {
      "Target": "alpine:3.10.2",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2018-6543",
          "PkgName": "binutils",
          "InstalledVersion": "2.30-r1",
          "FixedVersion": "2.30-r2",
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:M/Au:N/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N",
              "V2Score": 1.9,
              "V3Score": 4.7
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 5.5
            }
          },
          "Severity": "MEDIUM",
          "References": [
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6543"
          ],
          "Layer": {
            "Digest": "sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"
          }
        }
      ]
    }
  ]
}`
	expectedReport = Report{
		Vulnerabilities: []Vulnerability{
			{
				VulnerabilityID:  "CVE-2018-6543",
				PkgName:          "binutils",
				InstalledVersion: "2.30-r1",
				FixedVersion:     "2.30-r2",
				Severity:         "MEDIUM",
				References: []string{
					"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6543",
				},
				Layer: &Layer{Digest: "sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				CVSS: map[string]CVSSInfo{
					"nvd": {
						V2Vector: "AV:L/AC:M/Au:N/C:P/I:N/A:N",
						V3Vector: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N",
						V2Score:  lo.ToPtr[float32](1.9),
						V3Score:  lo.ToPtr[float32](4.7),
					},
					"redhat": {
						V2Vector: "",
						V3Vector: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
						V2Score:  nil,
						V3Score:  lo.ToPtr[float32](5.5),
					},
				},
			},
		},
	}
	expectedVersion = VersionInfo{
		Version: "v0.5.2-17-g3c9af62",
		VulnerabilityDB: &Metadata{
			NextUpdate: time.Unix(1584507644, 0).UTC(),
			UpdatedAt:  time.Unix(1584517644, 0).UTC(),
		},
	}
)

func TestWrapper_Scan(t *testing.T) {
	t.Run("vulnerability", func(t *testing.T) {
		ambassador := ext.NewMockAmbassador()
		ambassador.On("Environ").Return([]string{"HTTP_PROXY=http://someproxy:7777"})
		ambassador.On("LookPath", "trivy").Return("/usr/local/bin/trivy", nil)

		fakeImage := &fake.FakeImage{}
		fakeImage.ManifestReturns(&v1.Manifest{}, nil)
		ambassador.On("RemoteImage", mock.Anything, mock.Anything).Return(fakeImage, nil)

		reportsDir, cacheDir := tmpDirs(t)
		config := etc.Trivy{
			CacheDir:         cacheDir,
			ReportsDir:       reportsDir,
			DebugMode:        true,
			VulnType:         "os,library",
			Scanners:         "vuln",
			Severity:         "CRITICAL,MEDIUM",
			IgnoreUnfixed:    true,
			IgnorePolicy:     "/home/scanner/opa/policy.rego",
			SkipDBUpdate:     true,
			SkipJavaDBUpdate: true,
			DBRepository:     "ghcr.io/aquasecurity/trivy-db",
			JavaDBRepository: "ghcr.io/aquasecurity/trivy-java-db",
			GitHubToken:      "<github_token>",
			Insecure:         true,
			Timeout:          5 * time.Minute,
		}

		reportPath := filepath.Join(reportsDir, "scan_report_vuln.json")
		require.NoError(t, os.WriteFile(reportPath, []byte(expectedReportJSON), 0o644))
		ambassador.On("TempFile", reportsDir, mock.Anything).Return(os.Open(reportPath))

		ambassador.On("RunCmd", matchScanCommand(&exec.Cmd{
			Path: "/usr/local/bin/trivy",
			Env: []string{
				"HTTP_PROXY=http://someproxy:7777",
				"TRIVY_USERNAME=dave.loper",
				"TRIVY_PASSWORD=s3cret",
				"GITHUB_TOKEN=<github_token>",
			},
			Args: []string{
				"/usr/local/bin/trivy",
				"image",
				"--no-progress",
				"--severity",
				"CRITICAL,MEDIUM",
				"--vuln-type",
				"os,library",
				"--format",
				"json",
				"--output",
				reportPath,
				"--cache-dir",
				cacheDir,
				"--timeout",
				"5m0s",
				"--scanners",
				"vuln",
				"--ignore-unfixed",
				"--skip-db-update",
				"--skip-java-db-update",
				"--ignore-policy",
				"/home/scanner/opa/policy.rego",
				"--db-repository",
				"ghcr.io/aquasecurity/trivy-db",
				"--java-db-repository",
				"ghcr.io/aquasecurity/trivy-java-db",
				"--debug",
				"--insecure",
				"alpine:3.10.2",
			},
		}),
		).Return([]byte{}, []byte{}, nil)

		imageRef := ImageRef{
			Name: "alpine:3.10.2",
			Auth: BasicAuth{
				Username: "dave.loper",
				Password: "s3cret",
			},
			NonSSL: true,
		}

		got, err := NewWrapper(config, ambassador).Scan(context.Background(), imageRef, ScanOption{Format: FormatJSON})
		require.NoError(t, err)
		require.Equal(t, expectedReport, got)

		ambassador.AssertExpectations(t)
	})

	t.Run("sbom", func(t *testing.T) {
		ambassador := ext.NewMockAmbassador()
		ambassador.On("Environ").Return([]string{"HTTP_PROXY=http://someproxy:7777"})
		ambassador.On("LookPath", "trivy").Return("/usr/local/bin/trivy", nil)

		fakeImage := &fake.FakeImage{}
		fakeImage.ManifestReturns(&v1.Manifest{
			ArtifactType: "application/vnd.goharbor.harbor.sbom.v1",
		}, nil)
		fakeLayer, err := random.Layer(1024, types.DockerLayer)
		require.NoError(t, err, "failed to create fake layer")
		fakeImage.LayersReturns([]v1.Layer{fakeLayer}, nil)
		ambassador.On("RemoteImage", mock.Anything, mock.Anything).Return(fakeImage, nil)

		reportsDir, cacheDir := tmpDirs(t)
		config := etc.Trivy{
			CacheDir:         cacheDir,
			ReportsDir:       reportsDir,
			Scanners:         "vuln",
			VulnType:         "library",
			Severity:         "CRITICAL",
			SkipDBUpdate:     true,
			SkipJavaDBUpdate: true,
			Timeout:          10 * time.Second,
		}

		reportPath := filepath.Join(reportsDir, "scan_report_vuln.json")
		require.NoError(t, os.WriteFile(reportPath, []byte(expectedReportJSON), 0o644))
		ambassador.On("TempFile", reportsDir, mock.Anything).Return(os.Open(reportPath))

		sbomPath := filepath.Join(cacheDir, "sbom.json")
		ambassador.On("TempFile", cacheDir, mock.Anything).Return(os.Create(sbomPath))

		ambassador.On("RunCmd", matchScanCommand(&exec.Cmd{
			Path: "/usr/local/bin/trivy",
			Env: []string{
				"HTTP_PROXY=http://someproxy:7777",
			},
			Args: []string{
				"/usr/local/bin/trivy",
				"sbom",
				"--no-progress",
				"--severity",
				"CRITICAL",
				"--vuln-type",
				"library",
				"--format",
				"json",
				"--output",
				reportPath,
				"--cache-dir",
				cacheDir,
				"--timeout",
				"10s",
				"--skip-db-update",
				"--skip-java-db-update",
				sbomPath,
			},
		}),
		).Return([]byte{}, []byte{}, nil)

		imageRef := ImageRef{
			Name: "alpine@sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10",
			Auth: NoAuth{},
		}

		got, err := NewWrapper(config, ambassador).Scan(context.Background(), imageRef, ScanOption{Format: FormatJSON})
		require.NoError(t, err)
		require.Equal(t, expectedReport, got)

		ambassador.AssertExpectations(t)
	})
}

func TestWrapper_GetVersion(t *testing.T) {
	ambassador := ext.NewMockAmbassador()
	ambassador.On("LookPath", "trivy").Return("/usr/local/bin/trivy", nil)

	config := etc.Trivy{
		CacheDir:  "/home/scanner/.cache/trivy",
		DebugMode: true,
	}

	expectedCmdArgs := []string{
		"/usr/local/bin/trivy",
		"--cache-dir",
		"/home/scanner/.cache/trivy",
		"version",
		"--format",
		"json",
	}

	b, _ := json.Marshal(expectedVersion)
	ambassador.On("RunCmd", &exec.Cmd{
		Path: "/usr/local/bin/trivy",
		Args: expectedCmdArgs,
	},
	).Return(b, []byte{}, nil)

	vi, err := NewWrapper(config, ambassador).GetVersion()
	require.NoError(t, err)
	require.Equal(t, expectedVersion, vi)

	ambassador.AssertExpectations(t)
}

func tmpDirs(t *testing.T) (string, string) {
	tmpDir := t.TempDir()
	cacheDir := filepath.Join(tmpDir, "cache")
	require.NoError(t, os.MkdirAll(cacheDir, 0o700))
	reportsDir := filepath.Join(tmpDir, "reports")
	require.NoError(t, os.MkdirAll(reportsDir, 0o700))

	return cacheDir, reportsDir
}

func TestMalformedReportHasReportParseCategory(t *testing.T) {
	ambassador := ext.NewMockAmbassador()
	ambassador.On("Environ").Return([]string{})
	ambassador.On("LookPath", "trivy").Return("/usr/local/bin/trivy", nil)
	img := &fake.FakeImage{}
	img.ManifestReturns(&v1.Manifest{}, nil)
	ambassador.On("RemoteImage", mock.Anything, mock.Anything).Return(img, nil)
	path := filepath.Join(t.TempDir(), "report.json")
	require.NoError(t, os.WriteFile(path, []byte("{malformed"), 0o600))
	report, err := os.Open(path)
	require.NoError(t, err)
	ambassador.On("TempFile", mock.Anything, mock.Anything).Return(report, nil)
	ambassador.On("RunCmd", mock.Anything).Return([]byte{}, []byte{}, nil)
	wrapper := NewWrapper(etc.Trivy{}, ambassador)
	_, err = wrapper.Scan(context.Background(), ImageRef{Name: "alpine:latest", Auth: NoAuth{}}, ScanOption{Format: FormatJSON})
	var scanErr *ScanError
	require.ErrorAs(t, err, &scanErr)
	require.Equal(t, ErrCategoryReportParse, scanErr.Category)
	var syntaxErr *json.SyntaxError
	require.ErrorAs(t, err, &syntaxErr)
	require.Contains(t, scanErr.Detail, "report json decode error")
	require.Contains(t, scanErr.Detail, syntaxErr.Error())
	ambassador.AssertExpectations(t)
}

// Only compare the subprocess contract, not exec.Cmd's private context fields.
func matchScanCommand(want *exec.Cmd) interface{} {
	return mock.MatchedBy(func(got *exec.Cmd) bool {
		return got.Path == want.Path && reflect.DeepEqual(got.Args, want.Args) &&
			reflect.DeepEqual(got.Env, want.Env) && got.Cancel != nil && got.WaitDelay == time.Second
	})
}

func TestExecutionRetryPolicy(t *testing.T) {
	for _, tc := range []struct {
		output    string
		category  ScanErrorCategory
		retryable bool
	}{
		{"failed to write to cache: OOM command not allowed when used memory > 'maxmemory'", ErrCategoryTrivyExec, true},
		{"dial tcp: connection refused", ErrCategoryNetwork, true},
		{"new diagnostic from a future Trivy release", ErrCategoryTrivyExec, true},
		{"unauthorized: authentication required", ErrCategoryAuth, false},
		{"failed to extract the archive", ErrCategoryUnscannable, false},
	} {
		t.Run(tc.output, func(t *testing.T) {
			ambassador := ext.NewMockAmbassador()
			ambassador.On("Environ").Return([]string{})
			ambassador.On("LookPath", "trivy").Return("/usr/local/bin/trivy", nil)
			img := &fake.FakeImage{}
			img.ManifestReturns(&v1.Manifest{}, nil)
			ambassador.On("RemoteImage", mock.Anything, mock.Anything).Return(img, nil)
			report, err := os.CreateTemp(t.TempDir(), "report")
			require.NoError(t, err)
			ambassador.On("TempFile", mock.Anything, mock.Anything).Return(report, nil)
			ambassador.On("RunCmd", mock.Anything).Return([]byte{}, []byte(tc.output), &exec.ExitError{})
			_, err = NewWrapper(etc.Trivy{}, ambassador).Scan(context.Background(), ImageRef{Name: "alpine", Auth: NoAuth{}}, ScanOption{Format: FormatJSON})
			var failure *ScanError
			require.ErrorAs(t, err, &failure)
			require.Equal(t, tc.category, failure.Category)
			require.Equal(t, tc.retryable, failure.Retryable)
			ambassador.AssertExpectations(t)
		})
	}
}

func TestClassifyTrivyErrorTaxonomy(t *testing.T) {
	tests := []struct {
		name      string
		output    string
		expected  ScanErrorCategory
		retryable bool
	}{
		{
			name:      "registry rate limit",
			output:    "2026-09-15T10:00:00Z\tFATAL\tFatal error\timage scan error: TOOMANYREQUESTS: retry-after: 60, allowed: 100/minute",
			expected:  ErrCategoryRateLimit,
			retryable: true,
		},
		{
			name:      "numeric rate limit status",
			output:    "2026-09-15T10:00:00Z\tFATAL\tFatal error\tGET https://registry/v2/token: status code 429",
			expected:  ErrCategoryRateLimit,
			retryable: true,
		},
		{
			name:      "database download failure",
			output:    "2026-09-15T10:00:00Z\tFATAL\tFatal error\tinit error: DB error: failed to download artifact from any source: 3 errors occurred",
			expected:  ErrCategoryDBDownload,
			retryable: true,
		},
		{
			name:      "java database failure",
			output:    "2026-09-15T10:00:00Z\tFATAL\tFatal error\tjava DB error: failed to initialize the Java DB",
			expected:  ErrCategoryDBDownload,
			retryable: true,
		},
		{
			// Trivy logs the advice and returns the schema mismatch wrapped in
			// "DB error:", so both keywords reach the classifier together.
			name:      "outdated binary",
			output:    "2026-09-15T10:00:00Z\tERROR\tTrivy version is old. Update to the latest version.\n2026-09-15T10:00:00Z\tFATAL\tFatal error\tDB error: the version of DB schema doesn't match. Local DB: 3, Expected: 2",
			expected:  ErrCategoryDBSchema,
			retryable: false,
		},
		{
			name:      "schema mismatch with updates disabled",
			output:    "2026-09-15T10:00:00Z\tFATAL\tFatal error\tDB error: validate error: --skip-db-update cannot be specified with the old DB schema. Local DB: 2, Expected: 3",
			expected:  ErrCategoryDBSchema,
			retryable: false,
		},
		{
			name:      "java schema mismatch with updates disabled",
			output:    "2026-09-15T10:00:00Z\tFATAL\tFatal error\tJava DB error: '--skip-java-db-update' cannot be specified on the first run",
			expected:  ErrCategoryDBSchema,
			retryable: false,
		},
		{
			name:      "schema version mismatch",
			output:    "FATAL\tFatal error\tthe local DB doesn't match the schema version required by this binary",
			expected:  ErrCategoryDBSchema,
			retryable: false,
		},
		{
			name:      "artifact that is not an image",
			output:    "2026-09-15T10:00:00Z\tFATAL\tFatal error\tunsupported artifact type \"application/vnd.cncf.helm.config.v1+json\" for image \"registry/chart:1.0\"",
			expected:  ErrCategoryUnsupportedArtifact,
			retryable: false,
		},
		{
			name:      "cache miss",
			output:    "2026-09-15T10:00:00Z\tFATAL\tFatal error\tlayer cache missing: sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10",
			expected:  ErrCategoryCache,
			retryable: true,
		},
		{
			name:      "expired deadline",
			output:    "2026-09-15T10:00:00Z\tFATAL\tFatal error\timage scan error: context deadline exceeded",
			expected:  ErrCategoryTimeout,
			retryable: true,
		},
		{
			name:      "broken layer archive",
			output:    "2026-09-15T10:00:00Z\tFATAL\tFatal error\trun error: walk error: failed to extract the archive: unexpected EOF",
			expected:  ErrCategoryUnscannable,
			retryable: false,
		},
		{
			// Known ordering hazard: a timed-out extraction is reported as a
			// timeout, because "timeout" is matched before the archive keywords.
			name:      "broken layer archive reported after a timeout",
			output:    "2026-09-15T10:00:00Z\tFATAL\tFatal error\trun error: timeout: failed to extract the archive",
			expected:  ErrCategoryTimeout,
			retryable: true,
		},
		{
			name:      "registry rejects the credentials",
			output:    "2026-09-15T10:00:00Z\tFATAL\tFatal error\timage scan error: GET https://registry/v2/library/alpine/manifests/latest: UNAUTHORIZED: authentication required",
			expected:  ErrCategoryAuth,
			retryable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyTrivyError(tt.output)
			require.Equal(t, tt.expected, got)
			require.Equal(t, tt.retryable, retryable(got))
		})
	}
}

func TestDigestDigitsAreNotARateLimit(t *testing.T) {
	require.Equal(t, ErrCategoryTrivyExec, classifyTrivyError("run error: layer sha256:429aa1b0 has 429000 bytes"))
}

func TestFailureIsDiagnosedFromStderrAndTrimmedToItsTail(t *testing.T) {
	for _, tc := range []struct {
		name           string
		stdout, stderr string
		expected       ScanErrorCategory
	}{
		{"stderr wins", "downloading db\n", "FATAL\tFatal error\tTOOMANYREQUESTS: retry-after: 60", ErrCategoryRateLimit},
		{"stdout is the fallback", "FATAL\tFatal error\tTOOMANYREQUESTS: retry-after: 60", "   \n", ErrCategoryRateLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ambassador := ext.NewMockAmbassador()
			ambassador.On("Environ").Return([]string{})
			ambassador.On("LookPath", "trivy").Return("/usr/local/bin/trivy", nil)
			img := &fake.FakeImage{}
			img.ManifestReturns(&v1.Manifest{}, nil)
			ambassador.On("RemoteImage", mock.Anything, mock.Anything).Return(img, nil)
			report, err := os.CreateTemp(t.TempDir(), "report")
			require.NoError(t, err)
			ambassador.On("TempFile", mock.Anything, mock.Anything).Return(report, nil)
			ambassador.On("RunCmd", mock.Anything).Return([]byte(tc.stdout), []byte(tc.stderr), &exec.ExitError{})
			_, err = NewWrapper(etc.Trivy{}, ambassador).Scan(context.Background(), ImageRef{Name: "alpine", Auth: NoAuth{}}, ScanOption{Format: FormatJSON})
			var failure *ScanError
			require.ErrorAs(t, err, &failure)
			require.Equal(t, tc.expected, failure.Category)
			ambassador.AssertExpectations(t)
		})
	}
}

func TestScanDetailCarriesTheTailOfTheDiagnostics(t *testing.T) {
	ambassador := ext.NewMockAmbassador()
	ambassador.On("Environ").Return([]string{})
	ambassador.On("LookPath", "trivy").Return("/usr/local/bin/trivy", nil)
	img := &fake.FakeImage{}
	img.ManifestReturns(&v1.Manifest{}, nil)
	ambassador.On("RemoteImage", mock.Anything, mock.Anything).Return(img, nil)
	report, err := os.CreateTemp(t.TempDir(), "report")
	require.NoError(t, err)
	ambassador.On("TempFile", mock.Anything, mock.Anything).Return(report, nil)
	stderr := strings.Repeat("noisy debug line\n", 1000) + "FATAL\tFatal error\tunsupported artifact type \"application/vnd.cncf.helm.config.v1+json\""
	ambassador.On("RunCmd", mock.Anything).Return([]byte{}, []byte(stderr), &exec.ExitError{})
	_, err = NewWrapper(etc.Trivy{}, ambassador).Scan(context.Background(), ImageRef{Name: "alpine", Auth: NoAuth{}}, ScanOption{Format: FormatJSON})
	var failure *ScanError
	require.ErrorAs(t, err, &failure)
	require.Equal(t, ErrCategoryUnsupportedArtifact, failure.Category)
	require.False(t, failure.Retryable)
	require.Len(t, failure.Detail, detailLimit)
	require.True(t, strings.HasSuffix(failure.Detail, `unsupported artifact type "application/vnd.cncf.helm.config.v1+json"`))
}

func TestGetVersionReusesTheBackgroundProbe(t *testing.T) {
	engine := ext.NewMockAmbassador()
	engine.On("RunCmd", mock.Anything).Return([]byte(`{"Version":"0.74.0",
		"VulnerabilityDB":{"Version":2,"NextUpdate":"2026-09-16T10:00:00Z","UpdatedAt":"2026-09-15T10:00:00Z"}}`), []byte{}, nil)
	recorder := metrics.New(true)
	cfg := etc.Config{
		Metrics: etc.Metrics{CollectionInterval: time.Minute, CollectionTimeout: time.Second},
		Trivy:   etc.Trivy{CacheDir: t.TempDir(), ReportsDir: t.TempDir()},
	}
	stop := recorder.Start(context.Background(), cfg, "adapter", engine)
	require.Eventually(t, func() bool { _, ok := recorder.CachedVersion(); return ok }, 5*time.Second, 10*time.Millisecond)
	stop()

	// No RunCmd expectation: reaching the CLI would fail the test.
	ambassador := ext.NewMockAmbassador()
	ambassador.On("LookPath", "trivy").Return("/usr/local/bin/trivy", nil)
	vi, err := NewWrapper(cfg.Trivy, ambassador, recorder).GetVersion()
	require.NoError(t, err)
	require.Equal(t, "0.74.0", vi.Version)
	require.NotNil(t, vi.VulnerabilityDB)
	require.Equal(t, time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC), vi.VulnerabilityDB.UpdatedAt)
	require.Nil(t, vi.JavaDB)
	ambassador.AssertNotCalled(t, "RunCmd", mock.Anything)
}

func TestScanCommandCarriesTheDefaultEngineFlags(t *testing.T) {
	ambassador := ext.NewMockAmbassador()
	ambassador.On("Environ").Return([]string{"GOMEMLIMIT=inherited", "KEEP=yes"})
	ambassador.On("LookPath", "trivy").Return("/usr/local/bin/trivy", nil)
	config := etc.Trivy{ImageSrc: "remote", SkipVersionCheck: true, DisableTelemetry: true, ChildGoMemLimit: "1GiB"}
	w := &wrapper{config: config, ambassador: ambassador}

	image, err := w.prepareScanCmd(context.Background(), ScanTarget{kind: TargetImage, ref: ImageRef{Name: "alpine", Auth: NoAuth{}}}, "report.json", ScanOption{Format: FormatJSON})
	require.NoError(t, err)
	require.Contains(t, strings.Join(image.Args, " "), "--image-src remote")
	require.Subset(t, image.Args, []string{"--skip-version-check", "--disable-telemetry"})
	require.NotContains(t, image.Args, "--max-image-size")
	require.Contains(t, image.Env, "GOMEMLIMIT=1GiB")
	require.NotContains(t, image.Env, "GOMEMLIMIT=inherited")
	require.Contains(t, image.Env, "KEEP=yes")

	// --image-src and --max-image-size belong to the image subcommand only.
	sbom, err := w.prepareScanCmd(context.Background(), ScanTarget{kind: TargetSBOM, filePath: "sbom.json"}, "report.json", ScanOption{Format: FormatJSON})
	require.NoError(t, err)
	require.NotContains(t, sbom.Args, "--image-src")
	require.Subset(t, sbom.Args, []string{"--skip-version-check", "--disable-telemetry"})
}

func TestScanCommandOmitsUnsetEngineFlags(t *testing.T) {
	ambassador := ext.NewMockAmbassador()
	ambassador.On("Environ").Return([]string{"GOMEMLIMIT=inherited"})
	ambassador.On("LookPath", "trivy").Return("/usr/local/bin/trivy", nil)
	w := &wrapper{config: etc.Trivy{ChildGoMemLimit: "off"}, ambassador: ambassador}
	cmd, err := w.prepareScanCmd(context.Background(), ScanTarget{kind: TargetImage, ref: ImageRef{Name: "alpine", Auth: NoAuth{}}}, "report.json", ScanOption{Format: FormatJSON})
	require.NoError(t, err)
	for _, flag := range []string{"--image-src", "--max-image-size", "--skip-version-check", "--disable-telemetry"} {
		require.NotContains(t, cmd.Args, flag)
	}
	// "off" is the escape hatch: whatever the pod sets is passed through.
	require.Contains(t, cmd.Env, "GOMEMLIMIT=inherited")
}

func TestScanCommandPassesTheImageSizeLimit(t *testing.T) {
	ambassador := ext.NewMockAmbassador()
	ambassador.On("Environ").Return([]string{})
	ambassador.On("LookPath", "trivy").Return("/usr/local/bin/trivy", nil)
	w := &wrapper{config: etc.Trivy{MaxImageSize: "10GB"}, ambassador: ambassador}
	cmd, err := w.prepareScanCmd(context.Background(), ScanTarget{kind: TargetImage, ref: ImageRef{Name: "alpine", Auth: NoAuth{}}}, "report.json", ScanOption{Format: FormatJSON})
	require.NoError(t, err)
	require.Contains(t, strings.Join(cmd.Args, " "), "--max-image-size 10GB")
}

func TestClassificationReadsTheFatalLineNotTheWholeLog(t *testing.T) {
	// A database mirror that is unreachable logs a failure and then succeeds
	// from the next repository, so the buffer of a successful run carries
	// download errors that have nothing to do with why the scan ended.
	mirrorFallback := "2026-09-15T09:59:58Z\tERROR\t[oci] Failed to download artifact\trepo=\"mirror.gcr.io/aquasec/trivy-db\" err=\"oci download error\"\n" +
		"2026-09-15T09:59:58Z\tINFO\t[oci] Trying to download artifact from other repository...\n" +
		"2026-09-15T09:59:59Z\tINFO\t[vulndb] Vulnerability DB successfully downloaded\n"

	for _, tc := range []struct {
		name     string
		output   string
		expected ScanErrorCategory
	}{
		{
			name:     "fatal auth after a mirror fallback",
			output:   mirrorFallback + "2026-09-15T10:00:00Z\tFATAL\tFatal error\timage scan error: GET https://registry/v2/: UNAUTHORIZED: authentication required",
			expected: ErrCategoryAuth,
		},
		{
			name:     "fatal database download",
			output:   mirrorFallback + "2026-09-15T10:00:00Z\tFATAL\tFatal error\tinit error: DB error: failed to download artifact from any source",
			expected: ErrCategoryDBDownload,
		},
		{
			name: "debug mode puts the error chain under the fatal line",
			output: mirrorFallback + "2026-09-15T10:00:00Z\tFATAL\tFatal error\n" +
				"  - image scan error\n  - GET https://registry/v2/: UNAUTHORIZED: authentication required\n",
			expected: ErrCategoryAuth,
		},
		{
			name:     "only the last fatal line counts",
			output:   "2026-09-15T09:00:00Z\tFATAL\tFatal error\timage scan error: TOOMANYREQUESTS\n2026-09-15T10:00:00Z\tFATAL\tFatal error\timage scan error: context deadline exceeded",
			expected: ErrCategoryTimeout,
		},
		{
			// A child killed before it could report leaves no fatal line, so
			// the whole buffer is classified as it always was.
			name:     "no fatal line at all",
			output:   mirrorFallback,
			expected: ErrCategoryDBDownload,
		},
		{
			name:     "empty output",
			output:   "",
			expected: ErrCategoryTrivyExec,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expected, classifyTrivyError(tc.output))
		})
	}
}
