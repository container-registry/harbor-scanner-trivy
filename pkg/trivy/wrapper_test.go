package trivy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
	"github.com/stretchr/testify/require"
)

func TestCacheConfigurationReachesTrivyWithoutCredentialsInArgs(t *testing.T) {
	ambassador := ext.NewMockAmbassador()
	ambassador.On("Environ").Return([]string{"TRIVY_CACHE_BACKEND=fs", "TRIVY_CACHE_TTL=0", "KEEP=yes"})
	ambassador.On("LookPath", "trivy").Return("/usr/local/bin/trivy", nil)
	w := &wrapper{config: etc.Trivy{CacheBackend: "rediss://user:private@cache:6379/0", CacheTTL: 48 * time.Hour}, ambassador: ambassador}
	cmd, err := w.prepareScanCmd(ScanTarget{kind: TargetImage, ref: ImageRef{Name: "alpine", Auth: NoAuth{}}}, "report.json", ScanOption{Format: FormatJSON})
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
			ambassador.On("RunCmd", mock.Anything).Return([]byte("redis cache unavailable"), fmt.Errorf("cache: %w", cause))
			w := NewWrapper(etc.Trivy{CacheBackend: "redis://:cache@redis:6379/0", CacheTTL: time.Hour}, ambassador)
			_, err = w.Scan(ImageRef{Name: "alpine", Auth: NoAuth{}}, ScanOption{Format: FormatJSON})
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
	cmd, err := w.prepareScanCmd(ScanTarget{kind: TargetImage, ref: ImageRef{Name: "alpine", Auth: NoAuth{}}}, "report.json", ScanOption{Context: ctx})
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

		ambassador.On("RunCmd", &exec.Cmd{
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
		},
		).Return([]byte{}, nil)

		imageRef := ImageRef{
			Name: "alpine:3.10.2",
			Auth: BasicAuth{
				Username: "dave.loper",
				Password: "s3cret",
			},
			NonSSL: true,
		}

		got, err := NewWrapper(config, ambassador).Scan(imageRef, ScanOption{Format: FormatJSON})
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

		ambassador.On("RunCmd", &exec.Cmd{
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
		},
		).Return([]byte{}, nil)

		imageRef := ImageRef{
			Name: "alpine@sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10",
			Auth: NoAuth{},
		}

		got, err := NewWrapper(config, ambassador).Scan(imageRef, ScanOption{Format: FormatJSON})
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
	).Return(b, nil)

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
	ambassador.On("RunCmd", mock.Anything).Return([]byte{}, nil)
	wrapper := NewWrapper(etc.Trivy{}, ambassador)
	_, err = wrapper.Scan(ImageRef{Name: "alpine:latest", Auth: NoAuth{}}, ScanOption{Format: FormatJSON})
	var scanErr *ScanError
	require.ErrorAs(t, err, &scanErr)
	require.Equal(t, ErrCategoryReportParse, scanErr.Category)
	var syntaxErr *json.SyntaxError
	require.ErrorAs(t, err, &syntaxErr)
	require.Contains(t, scanErr.Detail, "report json decode error")
	require.Contains(t, scanErr.Detail, syntaxErr.Error())
	ambassador.AssertExpectations(t)
}
