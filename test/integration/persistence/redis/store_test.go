//go:build integration

package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/container-registry/harbor-scanner-trivy/pkg/http/api"

	"github.com/container-registry/harbor-scanner-trivy/pkg/etc"
	"github.com/container-registry/harbor-scanner-trivy/pkg/harbor"
	"github.com/container-registry/harbor-scanner-trivy/pkg/job"
	"github.com/container-registry/harbor-scanner-trivy/pkg/persistence/redis"
	"github.com/container-registry/harbor-scanner-trivy/pkg/redisx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// TestStore is an integration test for the Redis persistence store.
func TestStore(t *testing.T) {
	if testing.Short() {
		t.Skip("An integration test")
	}

	ctx := context.Background()
	redisC, err := tc.GenericContainer(ctx, tc.GenericContainerRequest{
		ContainerRequest: tc.ContainerRequest{
			Image:        "redis:5.0.5",
			ExposedPorts: []string{"6379/tcp"},
			WaitingFor:   wait.ForLog("Ready to accept connections"),
		},
		Started: true,
	})
	require.NoError(t, err, "should start redis container")
	defer func() {
		_ = redisC.Terminate(ctx)
	}()

	redisURL := getRedisURL(t, ctx, redisC)

	config := etc.RedisStore{
		Namespace:  "harbor.scanner.trivy:store",
		ScanJobTTL: parseDuration(t, "10s"),
	}

	pool, err := redisx.NewClient(etc.RedisPool{
		URL: redisURL,
	})
	require.NoError(t, err)

	store := redis.NewStore(config, pool)

	t.Run("CRUD", func(t *testing.T) {
		scanJobKey := job.ScanJobKey{
			ID:       "123",
			MIMEType: api.MimeTypeSecurityVulnerabilityReport,
		}

		err := store.Create(ctx, job.ScanJob{
			Key:    scanJobKey,
			Status: job.Queued,
		})
		require.NoError(t, err, "saving scan job should not fail")

		j, err := store.Get(ctx, scanJobKey)
		require.NoError(t, err, "getting scan job should not fail")
		assert.Equal(t, &job.ScanJob{
			Key:    scanJobKey,
			Status: job.Queued,
		}, j)

		err = store.UpdateStatus(ctx, scanJobKey, job.Pending)
		require.NoError(t, err, "updating scan job status should not fail")

		j, err = store.Get(ctx, scanJobKey)
		require.NoError(t, err, "getting scan job should not fail")
		assert.Equal(t, &job.ScanJob{
			Key:    scanJobKey,
			Status: job.Pending,
		}, j)

		scanReport := harbor.ScanReport{
			Severity: harbor.SevHigh,
			Vulnerabilities: []harbor.VulnerabilityItem{
				{
					ID: "CVE-2013-1400",
				},
			},
		}

		err = store.UpdateReport(ctx, scanJobKey, scanReport)
		require.NoError(t, err, "updating scan job reports should not fail")

		j, err = store.Get(ctx, scanJobKey)
		require.NoError(t, err, "retrieving scan job should not fail")
		require.NotNil(t, j, "retrieved scan job must not be nil")
		assert.Equal(t, scanReport, j.Report)

		err = store.UpdateStatus(ctx, scanJobKey, job.Finished)
		require.NoError(t, err)

		time.Sleep(parseDuration(t, "12s"))

		j, err = store.Get(ctx, scanJobKey)
		require.NoError(t, err, "retrieve scan job should not fail")
		require.Nil(t, j, "retrieved scan job should be nil, i.e. expired")
	})

	t.Run("Compresses stored values", func(t *testing.T) {
		scanJobKey := job.ScanJobKey{
			ID:        "big-sbom",
			MIMEType:  api.MimeTypeSecuritySBOMReport,
			MediaType: api.MediaTypeSPDX,
		}

		report := harbor.ScanReport{
			MediaType: api.MediaTypeSPDX,
			SBOM:      generateSPDXDocument(t, 2_000_000),
		}

		err := store.Create(ctx, job.ScanJob{Key: scanJobKey, Status: job.Queued})
		require.NoError(t, err)
		err = store.UpdateReport(ctx, scanJobKey, report)
		require.NoError(t, err)

		rawJSON, err := json.Marshal(job.ScanJob{Key: scanJobKey, Status: job.Queued, Report: report})
		require.NoError(t, err)

		storedSize, err := pool.StrLen(ctx, fmt.Sprintf("%s:scan-job:%s", config.Namespace, scanJobKey.String())).Result()
		require.NoError(t, err)
		t.Logf("raw JSON: %d bytes, stored: %d bytes, ratio: %.1fx", len(rawJSON), storedSize, float64(len(rawJSON))/float64(storedSize))
		assert.Less(t, storedSize, int64(len(rawJSON)/4), "stored value should be at least 4x smaller than raw JSON")

		j, err := store.Get(ctx, scanJobKey)
		require.NoError(t, err)
		require.NotNil(t, j)

		roundTripped, err := json.Marshal(j.Report)
		require.NoError(t, err)
		original, err := json.Marshal(report)
		require.NoError(t, err)
		assert.Equal(t, original, roundTripped, "report should round-trip byte-identical")
	})

	t.Run("Reads legacy uncompressed values", func(t *testing.T) {
		scanJobKey := job.ScanJobKey{
			ID:       "legacy",
			MIMEType: api.MimeTypeSecurityVulnerabilityReport,
		}
		legacyJob := job.ScanJob{
			Key:    scanJobKey,
			Status: job.Finished,
			Report: harbor.ScanReport{
				Severity:        harbor.SevCritical,
				Vulnerabilities: []harbor.VulnerabilityItem{{ID: "CVE-2024-0001"}},
			},
		}
		rawJSON, err := json.Marshal(legacyJob)
		require.NoError(t, err)

		key := fmt.Sprintf("%s:scan-job:%s", config.Namespace, scanJobKey.String())
		require.NoError(t, pool.Set(ctx, key, string(rawJSON), config.ScanJobTTL).Err())

		j, err := store.Get(ctx, scanJobKey)
		require.NoError(t, err, "legacy plain-JSON value should still be readable")
		assert.Equal(t, &legacyJob, j)

		err = store.UpdateStatus(ctx, scanJobKey, job.Failed, "some error")
		require.NoError(t, err, "updating a legacy value should not fail")

		j, err = store.Get(ctx, scanJobKey)
		require.NoError(t, err)
		require.NotNil(t, j)
		assert.Equal(t, job.Failed, j.Status)
	})

	t.Run("UpdateReport on missing job fails", func(t *testing.T) {
		err := store.UpdateReport(ctx, job.ScanJobKey{
			ID:       "does-not-exist",
			MIMEType: api.MimeTypeSecurityVulnerabilityReport,
		}, harbor.ScanReport{})
		require.Error(t, err)
	})
}

// generateSPDXDocument builds an SPDX-like document of roughly minBytes of
// JSON, mimicking the repetitive structure of real Trivy SBOM output.
func generateSPDXDocument(t *testing.T, minBytes int) any {
	t.Helper()

	packages := []map[string]any{}
	relationships := []map[string]any{}
	for i := 0; len(packages) == 0 || i*500 < minBytes; i++ {
		id := fmt.Sprintf("SPDXRef-Package-%06d", i)
		packages = append(packages, map[string]any{
			"SPDXID":           id,
			"name":             fmt.Sprintf("libexample%d", i),
			"versionInfo":      fmt.Sprintf("1.%d.%d-r0", i%20, i%7),
			"licenseConcluded": "GPL-2.0-only AND MIT",
			"licenseDeclared":  "GPL-2.0-only AND MIT",
			"downloadLocation": "NOASSERTION",
			"externalRefs": []map[string]any{{
				"referenceCategory": "PACKAGE-MANAGER",
				"referenceType":     "purl",
				"referenceLocator":  fmt.Sprintf("pkg:apk/alpine/libexample%d@1.%d.%d-r0?arch=x86_64&distro=3.19.1", i, i%20, i%7),
			}},
			"attributionTexts": []string{fmt.Sprintf("PkgID: libexample%d@1.%d.%d-r0", i, i%20, i%7)},
		})
		relationships = append(relationships, map[string]any{
			"spdxElementId":      "SPDXRef-ContainerImage",
			"relatedSpdxElement": id,
			"relationshipType":   "CONTAINS",
		})
	}

	doc := map[string]any{
		"spdxVersion":       "SPDX-2.3",
		"dataLicense":       "CC0-1.0",
		"SPDXID":            "SPDXRef-DOCUMENT",
		"name":              "alpine:3.19",
		"documentNamespace": "http://aquasecurity.github.io/trivy/container_image/alpine:3.19",
		"packages":          packages,
		"relationships":     relationships,
	}

	raw, err := json.Marshal(doc)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(raw), minBytes, "generated SBOM should reach the target size")

	// round-trip through JSON so the document matches what the store returns
	// (map[string]any with float64 numbers), keeping equality checks simple
	var generic any
	require.NoError(t, json.Unmarshal(raw, &generic))
	return generic
}

func getRedisURL(t *testing.T, ctx context.Context, redisC tc.Container) string {
	t.Helper()
	host, err := redisC.Host(ctx)
	require.NoError(t, err)
	port, err := redisC.MappedPort(ctx, "6379")
	require.NoError(t, err)
	return fmt.Sprintf("redis://%s:%d", host, port.Num())
}

func parseDuration(t *testing.T, s string) time.Duration {
	t.Helper()
	d, err := time.ParseDuration(s)
	require.NoError(t, err, "should parse duration %s", s)
	return d
}
