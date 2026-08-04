//go:build integration

package redis

import (
	"bytes"
	"compress/gzip"
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

		rawJSON, err := json.Marshal(report)
		require.NoError(t, err)

		storedSize, err := pool.StrLen(ctx, fmt.Sprintf("%s:scan-report:%s", config.Namespace, scanJobKey.String())).Result()
		require.NoError(t, err)
		t.Logf("raw report JSON: %d bytes, stored: %d bytes, ratio: %.1fx", len(rawJSON), storedSize, float64(len(rawJSON))/float64(storedSize))
		assert.Less(t, storedSize, int64(len(rawJSON)/4), "stored report should be at least 4x smaller than raw JSON")

		j, err := store.Get(ctx, scanJobKey)
		require.NoError(t, err)
		require.NotNil(t, j)

		roundTripped, err := json.Marshal(j.Report)
		require.NoError(t, err)
		original, err := json.Marshal(report)
		require.NoError(t, err)
		assert.Equal(t, original, roundTripped, "report should round-trip byte-identical")
	})

	t.Run("Status flip does not rewrite the report blob", func(t *testing.T) {
		scanJobKey := job.ScanJobKey{
			ID:        "status-flip",
			MIMEType:  api.MimeTypeSecuritySBOMReport,
			MediaType: api.MediaTypeSPDX,
		}
		jobKey := fmt.Sprintf("%s:scan-job:%s", config.Namespace, scanJobKey.String())
		reportKey := fmt.Sprintf("%s:scan-report:%s", config.Namespace, scanJobKey.String())

		err := store.Create(ctx, job.ScanJob{Key: scanJobKey, Status: job.Pending})
		require.NoError(t, err)
		err = store.UpdateReport(ctx, scanJobKey, harbor.ScanReport{
			MediaType: api.MediaTypeSPDX,
			SBOM:      generateSPDXDocument(t, 2_000_000),
		})
		require.NoError(t, err)

		reportBytesBefore, err := pool.Get(ctx, reportKey).Result()
		require.NoError(t, err)

		// Shorten both TTLs so the assertions below prove UpdateStatus re-arms
		// them; freshly written keys would sit near the full TTL either way.
		require.NoError(t, pool.Expire(ctx, jobKey, parseDuration(t, "3s")).Err())
		require.NoError(t, pool.Expire(ctx, reportKey, parseDuration(t, "3s")).Err())

		err = store.UpdateStatus(ctx, scanJobKey, job.Finished)
		require.NoError(t, err)

		jobSize, err := pool.StrLen(ctx, jobKey).Result()
		require.NoError(t, err)
		assert.Less(t, jobSize, int64(1024), "scan job key must hold only status/metadata, not the report")

		reportBytesAfter, err := pool.Get(ctx, reportKey).Result()
		require.NoError(t, err)
		assert.Equal(t, reportBytesBefore, reportBytesAfter, "status flip must not rewrite the report blob")

		jobTTL, err := pool.TTL(ctx, jobKey).Result()
		require.NoError(t, err)
		reportTTL, err := pool.TTL(ctx, reportKey).Result()
		require.NoError(t, err)
		assert.Greater(t, jobTTL.Seconds(), 5.0, "job key TTL should be re-armed to the full ScanJobTTL")
		assert.Greater(t, reportTTL.Seconds(), 5.0, "report key TTL should be re-armed to the full ScanJobTTL")
		assert.InDelta(t, jobTTL.Seconds(), reportTTL.Seconds(), 1, "both keys should carry the same TTL")

		j, err := store.Get(ctx, scanJobKey)
		require.NoError(t, err)
		require.NotNil(t, j)
		assert.Equal(t, job.Finished, j.Status)
		assert.NotNil(t, j.Report.SBOM, "report must survive the status flip")
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
		assert.Equal(t, legacyJob.Report, j.Report, "inline pre-split report must survive a status update")
	})

	t.Run("UpdateReport on a legacy combined value wins over the inline report", func(t *testing.T) {
		scanJobKey := job.ScanJobKey{
			ID:       "legacy-rescan",
			MIMEType: api.MimeTypeSecurityVulnerabilityReport,
		}
		legacyJob := job.ScanJob{
			Key:    scanJobKey,
			Status: job.Pending,
			Report: harbor.ScanReport{
				Severity:        harbor.SevLow,
				Vulnerabilities: []harbor.VulnerabilityItem{{ID: "CVE-2020-0001"}},
			},
		}
		rawJSON, err := json.Marshal(legacyJob)
		require.NoError(t, err)
		key := fmt.Sprintf("%s:scan-job:%s", config.Namespace, scanJobKey.String())
		require.NoError(t, pool.Set(ctx, key, string(rawJSON), config.ScanJobTTL).Err())

		newReport := harbor.ScanReport{
			Severity:        harbor.SevCritical,
			Vulnerabilities: []harbor.VulnerabilityItem{{ID: "CVE-2026-9999"}},
		}
		require.NoError(t, store.UpdateReport(ctx, scanJobKey, newReport))

		j, err := store.Get(ctx, scanJobKey)
		require.NoError(t, err)
		require.NotNil(t, j)
		assert.Equal(t, newReport, j.Report, "separate report key must fully replace the inline report")
	})

	t.Run("Rejects decompression bombs", func(t *testing.T) {
		scanJobKey := job.ScanJobKey{
			ID:       "bomb",
			MIMEType: api.MimeTypeSecurityVulnerabilityReport,
		}

		// gzip of >64 MiB of zeros: ~64 KB stored, over the decompression cap
		var bomb bytes.Buffer
		gw := gzip.NewWriter(&bomb)
		zeros := make([]byte, 1<<20)
		for written := 0; written <= 64<<20; written += len(zeros) {
			_, err := gw.Write(zeros)
			require.NoError(t, err)
		}
		require.NoError(t, gw.Close())

		key := fmt.Sprintf("%s:scan-job:%s", config.Namespace, scanJobKey.String())
		require.NoError(t, pool.Set(ctx, key, bomb.Bytes(), config.ScanJobTTL).Err())

		_, err := store.Get(ctx, scanJobKey)
		require.ErrorContains(t, err, "exceeds")
	})

	t.Run("Zero TTL means no expiry", func(t *testing.T) {
		noTTLStore := redis.NewStore(etc.RedisStore{
			Namespace:  "harbor.scanner.trivy:store-nottl",
			ScanJobTTL: 0,
		}, pool)

		scanJobKey := job.ScanJobKey{
			ID:       "no-ttl",
			MIMEType: api.MimeTypeSecurityVulnerabilityReport,
		}
		jobKey := fmt.Sprintf("harbor.scanner.trivy:store-nottl:scan-job:%s", scanJobKey.String())
		reportKey := fmt.Sprintf("harbor.scanner.trivy:store-nottl:scan-report:%s", scanJobKey.String())
		t.Cleanup(func() { pool.Del(ctx, jobKey, reportKey) })

		require.NoError(t, noTTLStore.Create(ctx, job.ScanJob{Key: scanJobKey, Status: job.Queued}))
		require.NoError(t, noTTLStore.UpdateReport(ctx, scanJobKey, harbor.ScanReport{Severity: harbor.SevHigh}))
		require.NoError(t, noTTLStore.UpdateStatus(ctx, scanJobKey, job.Finished))

		for _, key := range []string{jobKey, reportKey} {
			ttl, err := pool.TTL(ctx, key).Result()
			require.NoError(t, err)
			assert.Equal(t, time.Duration(-1), ttl, "key %s should persist without TTL", key)
		}

		j, err := noTTLStore.Get(ctx, scanJobKey)
		require.NoError(t, err)
		require.NotNil(t, j)
		assert.Equal(t, job.Finished, j.Status)
		assert.Equal(t, harbor.SevHigh, j.Report.Severity)
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
