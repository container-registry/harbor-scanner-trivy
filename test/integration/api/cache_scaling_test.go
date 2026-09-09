//go:build integration

package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/container-registry/harbor-scanner-trivy/pkg/etc"
	"github.com/container-registry/harbor-scanner-trivy/pkg/ext"
	"github.com/container-registry/harbor-scanner-trivy/pkg/harbor"
	adapterapi "github.com/container-registry/harbor-scanner-trivy/pkg/http/api"
	v1 "github.com/container-registry/harbor-scanner-trivy/pkg/http/api/v1"
	"github.com/container-registry/harbor-scanner-trivy/pkg/job"
	"github.com/container-registry/harbor-scanner-trivy/pkg/persistence"
	storedb "github.com/container-registry/harbor-scanner-trivy/pkg/persistence/redis"
	"github.com/container-registry/harbor-scanner-trivy/pkg/queue"
	"github.com/container-registry/harbor-scanner-trivy/pkg/scan"
	"github.com/container-registry/harbor-scanner-trivy/pkg/trivy"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestDedicatedCacheBackends(t *testing.T) {
	ctx := context.Background()
	for _, backend := range []struct{ image, binary string }{{"redis:7.4", "redis-server"}, {"valkey/valkey:8.1", "valkey-server"}} {
		t.Run(backend.image, func(t *testing.T) {
			cert, key := cacheCertificates(t)
			container, err := tc.GenericContainer(ctx, tc.GenericContainerRequest{ContainerRequest: tc.ContainerRequest{
				Image: backend.image, ExposedPorts: []string{"6379/tcp"},
				Cmd:        []string{backend.binary, "--port", "0", "--tls-port", "6379", "--tls-cert-file", "/tmp/cache.crt", "--tls-key-file", "/tmp/cache.key", "--tls-ca-cert-file", "/tmp/cache.crt", "--requirepass", "cache-test-password"},
				Files:      []tc.ContainerFile{{HostFilePath: cert, ContainerFilePath: "/tmp/cache.crt", FileMode: 0o644}, {HostFilePath: key, ContainerFilePath: "/tmp/cache.key", FileMode: 0o644}},
				WaitingFor: wait.ForListeningPort("6379/tcp"),
			}, Started: true})
			require.NoError(t, err)
			t.Cleanup(func() { _ = container.Terminate(context.Background()) })
			host, err := container.Host(ctx)
			require.NoError(t, err)
			port, err := container.MappedPort(ctx, "6379/tcp")
			require.NoError(t, err)
			backendURL := fmt.Sprintf("rediss://:cache-test-password@%s/0", net.JoinHostPort(host, port.Port()))
			pair, err := tls.LoadX509KeyPair(cert, key)
			require.NoError(t, err)
			roots := x509.NewCertPool()
			certBytes, err := os.ReadFile(cert)
			require.NoError(t, err)
			require.True(t, roots.AppendCertsFromPEM(certBytes))
			opts, err := redis.ParseURL(backendURL)
			require.NoError(t, err)
			opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{pair}}
			rdb := redis.NewClient(opts)
			t.Cleanup(func() { _ = rdb.Close() })
			require.NoError(t, rdb.Ping(ctx).Err())
			require.NoError(t, queue.CheckBackend(ctx, rdb))

			var layerGETs atomic.Int64
			var layerPath atomic.Value
			layerPath.Store("")
			reg := registry.New()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				path := layerPath.Load().(string)
				if r.Method == http.MethodGet && path != "" && strings.HasSuffix(r.URL.Path, path) {
					layerGETs.Add(1)
				}
				reg.ServeHTTP(w, r)
			}))
			t.Cleanup(server.Close)
			regURL, err := url.Parse(server.URL)
			require.NoError(t, err)
			image := setupTestImage(t, regURL)
			// Alpine's layer digest is obtained from the registry manifest; count only
			// layer GETs, not config/manifest reads needed to identify cache keys.
			img, err := ext.DefaultAmbassador.RemoteImage(image)
			require.NoError(t, err)
			manifest, err := img.Manifest()
			require.NoError(t, err)
			layerPath.Store("/blobs/" + manifest.Layers[0].Digest.String())
			newPod := func() trivy.Wrapper {
				_, cfg := initTrivy(t, time.Now())
				cfg.CacheBackend, cfg.CacheTTL = backendURL, time.Hour
				cfg.CacheRedisCA, cfg.CacheRedisCert, cfg.CacheRedisKey = cert, cert, key
				return trivy.NewWrapper(cfg, ext.DefaultAmbassador)
			}
			ref := trivy.ImageRef{Name: image.String(), Auth: trivy.NoAuth{}, NonSSL: true}
			coldStart := time.Now()
			baseline, err := newPod().Scan(ref, trivy.ScanOption{Format: trivy.FormatJSON, Context: ctx})
			require.NoError(t, err)
			require.NotEmpty(t, baseline.Vulnerabilities)
			coldGETs := layerGETs.Load()
			require.Positive(t, coldGETs)
			t.Logf("cold scan: %s, layer GETs=%d", time.Since(coldStart), coldGETs)
			for _, replicas := range []int{2, 4} {
				pods := make([]trivy.Wrapper, replicas)
				for i := range pods {
					pods[i] = newPod()
				}
				results := make([]trivy.Report, replicas)
				errs := make([]error, replicas)
				start := time.Now()
				var wg sync.WaitGroup
				for i := range pods {
					wg.Add(1)
					go func(i int) {
						defer wg.Done()
						results[i], errs[i] = pods[i].Scan(ref, trivy.ScanOption{Format: trivy.FormatJSON, Context: ctx})
					}(i)
				}
				wg.Wait()
				for i := range results {
					require.NoError(t, errs[i])
					require.Equal(t, baseline, results[i])
				}
				require.Equal(t, coldGETs, layerGETs.Load(), "warm pods must reuse cached layer analysis")
				t.Logf("%d warm pods: %s, completed scans/minute=%.1f, extra layer GETs=0", replicas, time.Since(start), float64(replicas)/time.Since(start).Minutes())
			}
			cacheKeys, _, err := rdb.Scan(ctx, 0, "fanal::*", 100).Result()
			require.NoError(t, err)
			require.NotEmpty(t, cacheKeys)
			for _, k := range cacheKeys {
				require.Positive(t, rdb.TTL(ctx, k).Val())
			}
			info, err := rdb.Info(ctx, "memory").Result()
			require.NoError(t, err)
			for _, line := range strings.Split(info, "\r\n") {
				if strings.HasPrefix(line, "used_memory:") || strings.HasPrefix(line, "used_memory_peak:") {
					t.Log(line)
				}
			}
			// TTL expiry must result in re-analysis with identical findings.
			for _, k := range cacheKeys {
				require.NoError(t, rdb.PExpire(ctx, k, time.Millisecond).Err())
			}
			require.Eventually(t, func() bool { return rdb.Exists(ctx, cacheKeys...).Val() == 0 }, time.Second, time.Millisecond)
			afterExpiry, err := newPod().Scan(ref, trivy.ScanOption{Format: trivy.FormatJSON, Context: ctx})
			require.NoError(t, err)
			require.Equal(t, baseline, afterExpiry)
			require.Greater(t, layerGETs.Load(), coldGETs)
			// Force a cache-only memory budget below server overhead. The cache
			// cannot hold a working set; report a retryable error rather than
			// silently selecting local storage or accepting incomplete findings.
			require.NoError(t, rdb.ConfigSet(ctx, "maxmemory-policy", "allkeys-lru").Err())
			require.NoError(t, rdb.ConfigSet(ctx, "maxmemory", "1").Err())
			_, err = newPod().Scan(ref, trivy.ScanOption{Format: trivy.FormatJSON, Context: ctx})
			var cacheErr *trivy.ScanError
			require.ErrorAs(t, err, &cacheErr)
			require.Equal(t, trivy.ErrCategoryCache, cacheErr.Category)
			require.NoError(t, rdb.ConfigSet(ctx, "maxmemory", "0").Err())
			afterRecovery, err := newPod().Scan(ref, trivy.ScanOption{Format: trivy.FormatJSON, Context: ctx})
			require.NoError(t, err)
			require.Equal(t, baseline, afterRecovery)
			testStreamBackend(t, rdb)
			testAPIWorkers(t, rdb, newPod, ref, baseline)
		})
	}
}

// Exercise the Harbor HTTP boundary with real controllers and one Trivy wrapper
// per worker, using separate local databases and the shared cache.
func testAPIWorkers(t *testing.T, rdb *redis.Client, newPod func() trivy.Wrapper, ref trivy.ImageRef, baseline trivy.Report) {
	t.Helper()
	image, err := name.NewDigest(ref.Name)
	require.NoError(t, err)
	request := harbor.ScanRequest{Registry: harbor.Registry{URL: "http://" + image.RegistryStr()}, Artifact: harbor.Artifact{Repository: image.RepositoryStr(), Digest: image.DigestStr()}}
	transformer := scan.NewTransformer(&scan.SystemClock{})
	expected := transformer.Transform("", request, baseline)
	for _, replicas := range []int{2, 4} {
		t.Run(fmt.Sprintf("http-%d-workers", replicas), func(t *testing.T) {
			ctx := context.Background()
			s := storedb.NewStore(etc.RedisStore{Namespace: fmt.Sprintf("api:%d:data", replicas), ScanJobTTL: time.Minute}, rdb)
			cfg := etc.JobQueue{Namespace: fmt.Sprintf("api:%d:queue", replicas), WorkerConcurrency: 1}
			var w trivy.Wrapper
			for range replicas {
				w = newPod()
				worker := queue.NewWorker(cfg, rdb, scan.NewController(s, w, transformer), s)
				worker.Start(ctx)
				t.Cleanup(worker.Stop)
			}
			server := httptest.NewServer(v1.NewAPIHandler(etc.BuildInfo{}, etc.Config{}, queue.NewEnqueuer(cfg, rdb, s), s, w))
			t.Cleanup(server.Close)
			client := server.Client()
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			payload, err := json.Marshal(request)
			require.NoError(t, err)
			var ids []string
			for range 8 {
				response, err := client.Post(server.URL+"/api/v1/scan", "application/json", bytes.NewReader(payload))
				require.NoError(t, err)
				require.Equal(t, http.StatusAccepted, response.StatusCode)
				var accepted harbor.ScanResponse
				require.NoError(t, json.NewDecoder(response.Body).Decode(&accepted))
				require.NoError(t, response.Body.Close())
				ids = append(ids, accepted.ID)
			}
			for _, id := range ids {
				var report harbor.ScanReport
				require.Eventually(t, func() bool {
					response, err := client.Get(server.URL + "/api/v1/scan/" + id + "/report")
					if err != nil {
						return false
					}
					defer response.Body.Close()
					return response.StatusCode == http.StatusOK && json.NewDecoder(response.Body).Decode(&report) == nil
				}, 15*time.Second, 20*time.Millisecond)
				expectedJSON, err := json.Marshal(expected.Vulnerabilities)
				require.NoError(t, err)
				actualJSON, err := json.Marshal(report.Vulnerabilities)
				require.NoError(t, err)
				require.JSONEq(t, string(expectedJSON), string(actualJSON))
				require.Equal(t, expected.Severity, report.Severity)
			}
		})
	}
}

type completingScan struct{ store persistence.Store }

func (c completingScan) Scan(ctx context.Context, key job.ScanJobKey, _ *harbor.ScanRequest) error {
	if err := c.store.UpdateStatus(ctx, key, job.Pending); err != nil {
		return err
	}
	return c.store.UpdateStatus(ctx, key, job.Finished)
}

func testStreamBackend(t *testing.T, rdb *redis.Client) {
	t.Helper()
	ctx := context.Background()
	s := storedb.NewStore(etc.RedisStore{Namespace: "test:jobs", ScanJobTTL: time.Minute}, rdb)
	cfg := etc.JobQueue{Namespace: "test:queue", WorkerConcurrency: 1}
	var keys []job.ScanJobKey
	for range 8 {
		id, err := queue.NewEnqueuer(cfg, rdb, s).Enqueue(ctx, harbor.ScanRequest{Capabilities: []harbor.Capability{{Type: harbor.CapabilityTypeVulnerability, ProducesMIMETypes: []adapterapi.MIMEType{adapterapi.MimeTypeSecurityVulnerabilityReport}}}})
		require.NoError(t, err)
		keys = append(keys, job.ScanJobKey{ID: id, MIMEType: adapterapi.MimeTypeSecurityVulnerabilityReport})
	}
	for range 2 {
		w := queue.NewWorker(cfg, rdb, completingScan{s}, s)
		w.Start(ctx)
		t.Cleanup(w.Stop)
	}
	require.Eventually(t, func() bool {
		for _, key := range keys {
			state, err := s.Get(ctx, key)
			if err != nil || state == nil || state.Status != job.Finished {
				return false
			}
		}
		return true
	}, 10*time.Second, 20*time.Millisecond)
}

func cacheCertificates(t *testing.T) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	require.NoError(t, err)
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cache.crt"), filepath.Join(dir, "cache.key")
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600))
	return certPath, keyPath
}
