package trivy

import (
	"errors"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/fake"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/container-registry/harbor-scanner-trivy/pkg/etc"
	"github.com/container-registry/harbor-scanner-trivy/pkg/ext"
)

func TestFindSBOMAccessory(t *testing.T) {
	imageDigest := v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("a", 64)}
	sbomDigestOld := v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("b", 64)}
	sbomDigestNew := v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("c", 64)}

	ref, err := name.ParseReference("registry.local:5000/library/node:1.0")
	require.NoError(t, err)

	newImage := func() *fake.FakeImage {
		img := &fake.FakeImage{}
		img.DigestReturns(imageDigest, nil)
		return img
	}

	t.Run("referrers lookup fails", func(t *testing.T) {
		ambassador := ext.NewMockAmbassador()
		ambassador.On("Referrers", mock.Anything, mock.Anything).Return(nil, errors.New("boom"))

		_, ok := findSBOMAccessory(ref, newImage(), ambassador)
		require.False(t, ok)
		ambassador.AssertExpectations(t)
	})

	t.Run("no matching artifact type", func(t *testing.T) {
		idx := &fake.FakeImageIndex{}
		idx.IndexManifestReturns(&v1.IndexManifest{
			Manifests: []v1.Descriptor{
				{Digest: sbomDigestOld, ArtifactType: "application/vnd.dev.cosign.artifact.sig.v1+json"},
			},
		}, nil)

		ambassador := ext.NewMockAmbassador()
		ambassador.On("Referrers", mock.Anything, mock.Anything).Return(idx, nil)

		_, ok := findSBOMAccessory(ref, newImage(), ambassador)
		require.False(t, ok)
		ambassador.AssertExpectations(t)
	})

	t.Run("picks most recently created SBOM accessory", func(t *testing.T) {
		idx := &fake.FakeImageIndex{}
		idx.IndexManifestReturns(&v1.IndexManifest{
			Manifests: []v1.Descriptor{
				{
					Digest:       sbomDigestOld,
					ArtifactType: HarborSBOMArtifactType,
					Annotations:  map[string]string{"created": "2026-01-01T00:00:00Z"},
				},
				{
					Digest:       sbomDigestNew,
					ArtifactType: HarborSBOMArtifactType,
					Annotations:  map[string]string{"created": "2026-06-01T00:00:00Z"},
				},
			},
		}, nil)

		accImage := &fake.FakeImage{}
		ambassador := ext.NewMockAmbassador()
		ambassador.On("Referrers", mock.Anything, mock.Anything).Return(idx, nil)
		ambassador.On("RemoteImage", mock.MatchedBy(func(r name.Reference) bool {
			return strings.HasSuffix(r.String(), sbomDigestNew.String())
		}), mock.Anything).Return(accImage, nil)

		got, ok := findSBOMAccessory(ref, newImage(), ambassador)
		require.True(t, ok)
		require.Same(t, accImage, got)
		ambassador.AssertExpectations(t)
	})

	t.Run("accessory manifest fetch fails", func(t *testing.T) {
		idx := &fake.FakeImageIndex{}
		idx.IndexManifestReturns(&v1.IndexManifest{
			Manifests: []v1.Descriptor{
				{Digest: sbomDigestOld, ArtifactType: HarborSBOMArtifactType},
			},
		}, nil)

		ambassador := ext.NewMockAmbassador()
		ambassador.On("Referrers", mock.Anything, mock.Anything).Return(idx, nil)
		ambassador.On("RemoteImage", mock.Anything, mock.Anything).Return((*fake.FakeImage)(nil), errors.New("boom"))

		_, ok := findSBOMAccessory(ref, newImage(), ambassador)
		require.False(t, ok)
		ambassador.AssertExpectations(t)
	})
}

// pushHarborStyleSBOMAccessory builds and pushes an SBOM accessory the same
// way Harbor's GenAccessoryArt does: an OCI image manifest whose config media
// type is the Harbor SBOM mime type, with a subject pointing at the image and
// no explicit artifactType field.
func pushHarborStyleSBOMAccessory(t *testing.T, repo name.Repository, img v1.Image, sbomContent []byte) {
	t.Helper()

	acc, err := mutate.Append(empty.Image, mutate.Addendum{
		Layer: static.NewLayer(sbomContent, types.MediaType("application/vnd.oci.image.layer.v1.tar")),
	})
	require.NoError(t, err)

	imgDigest, err := img.Digest()
	require.NoError(t, err)
	imgMediaType, err := img.MediaType()
	require.NoError(t, err)
	imgSize, err := img.Size()
	require.NoError(t, err)

	acc = mutate.MediaType(acc, types.OCIManifestSchema1)
	acc = mutate.ConfigMediaType(acc, types.MediaType(HarborSBOMArtifactType))
	acc = mutate.Annotations(acc, map[string]string{
		"created":    "2026-07-01T00:00:00Z",
		"created-by": "Harbor",
	}).(v1.Image)
	acc = mutate.Subject(acc, v1.Descriptor{
		MediaType: imgMediaType,
		Size:      imgSize,
		Digest:    imgDigest,
	}).(v1.Image)

	accDigest, err := acc.Digest()
	require.NoError(t, err)
	require.NoError(t, remote.Write(repo.Digest(accDigest.String()), acc))
}

func TestNewTarget_SBOMAccessory(t *testing.T) {
	ts := httptest.NewServer(registry.New(registry.WithReferrersSupport(true)))
	defer ts.Close()
	host := strings.TrimPrefix(ts.URL, "http://")

	repo, err := name.NewRepository(host + "/library/node")
	require.NoError(t, err)

	img, err := random.Image(1024, 2)
	require.NoError(t, err)
	imgDigest, err := img.Digest()
	require.NoError(t, err)
	require.NoError(t, remote.Write(repo.Digest(imgDigest.String()), img))

	sbomContent := []byte(`{"spdxVersion":"SPDX-2.3","name":"test-sbom"}`)
	pushHarborStyleSBOMAccessory(t, repo, img, sbomContent)

	imageRef := ImageRef{
		Name:   repo.String() + "@" + imgDigest.String(),
		Auth:   NoAuth{},
		NonSSL: true,
	}

	t.Run("uses SBOM accessory when enabled", func(t *testing.T) {
		target, err := newTarget(imageRef, etc.Trivy{CacheDir: t.TempDir()}, ext.DefaultAmbassador, true)
		require.NoError(t, err)
		require.Equal(t, TargetSBOM, target.kind)
		require.True(t, target.fromAccessory)

		got, err := os.ReadFile(target.filePath)
		require.NoError(t, err)
		require.Equal(t, sbomContent, got)
		require.NoError(t, target.Clean())
	})

	t.Run("scans image when disabled", func(t *testing.T) {
		target, err := newTarget(imageRef, etc.Trivy{CacheDir: t.TempDir()}, ext.DefaultAmbassador, false)
		require.NoError(t, err)
		require.Equal(t, TargetImage, target.kind)
		require.False(t, target.fromAccessory)
	})

	t.Run("scans image when no accessory exists", func(t *testing.T) {
		plain, err := random.Image(1024, 1)
		require.NoError(t, err)
		plainDigest, err := plain.Digest()
		require.NoError(t, err)
		require.NoError(t, remote.Write(repo.Digest(plainDigest.String()), plain))

		target, err := newTarget(ImageRef{
			Name:   repo.String() + "@" + plainDigest.String(),
			Auth:   NoAuth{},
			NonSSL: true,
		}, etc.Trivy{CacheDir: t.TempDir()}, ext.DefaultAmbassador, true)
		require.NoError(t, err)
		require.Equal(t, TargetImage, target.kind)
		require.False(t, target.fromAccessory)
	})
}

func TestWrapper_Scan_SBOMAccessoryFallback(t *testing.T) {
	imageDigest := v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("a", 64)}
	sbomDigest := v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("b", 64)}

	fakeImage := &fake.FakeImage{}
	fakeImage.ManifestReturns(&v1.Manifest{}, nil)
	fakeImage.DigestReturns(imageDigest, nil)

	fakeLayer, err := random.Layer(256, types.OCIUncompressedLayer)
	require.NoError(t, err)
	fakeAccessory := &fake.FakeImage{}
	fakeAccessory.ManifestReturns(&v1.Manifest{}, nil)
	fakeAccessory.LayersReturns([]v1.Layer{fakeLayer}, nil)

	idx := &fake.FakeImageIndex{}
	idx.IndexManifestReturns(&v1.IndexManifest{
		Manifests: []v1.Descriptor{
			{Digest: sbomDigest, ArtifactType: HarborSBOMArtifactType},
		},
	}, nil)

	reportsDir, cacheDir := tmpDirs(t)
	config := etc.Trivy{
		CacheDir:         cacheDir,
		ReportsDir:       reportsDir,
		Scanners:         "vuln",
		VulnType:         "os,library",
		Severity:         "CRITICAL",
		Timeout:          30 * time.Second,
		UseSBOMAccessory: true,
	}

	ambassador := ext.NewMockAmbassador()
	ambassador.On("Environ").Return([]string{})
	ambassador.On("LookPath", "trivy").Return("/usr/local/bin/trivy", nil)
	ambassador.On("Referrers", mock.Anything, mock.Anything).Return(idx, nil)
	ambassador.On("RemoteImage", mock.MatchedBy(func(r name.Reference) bool {
		return strings.HasSuffix(r.String(), sbomDigest.String())
	}), mock.Anything).Return(fakeAccessory, nil)
	ambassador.On("RemoteImage", mock.MatchedBy(func(r name.Reference) bool {
		return !strings.HasSuffix(r.String(), sbomDigest.String())
	}), mock.Anything).Return(fakeImage, nil)

	sbomPath := filepath.Join(cacheDir, "sbom_fallback.json")
	sbomFile, err := os.Create(sbomPath)
	require.NoError(t, err)
	ambassador.On("TempFile", cacheDir, mock.Anything).Return(sbomFile, nil)

	reportPath := filepath.Join(reportsDir, "scan_report_fallback.json")
	require.NoError(t, os.WriteFile(reportPath, []byte(expectedReportJSON), 0o644))
	// One report tmp file per scan attempt: the failed SBOM scan and the image retry.
	firstReport, err := os.Open(reportPath)
	require.NoError(t, err)
	secondReport, err := os.Open(reportPath)
	require.NoError(t, err)
	ambassador.On("TempFile", reportsDir, mock.Anything).Return(firstReport, nil).Once()
	ambassador.On("TempFile", reportsDir, mock.Anything).Return(secondReport, nil).Once()

	ambassador.On("RunCmd", mock.MatchedBy(func(cmd *exec.Cmd) bool {
		return len(cmd.Args) > 1 && cmd.Args[1] == "sbom"
	})).Return([]byte("sbom parse error"), errors.New("exit status 1"))
	ambassador.On("RunCmd", mock.MatchedBy(func(cmd *exec.Cmd) bool {
		return len(cmd.Args) > 1 && cmd.Args[1] == "image"
	})).Return([]byte{}, nil)

	got, err := NewWrapper(config, ambassador).Scan(ImageRef{
		Name: "registry.local:5000/library/node@" + imageDigest.String(),
		Auth: NoAuth{},
	}, ScanOption{Format: FormatJSON})
	require.NoError(t, err)
	require.Equal(t, expectedReport, got)

	ambassador.AssertExpectations(t)
}
