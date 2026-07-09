package trivy

import (
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/container-registry/harbor-scanner-trivy/pkg/etc"
	"github.com/container-registry/harbor-scanner-trivy/pkg/ext"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"golang.org/x/xerrors"
)

type Target string

const (
	TargetSBOM  Target = "sbom"
	TargetImage Target = "image"
)

// scannableLayerMediaTypes is the set of layer media types that Trivy can process.
// Layers with media types not in this set are non-archive payloads (signatures,
// attestations, DSSE envelopes) that Trivy will fail to extract as tar archives.
var scannableLayerMediaTypes = map[string]struct{}{
	// Docker/OCI image layers (actual content Trivy scans)
	"application/vnd.docker.image.rootfs.diff.tar.gzip":              {},
	"application/vnd.docker.image.rootfs.diff.tar":                   {},
	"application/vnd.oci.image.layer.v1.tar":                         {},
	"application/vnd.oci.image.layer.v1.tar+gzip":                    {},
	"application/vnd.oci.image.layer.v1.tar+zstd":                    {},
	"application/vnd.oci.image.layer.nondistributable.v1.tar":        {},
	"application/vnd.oci.image.layer.nondistributable.v1.tar+gzip":   {},
	"application/vnd.oci.image.layer.nondistributable.v1.tar+zstd":   {},
	"application/vnd.docker.image.rootfs.foreign.diff.tar.gzip":      {},
	"application/vnd.oci.image.layer.nondistributable.v1.tar+gzip;q": {},
	// Empty/no layers is OK (scratch images)
}

type ScanTarget struct {
	img      v1.Image
	ref      ImageRef
	kind     Target
	filePath string // For SBOM
}

func newTarget(imageRef ImageRef, config etc.Trivy, ambassador ext.Ambassador) (ScanTarget, error) {
	var nameOpts []name.Option
	slog.Debug("newTarget",
		slog.Bool("nonssl", imageRef.NonSSL),
		slog.Bool("insecure", config.Insecure),
	)
	if imageRef.NonSSL {
		nameOpts = append(nameOpts, name.Insecure)
	}
	ref, err := name.ParseReference(imageRef.Name, nameOpts...)
	if err != nil {
		return ScanTarget{}, &ScanError{
			Category: ErrCategoryImageFetch,
			ImageRef: imageRef.Name,
			Detail:   "parsing image reference",
			Cause:    err,
		}
	}

	authOpt := remote.WithAuthFromKeychain(authn.DefaultKeychain)
	switch a := imageRef.Auth.(type) {
	case NoAuth:
	case BasicAuth:
		authOpt = remote.WithAuth(&authn.Basic{
			Username: a.Username,
			Password: a.Password,
		})
	case BearerAuth:
		authOpt = remote.WithAuth(&authn.Bearer{
			Token: a.Token,
		})
	default:
		return ScanTarget{}, xerrors.Errorf("invalid auth type %T", a)
	}

	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: config.Insecure}
	trOpt := remote.WithTransport(tr)

	img, err := ambassador.RemoteImage(ref, authOpt, trOpt)
	if err != nil {
		return ScanTarget{}, &ScanError{
			Category: classifyRemoteError(err),
			ImageRef: imageRef.Name,
			Detail:   "fetching image from registry",
			Cause:    err,
		}
	}

	target := ScanTarget{
		img: img,
		ref: imageRef,
	}

	m, err := target.img.Manifest()
	if err != nil {
		return ScanTarget{}, &ScanError{
			Category: ErrCategoryManifest,
			ImageRef: imageRef.Name,
			Detail:   "getting image manifest",
			Cause:    err,
		}
	}

	slog.Debug("Image manifest retrieved",
		slog.String("image_ref", imageRef.Name),
		slog.String("media_type", string(m.MediaType)),
		slog.String("artifact_type", m.ArtifactType),
		slog.String("config_media_type", string(m.Config.MediaType)),
		slog.Int("layer_count", len(m.Layers)),
	)

	for i, l := range m.Layers {
		slog.Debug("Layer info",
			slog.String("image_ref", imageRef.Name),
			slog.Int("index", i),
			slog.String("media_type", string(l.MediaType)),
			slog.Int64("size", l.Size),
			slog.String("digest", l.Digest.String()),
		)
	}

	switch m.ArtifactType {
	case "application/vnd.goharbor.harbor.sbom.v1":
		target.kind = TargetSBOM
		if target.filePath, err = downloadSBOM(img, config.CacheDir, ambassador); err != nil {
			return ScanTarget{}, xerrors.Errorf("downloading SBOM: %w", err)
		}
	default:
		target.kind = TargetImage

		// Validate that layers are scannable before invoking Trivy.
		// Non-archive payloads (cosign signatures, DSSE envelopes, in-toto attestations)
		// will cause Trivy to fail with "failed to extract the archive: unexpected EOF".
		if err := validateLayers(imageRef.Name, m.Layers); err != nil {
			return ScanTarget{}, err
		}
	}

	return target, nil
}

// validateLayers checks that all layers in the manifest have media types that
// Trivy can scan (tar archives). Returns a ScanError if any layer has a
// non-scannable media type (e.g., cosign signatures, DSSE envelopes).
func validateLayers(imageRef string, layers []v1.Descriptor) error {
	for _, l := range layers {
		mt := string(l.MediaType)
		if _, ok := scannableLayerMediaTypes[mt]; !ok && mt != "" {
			slog.Warn("Image has unscannable layer",
				slog.String("image_ref", imageRef),
				slog.String("media_type", mt),
				slog.String("digest", l.Digest.String()),
				slog.Int64("size", l.Size),
			)
			return &ScanError{
				Category: ErrCategoryUnscannable,
				ImageRef: imageRef,
				Detail: "artifact contains non-scannable layer with media type " + mt +
					" (expected tar archive); this is likely a signature, attestation, or SBOM artifact, not a container image",
			}
		}
	}
	return nil
}

// classifyRemoteError categorizes errors from go-containerregistry's remote.Image.
func classifyRemoteError(err error) ScanErrorCategory {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "unauthorized") || strings.Contains(msg, "401") || strings.Contains(msg, "403"):
		return ErrCategoryAuth
	case strings.Contains(msg, "connection refused") || strings.Contains(msg, "no such host") || strings.Contains(msg, "dial tcp"):
		return ErrCategoryNetwork
	case strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline exceeded"):
		return ErrCategoryTimeout
	default:
		return ErrCategoryImageFetch
	}
}

func (t ScanTarget) Name() (string, error) {
	switch t.kind {
	case TargetSBOM:
		return t.filePath, nil
	case TargetImage:
		return t.ref.Name, nil
	default:
		return "", xerrors.Errorf("invalid target type %s", t.kind)
	}
}

func (t ScanTarget) NonSSL() bool {
	return t.ref.NonSSL
}

func (t ScanTarget) Auth() RegistryAuth {
	switch t.kind {
	case TargetSBOM:
		return NoAuth{}
	case TargetImage:
		return t.ref.Auth
	default:
		return NoAuth{}
	}
}

func (t ScanTarget) configLabels() (map[string]string, error) {
	if t.img == nil {
		return nil, nil
	}
	config, err := t.img.ConfigFile()
	if err != nil {
		return nil, xerrors.Errorf("getting image config: %w", err)
	}
	if config == nil {
		return nil, nil
	}
	return config.Config.Labels, nil
}

func (t ScanTarget) Clean() error {
	switch t.kind {
	case TargetSBOM:
		return os.Remove(t.filePath)
	default:
		return nil
	}
}

// downloadSBOM downloads the SBOM from the registry and returns the path to the downloaded file.
func downloadSBOM(img v1.Image, cacheDir string, ambassador ext.Ambassador) (string, error) {
	layers, err := img.Layers()
	if err != nil {
		return "", xerrors.Errorf("get image layers: %w", err)
	} else if len(layers) != 1 {
		return "", xerrors.Errorf("invalid number of layers: %d", len(layers))
	}

	r, err := layers[0].Uncompressed()
	if err != nil {
		return "", xerrors.Errorf("uncompress layer: %w", err)
	}
	defer r.Close()

	sbomFile, err := ambassador.TempFile(cacheDir, "sbom_*.json")
	if err != nil {
		return "", xerrors.Errorf("create temp file: %w", err)
	}
	defer sbomFile.Close()

	if _, err = io.Copy(sbomFile, r); err != nil {
		return "", xerrors.Errorf("copy layer to temp file: %w", err)
	}

	return sbomFile.Name(), nil
}
