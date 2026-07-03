package trivy

import (
	"errors"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateLayers(t *testing.T) {
	tests := []struct {
		name        string
		layers      []v1.Descriptor
		expectErr   bool
		errCategory ScanErrorCategory
	}{
		{
			name:      "empty layers (scratch image)",
			layers:    []v1.Descriptor{},
			expectErr: false,
		},
		{
			name: "standard OCI tar+gzip layer",
			layers: []v1.Descriptor{
				{MediaType: types.OCILayer, Size: 1024},
			},
			expectErr: false,
		},
		{
			name: "standard Docker layer",
			layers: []v1.Descriptor{
				{MediaType: types.DockerLayer, Size: 1024},
			},
			expectErr: false,
		},
		{
			name: "OCI zstd compressed layer",
			layers: []v1.Descriptor{
				{MediaType: "application/vnd.oci.image.layer.v1.tar+zstd", Size: 1024},
			},
			expectErr: false,
		},
		{
			name: "nondistributable layer (gzip)",
			layers: []v1.Descriptor{
				{MediaType: "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip", Size: 1024},
			},
			expectErr: false,
		},
		{
			name: "nondistributable layer (zstd)",
			layers: []v1.Descriptor{
				{MediaType: "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd", Size: 1024},
			},
			expectErr: false,
		},
		{
			name: "cosign signature layer",
			layers: []v1.Descriptor{
				{MediaType: "application/vnd.dev.cosign.simplesigning.v1+json", Size: 245},
			},
			expectErr:   true,
			errCategory: ErrCategoryUnscannable,
		},
		{
			name: "DSSE envelope layer (attestation)",
			layers: []v1.Descriptor{
				{MediaType: "application/vnd.dsse.envelope.v1+json", Size: 87488},
			},
			expectErr:   true,
			errCategory: ErrCategoryUnscannable,
		},
		{
			name: "in-toto attestation layer",
			layers: []v1.Descriptor{
				{MediaType: "application/vnd.in-toto+json", Size: 500},
			},
			expectErr:   true,
			errCategory: ErrCategoryUnscannable,
		},
		{
			name: "mixed valid and invalid layers",
			layers: []v1.Descriptor{
				{MediaType: types.OCILayer, Size: 1024},
				{MediaType: "application/vnd.dev.cosign.simplesigning.v1+json", Size: 245},
			},
			expectErr:   true,
			errCategory: ErrCategoryUnscannable,
		},
		{
			name: "multiple DSSE envelope layers",
			layers: []v1.Descriptor{
				{MediaType: "application/vnd.dsse.envelope.v1+json", Size: 87488},
				{MediaType: "application/vnd.dsse.envelope.v1+json", Size: 1516},
				{MediaType: "application/vnd.dsse.envelope.v1+json", Size: 2368},
			},
			expectErr:   true,
			errCategory: ErrCategoryUnscannable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateLayers("test-image:latest", tt.layers)
			if tt.expectErr {
				require.Error(t, err)
				var scanErr *ScanError
				require.True(t, errors.As(err, &scanErr))
				assert.Equal(t, tt.errCategory, scanErr.Category)
				assert.Contains(t, scanErr.ImageRef, "test-image")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestClassifyRemoteError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected ScanErrorCategory
	}{
		{
			name:     "unauthorized error",
			err:      errors.New("GET https://registry/v2/: UNAUTHORIZED"),
			expected: ErrCategoryAuth,
		},
		{
			name:     "403 forbidden",
			err:      errors.New("GET https://registry/v2/: 403 Forbidden"),
			expected: ErrCategoryAuth,
		},
		{
			name:     "connection refused",
			err:      errors.New("dial tcp 10.0.0.1:443: connection refused"),
			expected: ErrCategoryNetwork,
		},
		{
			name:     "no such host",
			err:      errors.New("dial tcp: lookup registry.example.com: no such host"),
			expected: ErrCategoryNetwork,
		},
		{
			name:     "timeout",
			err:      errors.New("context deadline exceeded"),
			expected: ErrCategoryTimeout,
		},
		{
			name:     "generic error",
			err:      errors.New("some unknown error"),
			expected: ErrCategoryImageFetch,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyRemoteError(tt.err)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestClassifyTrivyError(t *testing.T) {
	tests := []struct {
		name     string
		output   string
		expected ScanErrorCategory
	}{
		{
			name:     "archive extraction failure",
			output:   "FATAL\tFatal error\trun error: failed to analyze layer: walk error: failed to extract the archive: unexpected EOF",
			expected: ErrCategoryUnscannable,
		},
		{
			name:     "unauthorized",
			output:   "FATAL\tFatal error\timage scan error: UNAUTHORIZED: authentication required",
			expected: ErrCategoryAuth,
		},
		{
			name:     "connection refused",
			output:   "FATAL\tFatal error\timage scan error: dial tcp 10.0.0.1:443: connection refused",
			expected: ErrCategoryNetwork,
		},
		{
			name:     "timeout",
			output:   "FATAL\tFatal error\timage scan error: context deadline exceeded",
			expected: ErrCategoryTimeout,
		},
		{
			name:     "generic trivy error",
			output:   "FATAL\tFatal error\tsome other error",
			expected: ErrCategoryTrivyExec,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyTrivyError(tt.output)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestScanError(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := &ScanError{
			Category: ErrCategoryUnscannable,
			ImageRef: "registry/repo@sha256:abc",
			Detail:   "non-scannable layer",
			Cause:    cause,
		}
		assert.Contains(t, err.Error(), "[unscannable_layer]")
		assert.Contains(t, err.Error(), "non-scannable layer")
		assert.Contains(t, err.Error(), "underlying error")
		assert.Equal(t, cause, errors.Unwrap(err))
	})

	t.Run("without cause", func(t *testing.T) {
		err := &ScanError{
			Category: ErrCategoryUnscannable,
			ImageRef: "registry/repo@sha256:abc",
			Detail:   "non-scannable layer with media type application/vnd.dev.cosign.simplesigning.v1+json",
		}
		assert.Contains(t, err.Error(), "[unscannable_layer]")
		assert.Contains(t, err.Error(), "cosign")
		assert.Nil(t, errors.Unwrap(err))
	})
}
