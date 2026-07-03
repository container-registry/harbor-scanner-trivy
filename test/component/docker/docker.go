//go:build component
// +build component

package docker

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/opencontainers/go-digest"
)

type RegistryConfig struct {
	URL      *url.URL
	Username string
	Password string
}

func (c RegistryConfig) GetBasicAuthorization() string {
	return fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", c.Username, c.Password))))
}

// ReplicateImage copies the given imageRef from its source registry to the
// given dest registry. The copy is performed by this process with a registry
// client rather than through the Docker daemon: on Docker Desktop the daemon
// runs in a VM and cannot reach host-mapped localhost ports, while the test
// process can.
func ReplicateImage(imageRef string, dest RegistryConfig) (digest.Digest, error) {
	src, err := name.ParseReference(imageRef)
	if err != nil {
		return "", err
	}

	targetRef := fmt.Sprintf("%s:%s/%s", dest.URL.Hostname(), dest.URL.Port(), imageRef)
	dst, err := name.ParseReference(targetRef)
	if err != nil {
		return "", err
	}

	// The test registry uses a self-signed certificate.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	opts := []remote.Option{
		remote.WithAuth(&authn.Basic{Username: dest.Username, Password: dest.Password}),
		remote.WithTransport(transport),
	}

	desc, err := remote.Get(src)
	if err != nil {
		return "", err
	}

	// Preserve the source artifact as-is (multi-arch index or single image)
	// so the digest the scanner is asked to scan matches the source digest.
	if desc.MediaType.IsIndex() {
		idx, err := desc.ImageIndex()
		if err != nil {
			return "", err
		}
		if err := remote.WriteIndex(dst, idx, opts...); err != nil {
			return "", err
		}
	} else {
		img, err := desc.Image()
		if err != nil {
			return "", err
		}
		if err := remote.Write(dst, img, opts...); err != nil {
			return "", err
		}
	}

	return digest.Digest(desc.Digest.String()), nil
}
