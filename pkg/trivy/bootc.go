package trivy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/container-registry/harbor-scanner-trivy/pkg/ext"
	"golang.org/x/xerrors"
)

const (
	bootcLabel       = "containers.bootc"
	rechunkInfoLabel = "dev.hhd.rechunk.info"
)

var fedoraVersionRE = regexp.MustCompile(`(?:^|[.-])fc([0-9]+)(?:[.-]|$)`)

type bootcRechunkInfo struct {
	Version  int               `json:"version"`
	Uniq     string            `json:"uniq"`
	Packages map[string]string `json:"packages"`
	Revision string            `json:"revision"`
}

type bootcPackage struct {
	Name    string
	Version string
}

func bootcSBOMReport(target ScanTarget, format Format) (Report, bool, error) {
	if format != FormatSPDX && format != FormatCycloneDX {
		return Report{}, false, nil
	}

	doc, ok, err := bootcSBOMDocument(target, format)
	if err != nil || !ok {
		return Report{}, ok, err
	}
	return Report{SBOM: doc}, true, nil
}

func bootcVulnerabilityTarget(target ScanTarget, cacheDir string, ambassador ext.Ambassador) (ScanTarget, bool, error) {
	doc, ok, err := bootcSBOMDocument(target, FormatSPDX)
	if err != nil || !ok {
		return ScanTarget{}, ok, err
	}

	sbomFile, err := ambassador.TempFile(cacheDir, "bootc-sbom-*.spdx.json")
	if err != nil {
		return ScanTarget{}, false, xerrors.Errorf("create bootc sbom temp file: %w", err)
	}
	path := sbomFile.Name()
	if err := json.NewEncoder(sbomFile).Encode(doc); err != nil {
		_ = sbomFile.Close()
		_ = os.Remove(path)
		return ScanTarget{}, false, xerrors.Errorf("write bootc sbom temp file: %w", err)
	}
	if err := sbomFile.Close(); err != nil {
		_ = os.Remove(path)
		return ScanTarget{}, false, xerrors.Errorf("close bootc sbom temp file: %w", err)
	}

	return ScanTarget{kind: TargetSBOM, filePath: path}, true, nil
}

func bootcSBOMDocument(target ScanTarget, format Format) (any, bool, error) {
	if format != FormatSPDX && format != FormatCycloneDX {
		return nil, false, nil
	}

	labels, err := target.configLabels()
	if err != nil {
		return nil, false, err
	}
	if labels[bootcLabel] != "1" || labels[rechunkInfoLabel] == "" {
		return nil, false, nil
	}

	info, err := parseBootcRechunkInfo(labels[rechunkInfoLabel])
	if err != nil {
		return nil, false, err
	}

	packages := bootcPackages(info.Packages)
	if len(packages) == 0 {
		return nil, false, nil
	}

	name, err := target.Name()
	if err != nil {
		return nil, false, err
	}
	distro := detectFedoraDistro(labels, packages)
	created := time.Now().UTC().Format(time.RFC3339)

	switch format {
	case FormatSPDX:
		return newBootcSPDXDocument(name, info, packages, distro, created), true, nil
	case FormatCycloneDX:
		return newBootcCycloneDXDocument(name, info, packages, distro), true, nil
	default:
		return nil, false, nil
	}
}

func parseBootcRechunkInfo(raw string) (bootcRechunkInfo, error) {
	var info bootcRechunkInfo
	if err := json.Unmarshal([]byte(raw), &info); err != nil {
		return bootcRechunkInfo{}, xerrors.Errorf("parsing bootc rechunk info: %w", err)
	}
	return info, nil
}

func bootcPackages(source map[string]string) []bootcPackage {
	packages := make([]bootcPackage, 0, len(source))
	for name, version := range source {
		name = strings.TrimSpace(name)
		version = strings.TrimSpace(version)
		if name == "" || version == "" {
			continue
		}
		packages = append(packages, bootcPackage{Name: name, Version: version})
	}
	sort.Slice(packages, func(i, j int) bool {
		return packages[i].Name < packages[j].Name
	})
	return packages
}

func detectFedoraDistro(labels map[string]string, packages []bootcPackage) string {
	for _, value := range []string{
		labels["ostree.linux"],
		labels["org.opencontainers.image.version"],
	} {
		if distro := fedoraDistroFromString(value); distro != "" {
			return distro
		}
	}
	for _, pkg := range packages {
		if distro := fedoraDistroFromString(pkg.Version); distro != "" {
			return distro
		}
	}
	return ""
}

func fedoraDistroFromString(value string) string {
	match := fedoraVersionRE.FindStringSubmatch(value)
	if len(match) != 2 {
		return ""
	}
	return "fedora-" + match[1]
}

func packagePURL(pkg bootcPackage, distro string) string {
	purl := fmt.Sprintf("pkg:rpm/fedora/%s@%s", url.PathEscape(pkg.Name), url.PathEscape(pkg.Version))
	if distro != "" {
		purl += "?arch=x86_64&distro=" + url.QueryEscape(distro)
	}
	return purl
}

func spdxID(name string) string {
	replacer := strings.NewReplacer(":", "-", "/", "-", "_", "-", "+", "-", ".", "-")
	id := replacer.Replace(name)
	id = regexp.MustCompile(`[^A-Za-z0-9.-]`).ReplaceAllString(id, "-")
	id = strings.Trim(id, "-.")
	if id == "" {
		sum := sha256.Sum256([]byte(name))
		id = hex.EncodeToString(sum[:8])
	}
	return "SPDXRef-Package-" + id
}

type spdxDocument struct {
	SPDXVersion       string        `json:"spdxVersion"`
	DataLicense       string        `json:"dataLicense"`
	SPDXID            string        `json:"SPDXID"`
	Name              string        `json:"name"`
	DocumentNamespace string        `json:"documentNamespace"`
	CreationInfo      spdxCreation  `json:"creationInfo"`
	Packages          []spdxPackage `json:"packages"`
}

type spdxCreation struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	SPDXID           string            `json:"SPDXID"`
	Name             string            `json:"name"`
	VersionInfo      string            `json:"versionInfo"`
	DownloadLocation string            `json:"downloadLocation"`
	FilesAnalyzed    bool              `json:"filesAnalyzed"`
	Supplier         string            `json:"supplier"`
	ExternalRefs     []spdxExternalRef `json:"externalRefs,omitempty"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

func newBootcSPDXDocument(name string, info bootcRechunkInfo, packages []bootcPackage, distro, created string) spdxDocument {
	docPackages := make([]spdxPackage, 0, len(packages))
	seenIDs := map[string]int{}
	for _, pkg := range packages {
		id := spdxID(pkg.Name)
		if seenIDs[id] > 0 {
			id = fmt.Sprintf("%s-%d", id, seenIDs[id]+1)
		}
		seenIDs[id]++
		docPackages = append(docPackages, spdxPackage{
			SPDXID:           id,
			Name:             pkg.Name,
			VersionInfo:      pkg.Version,
			DownloadLocation: "NOASSERTION",
			FilesAnalyzed:    false,
			Supplier:         "NOASSERTION",
			ExternalRefs: []spdxExternalRef{
				{
					ReferenceCategory: "PACKAGE-MANAGER",
					ReferenceType:     "purl",
					ReferenceLocator:  packagePURL(pkg, distro),
				},
			},
		})
	}

	namespaceSource := name
	if info.Revision != "" {
		namespaceSource += "@" + info.Revision
	}
	sum := sha256.Sum256([]byte(namespaceSource))

	return spdxDocument{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              name,
		DocumentNamespace: fmt.Sprintf("https://goharbor.io/bootc/%s", hex.EncodeToString(sum[:16])),
		CreationInfo: spdxCreation{
			Created:  created,
			Creators: []string{"Tool: harbor-scanner-trivy"},
		},
		Packages: docPackages,
	}
}

type cyclonedxDocument struct {
	BOMFormat   string               `json:"bomFormat"`
	SpecVersion string               `json:"specVersion"`
	Version     int                  `json:"version"`
	Metadata    cyclonedxMetadata    `json:"metadata"`
	Components  []cyclonedxComponent `json:"components"`
}

type cyclonedxMetadata struct {
	Component cyclonedxComponent `json:"component"`
}

type cyclonedxComponent struct {
	Type       string `json:"type"`
	Name       string `json:"name"`
	Version    string `json:"version,omitempty"`
	PackageURL string `json:"purl,omitempty"`
}

func newBootcCycloneDXDocument(name string, info bootcRechunkInfo, packages []bootcPackage, distro string) cyclonedxDocument {
	components := make([]cyclonedxComponent, 0, len(packages))
	for _, pkg := range packages {
		components = append(components, cyclonedxComponent{
			Type:       "library",
			Name:       pkg.Name,
			Version:    pkg.Version,
			PackageURL: packagePURL(pkg, distro),
		})
	}

	return cyclonedxDocument{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.5",
		Version:     1,
		Metadata: cyclonedxMetadata{
			Component: cyclonedxComponent{
				Type:    "container",
				Name:    name,
				Version: info.Uniq,
			},
		},
		Components: components,
	}
}
