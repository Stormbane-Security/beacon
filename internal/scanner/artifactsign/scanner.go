// Package artifactsign checks whether public packages associated with a domain
// have proper build artifact signatures (npm provenance, PyPI Sigstore, container
// cosign). Surface mode only — all checks are passive queries to public registries.
package artifactsign

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
)

const scannerName = "artifactsign"

// Scanner queries public package registries for signature/provenance status.
type Scanner struct {
	// NPMRegistryURL overrides the npm registry base URL (for testing).
	NPMRegistryURL string
	// PyPIBaseURL overrides the PyPI base URL (for testing).
	PyPIBaseURL string
	// DockerHubURL overrides the Docker Hub registry URL (for testing).
	DockerHubURL string
	// GHCRURL overrides the GitHub Container Registry URL (for testing).
	GHCRURL string
}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) npmRegistryURL() string {
	if s.NPMRegistryURL != "" {
		return s.NPMRegistryURL
	}
	return "https://registry.npmjs.org"
}

func (s *Scanner) pypiBaseURL() string {
	if s.PyPIBaseURL != "" {
		return s.PyPIBaseURL
	}
	return "https://pypi.org"
}

func (s *Scanner) dockerHubURL() string {
	if s.DockerHubURL != "" {
		return s.DockerHubURL
	}
	return "https://registry-1.docker.io"
}

func (s *Scanner) ghcrURL() string {
	if s.GHCRURL != "" {
		return s.GHCRURL
	}
	return "https://ghcr.io"
}

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, _ module.ScanType) ([]finding.Finding, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec
			},
		},
	}

	now := time.Now()

	// Derive candidate package names from the domain.
	// e.g. "acme.com" -> ["acme"], "my-corp.io" -> ["my-corp"]
	candidates := packageCandidates(asset)
	if len(candidates) == 0 {
		return nil, nil
	}

	var findings []finding.Finding

	for _, pkg := range candidates {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}

		// npm: check registry.npmjs.org for package provenance
		if f := s.checkNPM(ctx, client, asset, pkg, now); f != nil {
			findings = append(findings, *f)
		}
		// Also check scoped packages (@org/package)
		if f := s.checkNPM(ctx, client, asset, "@"+pkg+"/"+pkg, now); f != nil {
			findings = append(findings, *f)
		}

		// PyPI: check pypi.org for Sigstore attestation
		if f := s.checkPyPI(ctx, client, asset, pkg, now); f != nil {
			findings = append(findings, *f)
		}

		// Container: check for cosign signature on Docker Hub and ghcr.io
		if f := s.checkContainerHub(ctx, client, asset, pkg, now); f != nil {
			findings = append(findings, *f)
		}
		if f := s.checkContainerGHCR(ctx, client, asset, pkg, now); f != nil {
			findings = append(findings, *f)
		}
	}

	return findings, nil
}

// checkNPM queries the npm registry for a package and checks for provenance attestation.
func (s *Scanner) checkNPM(ctx context.Context, client *http.Client, asset, pkg string, now time.Time) *finding.Finding {
	registryURL := s.npmRegistryURL() + "/" + pkg

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, registryURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon Security Scanner)")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	bodyStr := string(body)

	// Check for npm provenance indicators in the response.
	// Provenance-enabled packages include attestation data or
	// publishConfig.provenance references in their metadata.
	hasProvenance := strings.Contains(bodyStr, `"provenance"`) ||
		strings.Contains(bodyStr, `"attestations"`) ||
		strings.Contains(bodyStr, `"transparency"`)

	if hasProvenance {
		return nil // package is signed, no finding
	}

	return &finding.Finding{
		CheckID:  finding.CheckSupplyChainUnsignedNPM,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityMedium,
		Asset:    asset,
		Title:    fmt.Sprintf("npm package %q lacks provenance attestation", pkg),
		Description: fmt.Sprintf(
			"The npm package %q (associated with %s) exists on the public npm registry but has no "+
				"provenance attestation. Without provenance, consumers cannot verify the package was built "+
				"from its claimed source repository by a trusted CI system. Enable npm provenance via "+
				"`npm publish --provenance` in a supported CI environment (GitHub Actions with OIDC).",
			pkg, asset,
		),
		Evidence: map[string]any{
			"package":      pkg,
			"registry_url": registryURL,
			"ecosystem":    "npm",
		},
		ProofCommand: fmt.Sprintf("curl -s '%s' | jq '.attestations // \"no attestations\"'", registryURL),
		DiscoveredAt: now,
	}
}

// checkPyPI queries PyPI for a package and checks for Sigstore attestation.
func (s *Scanner) checkPyPI(ctx context.Context, client *http.Client, asset, pkg string, now time.Time) *finding.Finding {
	pypiURL := s.pypiBaseURL() + "/pypi/" + pkg + "/json"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pypiURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon Security Scanner)")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	bodyStr := string(body)

	// Check for Sigstore attestation indicators.
	// PyPI packages with Sigstore have .sigstore bundles or attestation references.
	hasSigstore := strings.Contains(bodyStr, ".sigstore") ||
		strings.Contains(bodyStr, `"attestation"`) ||
		strings.Contains(bodyStr, `"provenance_url"`)

	if hasSigstore {
		return nil // signed, no finding
	}

	return &finding.Finding{
		CheckID:  finding.CheckSupplyChainUnsignedPyPI,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityMedium,
		Asset:    asset,
		Title:    fmt.Sprintf("PyPI package %q lacks Sigstore attestation", pkg),
		Description: fmt.Sprintf(
			"The PyPI package %q (associated with %s) exists on PyPI but has no Sigstore attestation. "+
				"Without Sigstore signing, consumers cannot verify the package was published from a trusted "+
				"build environment. Use Trusted Publishers on PyPI with GitHub Actions OIDC to enable "+
				"automatic Sigstore attestation on every release.",
			pkg, asset,
		),
		Evidence: map[string]any{
			"package":      pkg,
			"registry_url": pypiURL,
			"ecosystem":    "pypi",
		},
		ProofCommand: fmt.Sprintf("curl -s '%s' | jq '.urls[0].digests'", pypiURL),
		DiscoveredAt: now,
	}
}

// checkContainerHub checks Docker Hub for cosign signatures on an image.
func (s *Scanner) checkContainerHub(ctx context.Context, client *http.Client, asset, pkg string, now time.Time) *finding.Finding {
	return s.checkContainerRegistry(ctx, client, asset, pkg, "docker.io", s.dockerHubURL(), "library/"+pkg, now)
}

// checkContainerGHCR checks GitHub Container Registry for cosign signatures.
func (s *Scanner) checkContainerGHCR(ctx context.Context, client *http.Client, asset, pkg string, now time.Time) *finding.Finding {
	return s.checkContainerRegistry(ctx, client, asset, pkg, "ghcr.io", s.ghcrURL(), pkg+"/"+pkg, now)
}

// checkContainerRegistry checks an OCI registry for cosign signatures on an image.
func (s *Scanner) checkContainerRegistry(ctx context.Context, client *http.Client, asset, pkg, registryName, registryURL, repoPath string, now time.Time) *finding.Finding {
	// First, check if the image exists by fetching the :latest manifest.
	manifestURL := fmt.Sprintf("%s/v2/%s/manifests/latest", registryURL, repoPath)

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, manifestURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon Security Scanner)")
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	digest := resp.Header.Get("Docker-Content-Digest")
	if digest == "" {
		return nil
	}

	// Check for cosign signature tag: sha256-<hash>.sig
	sigTag := strings.Replace(digest, "sha256:", "sha256-", 1) + ".sig"
	sigURL := fmt.Sprintf("%s/v2/%s/manifests/%s", registryURL, repoPath, sigTag)

	sigReq, err := http.NewRequestWithContext(ctx, http.MethodHead, sigURL, nil)
	if err != nil {
		return nil
	}
	sigReq.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon Security Scanner)")

	sigResp, err := client.Do(sigReq)
	if err != nil {
		return nil
	}
	sigResp.Body.Close()

	// If the signature tag exists, the image is signed.
	if sigResp.StatusCode == http.StatusOK {
		return nil
	}

	return &finding.Finding{
		CheckID:  finding.CheckSupplyChainUnsignedContainer,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityMedium,
		Asset:    asset,
		Title:    fmt.Sprintf("Container image %s/%s lacks cosign signature on %s", registryName, repoPath, registryName),
		Description: fmt.Sprintf(
			"The container image %s/%s (associated with %s) exists on %s but has no cosign signature. "+
				"Without signature verification, deployment systems cannot confirm the image was built by "+
				"a trusted CI pipeline. Sign images with cosign (Sigstore) and enforce signature verification "+
				"in your admission controller (e.g., Kyverno, Gatekeeper, or cosign policy-controller).",
			registryName, repoPath, asset, registryName,
		),
		Evidence: map[string]any{
			"package":       pkg,
			"registry":      registryName,
			"repository":    repoPath,
			"digest":        digest,
			"sig_tag":       sigTag,
			"sig_status":    sigResp.StatusCode,
			"ecosystem":     "container",
		},
		ProofCommand: fmt.Sprintf("# Check for cosign signature:\ncosign verify --key cosign.pub %s/%s@%s 2>&1 || echo 'No signature found'", registryName, repoPath, digest),
		DiscoveredAt: now,
	}
}

// packageCandidates derives likely package names from a domain.
// e.g. "acme.com" -> ["acme"], "my-corp.io" -> ["my-corp"]
func packageCandidates(asset string) []string {
	// Strip to root domain first.
	parts := strings.Split(asset, ".")
	if len(parts) < 2 {
		return nil
	}

	// Use the second-level domain label as the primary candidate.
	base := parts[len(parts)-2]
	if base == "" {
		return nil
	}

	seen := make(map[string]struct{})
	var candidates []string

	add := func(name string) {
		name = strings.ToLower(name)
		if _, ok := seen[name]; !ok && name != "" {
			seen[name] = struct{}{}
			candidates = append(candidates, name)
		}
	}

	add(base)
	// Also try with hyphens removed and underscored variants.
	if strings.Contains(base, "-") {
		add(strings.ReplaceAll(base, "-", ""))
		add(strings.ReplaceAll(base, "-", "_"))
	}

	return candidates
}
