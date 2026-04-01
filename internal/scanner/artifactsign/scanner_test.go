package artifactsign_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scanner/artifactsign"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func hasCheckID(findings []finding.Finding, id finding.CheckID) bool {
	for _, f := range findings {
		if f.CheckID == id {
			return true
		}
	}
	return false
}

func countCheckID(findings []finding.Finding, id finding.CheckID) int {
	n := 0
	for _, f := range findings {
		if f.CheckID == id {
			n++
		}
	}
	return n
}

func findByCheckID(findings []finding.Finding, id finding.CheckID) *finding.Finding {
	for i := range findings {
		if findings[i].CheckID == id {
			return &findings[i]
		}
	}
	return nil
}

// newScanner creates a Scanner wired to the given test servers.
// Pass nil for any registry you want to remain unreachable (no server).
func newScanner(npm, pypi, dockerHub, ghcr *httptest.Server) *artifactsign.Scanner {
	s := artifactsign.New()
	if npm != nil {
		s.NPMRegistryURL = npm.URL
	} else {
		// Point at a port that will refuse connections.
		s.NPMRegistryURL = "http://127.0.0.1:1"
	}
	if pypi != nil {
		s.PyPIBaseURL = pypi.URL
	} else {
		s.PyPIBaseURL = "http://127.0.0.1:1"
	}
	if dockerHub != nil {
		s.DockerHubURL = dockerHub.URL
	} else {
		s.DockerHubURL = "http://127.0.0.1:1"
	}
	if ghcr != nil {
		s.GHCRURL = ghcr.URL
	} else {
		s.GHCRURL = "http://127.0.0.1:1"
	}
	return s
}

// ---------------------------------------------------------------------------
// Scanner metadata
// ---------------------------------------------------------------------------

func TestName(t *testing.T) {
	s := artifactsign.New()
	if s.Name() != "artifactsign" {
		t.Errorf("expected scanner name %q, got %q", "artifactsign", s.Name())
	}
}

// ---------------------------------------------------------------------------
// npm: unsigned package emits finding
// ---------------------------------------------------------------------------

func TestNPM_UnsignedPackage_EmitsFinding(t *testing.T) {
	npm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return a package with no provenance indicators.
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"name":"acme","version":"1.0.0","description":"a package"}`)
	}))
	defer npm.Close()

	s := newScanner(npm, nil, nil, nil)
	findings, err := s.Run(context.Background(), "acme.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckSupplyChainUnsignedNPM) {
		t.Error("expected CheckSupplyChainUnsignedNPM when npm package has no provenance")
	}

	f := findByCheckID(findings, finding.CheckSupplyChainUnsignedNPM)
	if f == nil {
		t.Fatal("finding not found")
	}
	if f.Severity != finding.SeverityMedium {
		t.Errorf("expected SeverityMedium, got %s", f.Severity)
	}
	if f.Module != "surface" {
		t.Errorf("expected module 'surface', got %q", f.Module)
	}
	if f.Scanner != "artifactsign" {
		t.Errorf("expected scanner 'artifactsign', got %q", f.Scanner)
	}
	if f.Asset != "acme.com" {
		t.Errorf("expected asset 'acme.com', got %q", f.Asset)
	}
	if f.ProofCommand == "" {
		t.Error("ProofCommand must not be empty")
	}
}

// ---------------------------------------------------------------------------
// npm: package with "provenance" field -> no finding
// ---------------------------------------------------------------------------

func TestNPM_PackageWithProvenance_NoFinding(t *testing.T) {
	npm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"name":"acme","version":"2.0.0","publishConfig":{"provenance":true}}`)
	}))
	defer npm.Close()

	s := newScanner(npm, nil, nil, nil)
	findings, err := s.Run(context.Background(), "acme.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasCheckID(findings, finding.CheckSupplyChainUnsignedNPM) {
		t.Error("expected no CheckSupplyChainUnsignedNPM when provenance is present")
	}
}

// ---------------------------------------------------------------------------
// npm: package with "attestations" field -> no finding
// ---------------------------------------------------------------------------

func TestNPM_PackageWithAttestations_NoFinding(t *testing.T) {
	npm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"name":"acme","attestations":{"url":"https://example.com"}}`)
	}))
	defer npm.Close()

	s := newScanner(npm, nil, nil, nil)
	findings, err := s.Run(context.Background(), "acme.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasCheckID(findings, finding.CheckSupplyChainUnsignedNPM) {
		t.Error("expected no CheckSupplyChainUnsignedNPM when attestations are present")
	}
}

// ---------------------------------------------------------------------------
// npm: package with "transparency" field -> no finding
// ---------------------------------------------------------------------------

func TestNPM_PackageWithTransparency_NoFinding(t *testing.T) {
	npm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"name":"acme","transparency":"log-entry-url"}`)
	}))
	defer npm.Close()

	s := newScanner(npm, nil, nil, nil)
	findings, err := s.Run(context.Background(), "acme.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasCheckID(findings, finding.CheckSupplyChainUnsignedNPM) {
		t.Error("expected no CheckSupplyChainUnsignedNPM when transparency is present")
	}
}

// ---------------------------------------------------------------------------
// npm: 404 response -> no finding (package does not exist)
// ---------------------------------------------------------------------------

func TestNPM_PackageNotFound_NoFinding(t *testing.T) {
	npm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer npm.Close()

	s := newScanner(npm, nil, nil, nil)
	findings, err := s.Run(context.Background(), "acme.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasCheckID(findings, finding.CheckSupplyChainUnsignedNPM) {
		t.Error("expected no finding when npm package does not exist (404)")
	}
}

// ---------------------------------------------------------------------------
// npm: scoped package also checked (@acme/acme)
// ---------------------------------------------------------------------------

func TestNPM_ScopedPackageAlsoChecked(t *testing.T) {
	var requestedPaths []string
	npm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPaths = append(requestedPaths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"name":"test"}`)
	}))
	defer npm.Close()

	s := newScanner(npm, nil, nil, nil)
	_, err := s.Run(context.Background(), "acme.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundUnscoped := false
	foundScoped := false
	for _, p := range requestedPaths {
		if p == "/acme" {
			foundUnscoped = true
		}
		if p == "/@acme/acme" {
			foundScoped = true
		}
	}
	if !foundUnscoped {
		t.Error("expected scanner to check unscoped package /acme")
	}
	if !foundScoped {
		t.Error("expected scanner to also check scoped package /@acme/acme")
	}
}

// ---------------------------------------------------------------------------
// npm: evidence fields populated correctly
// ---------------------------------------------------------------------------

func TestNPM_EvidenceFields(t *testing.T) {
	npm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"name":"acme","version":"1.0.0"}`)
	}))
	defer npm.Close()

	s := newScanner(npm, nil, nil, nil)
	findings, err := s.Run(context.Background(), "acme.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	f := findByCheckID(findings, finding.CheckSupplyChainUnsignedNPM)
	if f == nil {
		t.Fatal("expected npm unsigned finding")
	}

	eco, ok := f.Evidence["ecosystem"]
	if !ok || eco != "npm" {
		t.Errorf("expected ecosystem 'npm', got %v", eco)
	}
	pkg, ok := f.Evidence["package"]
	if !ok {
		t.Error("expected 'package' key in evidence")
	}
	if pkg != "acme" {
		t.Errorf("expected package 'acme', got %v", pkg)
	}
	regURL, ok := f.Evidence["registry_url"]
	if !ok || regURL == "" {
		t.Error("expected 'registry_url' key in evidence")
	}
}

// ---------------------------------------------------------------------------
// PyPI: unsigned package emits finding
// ---------------------------------------------------------------------------

func TestPyPI_UnsignedPackage_EmitsFinding(t *testing.T) {
	pypi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"info":{"name":"acme","version":"1.0.0"},"urls":[]}`)
	}))
	defer pypi.Close()

	s := newScanner(nil, pypi, nil, nil)
	findings, err := s.Run(context.Background(), "acme.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckSupplyChainUnsignedPyPI) {
		t.Error("expected CheckSupplyChainUnsignedPyPI when PyPI package has no Sigstore")
	}

	f := findByCheckID(findings, finding.CheckSupplyChainUnsignedPyPI)
	if f == nil {
		t.Fatal("finding not found")
	}
	if f.Severity != finding.SeverityMedium {
		t.Errorf("expected SeverityMedium, got %s", f.Severity)
	}
	if f.Module != "surface" {
		t.Errorf("expected module 'surface', got %q", f.Module)
	}
	if f.ProofCommand == "" {
		t.Error("ProofCommand must not be empty")
	}

	eco, _ := f.Evidence["ecosystem"]
	if eco != "pypi" {
		t.Errorf("expected ecosystem 'pypi', got %v", eco)
	}
}

// ---------------------------------------------------------------------------
// PyPI: package with .sigstore bundle -> no finding
// ---------------------------------------------------------------------------

func TestPyPI_PackageWithSigstore_NoFinding(t *testing.T) {
	pypi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"info":{"name":"acme"},"urls":[{"filename":"acme-1.0.0.tar.gz.sigstore"}]}`)
	}))
	defer pypi.Close()

	s := newScanner(nil, pypi, nil, nil)
	findings, err := s.Run(context.Background(), "acme.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasCheckID(findings, finding.CheckSupplyChainUnsignedPyPI) {
		t.Error("expected no CheckSupplyChainUnsignedPyPI when .sigstore bundle is present")
	}
}

// ---------------------------------------------------------------------------
// PyPI: package with "attestation" field -> no finding
// ---------------------------------------------------------------------------

func TestPyPI_PackageWithAttestation_NoFinding(t *testing.T) {
	pypi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"info":{"name":"acme"},"attestation":{"digest":"sha256:abc"}}`)
	}))
	defer pypi.Close()

	s := newScanner(nil, pypi, nil, nil)
	findings, err := s.Run(context.Background(), "acme.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasCheckID(findings, finding.CheckSupplyChainUnsignedPyPI) {
		t.Error("expected no CheckSupplyChainUnsignedPyPI when attestation is present")
	}
}

// ---------------------------------------------------------------------------
// PyPI: package with "provenance_url" field -> no finding
// ---------------------------------------------------------------------------

func TestPyPI_PackageWithProvenanceURL_NoFinding(t *testing.T) {
	pypi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"info":{"name":"acme"},"provenance_url":"https://rekor.sigstore.dev/api/v1/log/entries/abc"}`)
	}))
	defer pypi.Close()

	s := newScanner(nil, pypi, nil, nil)
	findings, err := s.Run(context.Background(), "acme.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasCheckID(findings, finding.CheckSupplyChainUnsignedPyPI) {
		t.Error("expected no CheckSupplyChainUnsignedPyPI when provenance_url is present")
	}
}

// ---------------------------------------------------------------------------
// PyPI: package not found (404) -> no finding
// ---------------------------------------------------------------------------

func TestPyPI_PackageNotFound_NoFinding(t *testing.T) {
	pypi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer pypi.Close()

	s := newScanner(nil, pypi, nil, nil)
	findings, err := s.Run(context.Background(), "acme.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasCheckID(findings, finding.CheckSupplyChainUnsignedPyPI) {
		t.Error("expected no finding when PyPI package does not exist (404)")
	}
}

// ---------------------------------------------------------------------------
// PyPI: request path includes /pypi/<pkg>/json
// ---------------------------------------------------------------------------

func TestPyPI_CorrectRequestPath(t *testing.T) {
	var requestedPath string
	pypi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPath = r.URL.Path
		http.NotFound(w, r)
	}))
	defer pypi.Close()

	s := newScanner(nil, pypi, nil, nil)
	_, _ = s.Run(context.Background(), "acme.com", module.ScanSurface)

	if requestedPath != "/pypi/acme/json" {
		t.Errorf("expected request path /pypi/acme/json, got %q", requestedPath)
	}
}

// ---------------------------------------------------------------------------
// Container (Docker Hub): unsigned image emits finding
// ---------------------------------------------------------------------------

func TestContainerHub_UnsignedImage_EmitsFinding(t *testing.T) {
	dockerHub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Manifest request for image existence check.
		if strings.Contains(r.URL.Path, "/manifests/latest") {
			w.Header().Set("Docker-Content-Digest", "sha256:abc123def456")
			w.WriteHeader(http.StatusOK)
			return
		}
		// Signature tag lookup — return 404 (no cosign signature).
		if strings.Contains(r.URL.Path, ".sig") {
			http.NotFound(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	defer dockerHub.Close()

	s := newScanner(nil, nil, dockerHub, nil)
	findings, err := s.Run(context.Background(), "acme.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckSupplyChainUnsignedContainer) {
		t.Error("expected CheckSupplyChainUnsignedContainer when Docker Hub image lacks cosign signature")
	}

	f := findByCheckID(findings, finding.CheckSupplyChainUnsignedContainer)
	if f == nil {
		t.Fatal("finding not found")
	}
	if f.Severity != finding.SeverityMedium {
		t.Errorf("expected SeverityMedium, got %s", f.Severity)
	}
	if f.ProofCommand == "" {
		t.Error("ProofCommand must not be empty")
	}

	eco, _ := f.Evidence["ecosystem"]
	if eco != "container" {
		t.Errorf("expected ecosystem 'container', got %v", eco)
	}
	digest, _ := f.Evidence["digest"]
	if digest != "sha256:abc123def456" {
		t.Errorf("expected digest 'sha256:abc123def456', got %v", digest)
	}
	sigTag, _ := f.Evidence["sig_tag"]
	if sigTag != "sha256-abc123def456.sig" {
		t.Errorf("expected sig_tag 'sha256-abc123def456.sig', got %v", sigTag)
	}
	reg, _ := f.Evidence["registry"]
	if reg != "docker.io" {
		t.Errorf("expected registry 'docker.io', got %v", reg)
	}
}

// ---------------------------------------------------------------------------
// Container (Docker Hub): signed image (cosign sig exists) -> no finding
// ---------------------------------------------------------------------------

func TestContainerHub_SignedImage_NoFinding(t *testing.T) {
	dockerHub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/manifests/latest") {
			w.Header().Set("Docker-Content-Digest", "sha256:abc123def456")
			w.WriteHeader(http.StatusOK)
			return
		}
		// Cosign signature tag exists — return 200.
		if strings.Contains(r.URL.Path, "sha256-abc123def456.sig") {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	defer dockerHub.Close()

	s := newScanner(nil, nil, dockerHub, nil)
	findings, err := s.Run(context.Background(), "acme.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Only Docker Hub findings should be checked; we disabled other registries.
	for _, f := range findings {
		if f.CheckID == finding.CheckSupplyChainUnsignedContainer {
			if reg, ok := f.Evidence["registry"]; ok && reg == "docker.io" {
				t.Error("expected no CheckSupplyChainUnsignedContainer for Docker Hub when cosign signature exists")
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Container (Docker Hub): image not found (404 on manifest) -> no finding
// ---------------------------------------------------------------------------

func TestContainerHub_ImageNotFound_NoFinding(t *testing.T) {
	dockerHub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer dockerHub.Close()

	s := newScanner(nil, nil, dockerHub, nil)
	findings, err := s.Run(context.Background(), "acme.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if f.CheckID == finding.CheckSupplyChainUnsignedContainer {
			if reg, ok := f.Evidence["registry"]; ok && reg == "docker.io" {
				t.Error("expected no finding when image does not exist on Docker Hub (404)")
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Container (Docker Hub): missing Docker-Content-Digest header -> no finding
// ---------------------------------------------------------------------------

func TestContainerHub_NoDigestHeader_NoFinding(t *testing.T) {
	dockerHub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Image exists but no digest header.
		w.WriteHeader(http.StatusOK)
	}))
	defer dockerHub.Close()

	s := newScanner(nil, nil, dockerHub, nil)
	findings, err := s.Run(context.Background(), "acme.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if f.CheckID == finding.CheckSupplyChainUnsignedContainer {
			if reg, ok := f.Evidence["registry"]; ok && reg == "docker.io" {
				t.Error("expected no finding when Docker-Content-Digest header is missing")
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Container (GHCR): unsigned image emits finding
// ---------------------------------------------------------------------------

func TestContainerGHCR_UnsignedImage_EmitsFinding(t *testing.T) {
	ghcr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/manifests/latest") {
			w.Header().Set("Docker-Content-Digest", "sha256:deadbeef")
			w.WriteHeader(http.StatusOK)
			return
		}
		if strings.Contains(r.URL.Path, ".sig") {
			http.NotFound(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	defer ghcr.Close()

	s := newScanner(nil, nil, nil, ghcr)
	findings, err := s.Run(context.Background(), "acme.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckSupplyChainUnsignedContainer {
			if reg, ok := f.Evidence["registry"]; ok && reg == "ghcr.io" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected CheckSupplyChainUnsignedContainer for ghcr.io when image lacks cosign signature")
	}
}

// ---------------------------------------------------------------------------
// Container (GHCR): signed image -> no finding
// ---------------------------------------------------------------------------

func TestContainerGHCR_SignedImage_NoFinding(t *testing.T) {
	ghcr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/manifests/latest") {
			w.Header().Set("Docker-Content-Digest", "sha256:deadbeef")
			w.WriteHeader(http.StatusOK)
			return
		}
		if strings.Contains(r.URL.Path, "sha256-deadbeef.sig") {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	defer ghcr.Close()

	s := newScanner(nil, nil, nil, ghcr)
	findings, err := s.Run(context.Background(), "acme.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if f.CheckID == finding.CheckSupplyChainUnsignedContainer {
			if reg, ok := f.Evidence["registry"]; ok && reg == "ghcr.io" {
				t.Error("expected no finding for ghcr.io when cosign signature exists")
			}
		}
	}
}

// ---------------------------------------------------------------------------
// All registries: unsigned everywhere -> findings from all ecosystems
// ---------------------------------------------------------------------------

func TestAllRegistries_UnsignedEverywhere_EmitsAllFindings(t *testing.T) {
	npm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"name":"acme","version":"1.0.0"}`)
	}))
	defer npm.Close()

	pypi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"info":{"name":"acme"}}`)
	}))
	defer pypi.Close()

	containerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/manifests/latest") {
			w.Header().Set("Docker-Content-Digest", "sha256:aaa")
			w.WriteHeader(http.StatusOK)
			return
		}
		if strings.Contains(r.URL.Path, ".sig") {
			http.NotFound(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	defer containerSrv.Close()

	s := newScanner(npm, pypi, containerSrv, containerSrv)
	findings, err := s.Run(context.Background(), "acme.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckSupplyChainUnsignedNPM) {
		t.Error("expected npm unsigned finding")
	}
	if !hasCheckID(findings, finding.CheckSupplyChainUnsignedPyPI) {
		t.Error("expected PyPI unsigned finding")
	}
	if !hasCheckID(findings, finding.CheckSupplyChainUnsignedContainer) {
		t.Error("expected container unsigned finding")
	}
}

// ---------------------------------------------------------------------------
// All registries: signed everywhere -> no findings
// ---------------------------------------------------------------------------

func TestAllRegistries_SignedEverywhere_NoFindings(t *testing.T) {
	npm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"name":"acme","attestations":{"url":"https://tlog.sigstore.dev"}}`)
	}))
	defer npm.Close()

	pypi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"info":{"name":"acme"},"urls":[{"filename":"acme-1.0.tar.gz.sigstore"}]}`)
	}))
	defer pypi.Close()

	containerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/manifests/latest") {
			w.Header().Set("Docker-Content-Digest", "sha256:bbb")
			w.WriteHeader(http.StatusOK)
			return
		}
		if strings.Contains(r.URL.Path, ".sig") {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	defer containerSrv.Close()

	s := newScanner(npm, pypi, containerSrv, containerSrv)
	findings, err := s.Run(context.Background(), "acme.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings when all packages are signed, got %d", len(findings))
		for _, f := range findings {
			t.Logf("  unexpected finding: %s (%s)", f.CheckID, f.Title)
		}
	}
}

// ---------------------------------------------------------------------------
// Invalid asset (single label, no dot) -> no findings, no error
// ---------------------------------------------------------------------------

func TestInvalidAsset_NoDot_NoFindings(t *testing.T) {
	s := artifactsign.New()
	// Override URLs to prevent real network calls.
	s.NPMRegistryURL = "http://127.0.0.1:1"
	s.PyPIBaseURL = "http://127.0.0.1:1"
	s.DockerHubURL = "http://127.0.0.1:1"
	s.GHCRURL = "http://127.0.0.1:1"

	findings, err := s.Run(context.Background(), "localhost", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for single-label domain, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Hyphenated domain generates extra candidate variants
// ---------------------------------------------------------------------------

func TestHyphenatedDomain_ExtraCandidates(t *testing.T) {
	var requestedPaths []string
	npm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPaths = append(requestedPaths, r.URL.Path)
		http.NotFound(w, r)
	}))
	defer npm.Close()

	s := newScanner(npm, nil, nil, nil)
	_, _ = s.Run(context.Background(), "my-corp.io", module.ScanSurface)

	// Should check "my-corp", "mycorp", and "my_corp" (plus scoped variants).
	wantPaths := map[string]bool{
		"/my-corp":         false,
		"/@my-corp/my-corp": false,
		"/mycorp":          false,
		"/@mycorp/mycorp":  false,
		"/my_corp":         false,
		"/@my_corp/my_corp": false,
	}
	for _, p := range requestedPaths {
		if _, ok := wantPaths[p]; ok {
			wantPaths[p] = true
		}
	}
	for path, found := range wantPaths {
		if !found {
			t.Errorf("expected npm request for path %q (hyphen variant), but it was not made", path)
		}
	}
}

// ---------------------------------------------------------------------------
// Subdomain asset uses second-level domain label
// ---------------------------------------------------------------------------

func TestSubdomain_UsesSecondLevelLabel(t *testing.T) {
	var requestedPaths []string
	npm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPaths = append(requestedPaths, r.URL.Path)
		http.NotFound(w, r)
	}))
	defer npm.Close()

	s := newScanner(npm, nil, nil, nil)
	_, _ = s.Run(context.Background(), "api.staging.example.com", module.ScanSurface)

	// Second-level domain label of "api.staging.example.com" is "example".
	foundExample := false
	for _, p := range requestedPaths {
		if p == "/example" {
			foundExample = true
		}
	}
	if !foundExample {
		t.Errorf("expected scanner to derive package candidate 'example' from 'api.staging.example.com', paths: %v", requestedPaths)
	}
}

// ---------------------------------------------------------------------------
// Context cancellation -> no panic, partial or empty results
// ---------------------------------------------------------------------------

func TestContextCancelled_NoPanic(t *testing.T) {
	npm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"name":"acme"}`)
	}))
	defer npm.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before Run

	s := newScanner(npm, nil, nil, nil)
	findings, _ := s.Run(ctx, "acme.com", module.ScanSurface)
	_ = findings // must not panic
}

// ---------------------------------------------------------------------------
// Unreachable registries -> no panic, no findings
// ---------------------------------------------------------------------------

func TestUnreachableRegistries_NoFindingsNoPanic(t *testing.T) {
	s := artifactsign.New()
	s.NPMRegistryURL = "http://127.0.0.1:1"
	s.PyPIBaseURL = "http://127.0.0.1:1"
	s.DockerHubURL = "http://127.0.0.1:1"
	s.GHCRURL = "http://127.0.0.1:1"

	findings, err := s.Run(context.Background(), "acme.com", module.ScanSurface)
	_ = err // error is acceptable
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for unreachable registries, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Surface mode works (scanner ignores scan type, works in all modes)
// ---------------------------------------------------------------------------

func TestSurfaceMode_Works(t *testing.T) {
	npm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"name":"acme","version":"1.0.0"}`)
	}))
	defer npm.Close()

	s := newScanner(npm, nil, nil, nil)
	findings, err := s.Run(context.Background(), "acme.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckSupplyChainUnsignedNPM) {
		t.Error("expected scanner to produce findings in ScanSurface mode")
	}
}

// ---------------------------------------------------------------------------
// Container: Docker Hub uses library/<pkg> repo path
// ---------------------------------------------------------------------------

func TestContainerHub_RepoPathIsLibrarySlashPkg(t *testing.T) {
	var requestedPaths []string
	dockerHub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPaths = append(requestedPaths, r.URL.Path)
		http.NotFound(w, r)
	}))
	defer dockerHub.Close()

	s := newScanner(nil, nil, dockerHub, nil)
	_, _ = s.Run(context.Background(), "acme.com", module.ScanSurface)

	found := false
	for _, p := range requestedPaths {
		if p == "/v2/library/acme/manifests/latest" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected Docker Hub manifest request at /v2/library/acme/manifests/latest, got paths: %v", requestedPaths)
	}
}

// ---------------------------------------------------------------------------
// Container: GHCR uses <pkg>/<pkg> repo path
// ---------------------------------------------------------------------------

func TestContainerGHCR_RepoPathIsPkgSlashPkg(t *testing.T) {
	var requestedPaths []string
	ghcr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPaths = append(requestedPaths, r.URL.Path)
		http.NotFound(w, r)
	}))
	defer ghcr.Close()

	s := newScanner(nil, nil, nil, ghcr)
	_, _ = s.Run(context.Background(), "acme.com", module.ScanSurface)

	found := false
	for _, p := range requestedPaths {
		if p == "/v2/acme/acme/manifests/latest" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected GHCR manifest request at /v2/acme/acme/manifests/latest, got paths: %v", requestedPaths)
	}
}

// ---------------------------------------------------------------------------
// Container: manifest HEAD uses correct Accept header
// ---------------------------------------------------------------------------

func TestContainerRegistry_AcceptHeader(t *testing.T) {
	var acceptHeader string
	containerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/manifests/latest") {
			acceptHeader = r.Header.Get("Accept")
		}
		http.NotFound(w, r)
	}))
	defer containerSrv.Close()

	s := newScanner(nil, nil, containerSrv, nil)
	_, _ = s.Run(context.Background(), "acme.com", module.ScanSurface)

	if !strings.Contains(acceptHeader, "application/vnd.docker.distribution.manifest.v2+json") {
		t.Errorf("expected Docker manifest Accept header, got %q", acceptHeader)
	}
	if !strings.Contains(acceptHeader, "application/vnd.oci.image.manifest.v1+json") {
		t.Errorf("expected OCI manifest Accept header, got %q", acceptHeader)
	}
}

// ---------------------------------------------------------------------------
// Container: unsigned image evidence includes sig_status
// ---------------------------------------------------------------------------

func TestContainerUnsigned_EvidenceIncludesSigStatus(t *testing.T) {
	dockerHub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/manifests/latest") {
			w.Header().Set("Docker-Content-Digest", "sha256:face0ff")
			w.WriteHeader(http.StatusOK)
			return
		}
		if strings.Contains(r.URL.Path, ".sig") {
			http.NotFound(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	defer dockerHub.Close()

	s := newScanner(nil, nil, dockerHub, nil)
	findings, err := s.Run(context.Background(), "acme.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	f := findByCheckID(findings, finding.CheckSupplyChainUnsignedContainer)
	if f == nil {
		t.Fatal("expected container unsigned finding")
	}
	sigStatus, ok := f.Evidence["sig_status"]
	if !ok {
		t.Error("expected 'sig_status' key in evidence")
	}
	// sig_status should be the HTTP status code of the signature tag check (404).
	if status, ok := sigStatus.(int); ok && status != http.StatusNotFound {
		t.Errorf("expected sig_status %d, got %d", http.StatusNotFound, status)
	}
}

// ---------------------------------------------------------------------------
// npm: multiple unsigned findings for different candidates (scoped + unscoped)
// ---------------------------------------------------------------------------

func TestNPM_BothScopedAndUnscoped_EmitsMultipleFindings(t *testing.T) {
	npm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"name":"test","version":"1.0.0"}`)
	}))
	defer npm.Close()

	s := newScanner(npm, nil, nil, nil)
	findings, err := s.Run(context.Background(), "acme.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have at least 2 npm findings: one for "acme", one for "@acme/acme".
	npmCount := countCheckID(findings, finding.CheckSupplyChainUnsignedNPM)
	if npmCount < 2 {
		t.Errorf("expected at least 2 npm unsigned findings (scoped + unscoped), got %d", npmCount)
	}
}

// ---------------------------------------------------------------------------
// npm: unscoped signed but scoped unsigned -> only scoped finding
// ---------------------------------------------------------------------------

func TestNPM_UnscopedSigned_ScopedUnsigned(t *testing.T) {
	npm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/acme" {
			// Unscoped package has provenance.
			fmt.Fprint(w, `{"name":"acme","attestations":{"url":"https://example.com"}}`)
			return
		}
		// Scoped package has no provenance.
		fmt.Fprint(w, `{"name":"@acme/acme","version":"1.0.0"}`)
	}))
	defer npm.Close()

	s := newScanner(npm, nil, nil, nil)
	findings, err := s.Run(context.Background(), "acme.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	npmCount := countCheckID(findings, finding.CheckSupplyChainUnsignedNPM)
	if npmCount != 1 {
		t.Errorf("expected 1 npm unsigned finding (scoped only), got %d", npmCount)
	}

	f := findByCheckID(findings, finding.CheckSupplyChainUnsignedNPM)
	if f == nil {
		t.Fatal("expected finding")
	}
	pkg, _ := f.Evidence["package"]
	if pkg != "@acme/acme" {
		t.Errorf("expected package '@acme/acme', got %v", pkg)
	}
}

// ---------------------------------------------------------------------------
// Empty second-level domain label -> no findings
// ---------------------------------------------------------------------------

func TestEmptySecondLevelLabel_NoFindings(t *testing.T) {
	s := artifactsign.New()
	s.NPMRegistryURL = "http://127.0.0.1:1"
	s.PyPIBaseURL = "http://127.0.0.1:1"
	s.DockerHubURL = "http://127.0.0.1:1"
	s.GHCRURL = "http://127.0.0.1:1"

	findings, err := s.Run(context.Background(), ".com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty second-level label, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// DiscoveredAt is set on findings
// ---------------------------------------------------------------------------

func TestFinding_DiscoveredAtIsSet(t *testing.T) {
	npm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"name":"acme"}`)
	}))
	defer npm.Close()

	s := newScanner(npm, nil, nil, nil)
	findings, err := s.Run(context.Background(), "acme.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	f := findByCheckID(findings, finding.CheckSupplyChainUnsignedNPM)
	if f == nil {
		t.Fatal("expected finding")
	}
	if f.DiscoveredAt.IsZero() {
		t.Error("DiscoveredAt must not be zero")
	}
}
