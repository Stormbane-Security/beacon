package containerimage_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scanner/containerimage"
)

// registryPort is the port used for the fake registry server. The scanner
// probes a fixed set of ports (5000, 443, 8080); we use 8080 because 443
// requires root and 5000 may be occupied by AirPlay on macOS.
const registryPort = "8080"

// startRegistry starts an HTTP server on 127.0.0.1:registryPort with the
// given handler. It returns a cleanup function. The test is skipped if the
// port is already in use.
func startRegistry(t *testing.T, handler http.Handler) func() {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:"+registryPort)
	if err != nil {
		t.Skipf("cannot bind port %s (in use): %v", registryPort, err)
	}

	srv := &http.Server{Handler: handler}
	go srv.Serve(l) //nolint:errcheck

	return func() {
		srv.Close()
	}
}

func hasCheckID(findings []finding.Finding, id finding.CheckID) bool {
	for _, f := range findings {
		if f.CheckID == id {
			return true
		}
	}
	return false
}

func hasSeverity(findings []finding.Finding, id finding.CheckID, sev finding.Severity) bool {
	for _, f := range findings {
		if f.CheckID == id && f.Severity == sev {
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

// ---------------------------------------------------------------------------
// Surface mode -- scanner must be a no-op (deep mode only)
// ---------------------------------------------------------------------------

func TestSurfaceMode_ReturnsNil(t *testing.T) {
	// No server needed: surface mode should return immediately.
	s := containerimage.New()
	findings, err := s.Run(context.Background(), "127.0.0.1", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings in surface mode (container image scanner is deep-only), got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Deep mode -- exposed registry V2 API with catalog + repos
// ---------------------------------------------------------------------------

func TestDeepMode_ExposedRegistry_WithCatalog(t *testing.T) {
	mux := http.NewServeMux()

	// /v2/ -- registry API root returns 200
	mux.HandleFunc("/v2/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{}`)
			return
		}
		// Fall through for sub-paths handled by other routes.
		http.NotFound(w, r)
	})

	// /v2/_catalog -- return repository list
	mux.HandleFunc("/v2/_catalog", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"repositories":["myapp","internal/secrets","infra/nginx"]}`)
	})

	// /v2/<repo>/manifests/latest -- return 200 with digest header (latest tag exists)
	mux.HandleFunc("/v2/myapp/manifests/latest", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Docker-Content-Digest", "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
		w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
		w.WriteHeader(http.StatusOK)
	})

	// /v2/<repo>/manifests/sha256-... -- cosign signature tag: return 404 (unsigned)
	mux.HandleFunc("/v2/myapp/manifests/sha256-abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890.sig", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	// Other repo manifests: no :latest tag
	mux.HandleFunc("/v2/internal/secrets/manifests/latest", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/v2/infra/nginx/manifests/latest", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	// Anonymous push: reject (401)
	mux.HandleFunc("/v2/myapp/blobs/uploads/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		http.NotFound(w, r)
	})

	cleanup := startRegistry(t, mux)
	defer cleanup()

	s := containerimage.New()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	findings, err := s.Run(ctx, "127.0.0.1", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should detect: exposed registry (High)
	if !hasCheckID(findings, finding.CheckContainerRegistryExposed) {
		t.Error("expected CheckContainerRegistryExposed finding when /v2/ returns 200")
	}

	// Should detect catalog (Critical) with the 3 repos
	catalogCount := 0
	for _, f := range findings {
		if f.CheckID == finding.CheckContainerRegistryExposed && f.Severity == finding.SeverityCritical {
			catalogCount++
			repos, ok := f.Evidence["total_repos"]
			if !ok {
				t.Error("catalog finding must include 'total_repos' in Evidence")
			} else if n, _ := repos.(int); n != 3 {
				t.Errorf("expected 3 repos in catalog, got %v", repos)
			}
		}
	}
	if catalogCount == 0 {
		t.Error("expected Critical catalog finding when /v2/_catalog returns repositories")
	}

	// Should detect :latest tag on myapp (Medium)
	if !hasCheckID(findings, finding.CheckContainerImageLatestTag) {
		t.Error("expected CheckContainerImageLatestTag finding when repo has :latest tag")
	}
	if !hasSeverity(findings, finding.CheckContainerImageLatestTag, finding.SeverityMedium) {
		t.Error("expected SeverityMedium for :latest tag finding")
	}

	// Should detect unsigned image (Medium) for myapp
	if !hasCheckID(findings, finding.CheckContainerImageUnsigned) {
		t.Error("expected CheckContainerImageUnsigned finding when cosign signature returns 404")
	}
	if !hasSeverity(findings, finding.CheckContainerImageUnsigned, finding.SeverityMedium) {
		t.Error("expected SeverityMedium for unsigned image finding")
	}

	// Should NOT detect anonymous push (push was rejected)
	if hasCheckID(findings, finding.CheckContainerRegistryAnonymousPush) {
		t.Error("expected no CheckContainerRegistryAnonymousPush when push returns 401")
	}
}

// ---------------------------------------------------------------------------
// Deep mode -- anonymous push accepted (202)
// ---------------------------------------------------------------------------

func TestDeepMode_AnonymousPush_Accepted(t *testing.T) {
	mux := http.NewServeMux()

	// /v2/ returns 200 (registry is exposed)
	mux.HandleFunc("/v2/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{}`)
			return
		}
		http.NotFound(w, r)
	})

	// /v2/_catalog -- empty repo list (no catalog)
	mux.HandleFunc("/v2/_catalog", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	// Anonymous push: accept blob upload (202 Accepted)
	mux.HandleFunc("/v2/beacon-test/blobs/uploads/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.Header().Set("Location", "/v2/beacon-test/blobs/uploads/uuid-1234")
			w.WriteHeader(http.StatusAccepted)
			return
		}
		http.NotFound(w, r)
	})

	cleanup := startRegistry(t, mux)
	defer cleanup()

	s := containerimage.New()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	findings, err := s.Run(ctx, "127.0.0.1", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Must detect anonymous push
	if !hasCheckID(findings, finding.CheckContainerRegistryAnonymousPush) {
		t.Error("expected CheckContainerRegistryAnonymousPush when POST to blobs/uploads/ returns 202")
	}
	if !hasSeverity(findings, finding.CheckContainerRegistryAnonymousPush, finding.SeverityCritical) {
		t.Error("expected SeverityCritical for anonymous push finding")
	}

	// Verify evidence includes the upload URL
	for _, f := range findings {
		if f.CheckID == finding.CheckContainerRegistryAnonymousPush {
			url, ok := f.Evidence["url"]
			if !ok {
				t.Error("anonymous push finding must include 'url' in Evidence")
			} else if urlStr, _ := url.(string); !strings.Contains(urlStr, "blobs/uploads") {
				t.Errorf("Evidence['url'] should contain 'blobs/uploads', got: %s", urlStr)
			}
			if f.ProofCommand == "" {
				t.Error("ProofCommand must not be empty on anonymous push finding")
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Deep mode -- catalog with repos that have signed images (no unsigned finding)
// ---------------------------------------------------------------------------

func TestDeepMode_SignedImage_NoUnsignedFinding(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/v2/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{}`)
			return
		}
		http.NotFound(w, r)
	})

	mux.HandleFunc("/v2/_catalog", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"repositories":["signed-app"]}`)
	})

	// :latest tag exists with a digest
	mux.HandleFunc("/v2/signed-app/manifests/latest", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Docker-Content-Digest", "sha256:deadbeef0000111122223333444455556666777788889999aaaabbbbccccdddd")
		w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
		w.WriteHeader(http.StatusOK)
	})

	// Cosign signature EXISTS (200) -- image is signed
	mux.HandleFunc("/v2/signed-app/manifests/sha256-deadbeef0000111122223333444455556666777788889999aaaabbbbccccdddd.sig", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Reject anonymous push
	mux.HandleFunc("/v2/signed-app/blobs/uploads/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	cleanup := startRegistry(t, mux)
	defer cleanup()

	s := containerimage.New()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	findings, err := s.Run(ctx, "127.0.0.1", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// :latest tag should still be flagged
	if !hasCheckID(findings, finding.CheckContainerImageLatestTag) {
		t.Error("expected CheckContainerImageLatestTag even when image is signed")
	}

	// But no unsigned finding -- the cosign signature exists
	if hasCheckID(findings, finding.CheckContainerImageUnsigned) {
		t.Error("expected no CheckContainerImageUnsigned when cosign signature returns 200")
	}
}

// ---------------------------------------------------------------------------
// Deep mode -- secure registry (all checks return auth-required)
// ---------------------------------------------------------------------------

func TestDeepMode_SecureRegistry_NoFindings(t *testing.T) {
	mux := http.NewServeMux()

	// /v2/ returns 401 Unauthorized -- registry requires authentication
	mux.HandleFunc("/v2/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="https://auth.example.com/token",service="registry.example.com"`)
		w.WriteHeader(http.StatusUnauthorized)
	})

	cleanup := startRegistry(t, mux)
	defer cleanup()

	s := containerimage.New()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	findings, err := s.Run(ctx, "127.0.0.1", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for a secure (401) registry, got %d", len(findings))
		for _, f := range findings {
			t.Logf("  unexpected finding: %s (%s)", f.CheckID, f.Title)
		}
	}
}

// ---------------------------------------------------------------------------
// Deep mode -- catalog enumeration with many repos (>10 limit)
// ---------------------------------------------------------------------------

func TestDeepMode_CatalogManyRepos_LimitsChecks(t *testing.T) {
	// Build 15 repos; scanner should only check first 10 for :latest and sigs.
	var repoNames []string
	for i := 0; i < 15; i++ {
		repoNames = append(repoNames, fmt.Sprintf("repo%d", i))
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/v2/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{}`)
			return
		}
		http.NotFound(w, r)
	})

	mux.HandleFunc("/v2/_catalog", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		quoted := make([]string, len(repoNames))
		for i, r := range repoNames {
			quoted[i] = fmt.Sprintf("%q", r)
		}
		fmt.Fprintf(w, `{"repositories":[%s]}`, strings.Join(quoted, ","))
	})

	// All repos: :latest tag returns 404 (no :latest)
	for _, repo := range repoNames {
		repo := repo
		mux.HandleFunc("/v2/"+repo+"/manifests/latest", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		})
	}

	// Reject all push attempts
	for _, repo := range repoNames {
		repo := repo
		mux.HandleFunc("/v2/"+repo+"/blobs/uploads/", func(w http.ResponseWriter, r *http.Request) {
			_ = repo
			w.WriteHeader(http.StatusUnauthorized)
		})
	}

	cleanup := startRegistry(t, mux)
	defer cleanup()

	s := containerimage.New()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	findings, err := s.Run(ctx, "127.0.0.1", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have the catalog finding with total_repos = 15
	for _, f := range findings {
		if f.CheckID == finding.CheckContainerRegistryExposed && f.Severity == finding.SeverityCritical {
			if total, ok := f.Evidence["total_repos"]; ok {
				if n, _ := total.(int); n != 15 {
					t.Errorf("expected total_repos=15 in catalog finding, got %v", total)
				}
			}
		}
	}

	// No :latest tag findings since all return 404
	if hasCheckID(findings, finding.CheckContainerImageLatestTag) {
		t.Error("expected no :latest tag finding when all manifests/latest return 404")
	}

	// No unsigned findings since no :latest manifests returned a digest
	if hasCheckID(findings, finding.CheckContainerImageUnsigned) {
		t.Error("expected no unsigned finding when no :latest tag exists")
	}
}

// ---------------------------------------------------------------------------
// Probe evidence and ProofCommand correctness
// ---------------------------------------------------------------------------

func TestDeepMode_RegistryExposed_EvidenceFields(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/v2/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"version":"2.0"}`)
			return
		}
		http.NotFound(w, r)
	})

	// No catalog
	mux.HandleFunc("/v2/_catalog", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	// Reject push
	mux.HandleFunc("/v2/beacon-test/blobs/uploads/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	cleanup := startRegistry(t, mux)
	defer cleanup()

	s := containerimage.New()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	findings, err := s.Run(ctx, "127.0.0.1", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckContainerRegistryExposed && f.Severity == finding.SeverityHigh {
			found = true

			// Verify Evidence fields
			if _, ok := f.Evidence["url"]; !ok {
				t.Error("registry exposed finding must include 'url' in Evidence")
			}
			if _, ok := f.Evidence["port"]; !ok {
				t.Error("registry exposed finding must include 'port' in Evidence")
			}
			if _, ok := f.Evidence["status_code"]; !ok {
				t.Error("registry exposed finding must include 'status_code' in Evidence")
			}

			// Verify ProofCommand is populated and contains the target
			if f.ProofCommand == "" {
				t.Error("ProofCommand must not be empty")
			}
			if !strings.Contains(f.ProofCommand, "127.0.0.1") {
				t.Errorf("ProofCommand must contain target host, got: %s", f.ProofCommand)
			}
			if !strings.Contains(f.ProofCommand, "/v2/") {
				t.Errorf("ProofCommand must reference /v2/, got: %s", f.ProofCommand)
			}

			// Module should be "deep"
			if f.Module != "deep" {
				t.Errorf("Module should be 'deep', got: %s", f.Module)
			}

			// Scanner name
			if f.Scanner != "containerimage" {
				t.Errorf("Scanner should be 'containerimage', got: %s", f.Scanner)
			}

			// DiscoveredAt should be set
			if f.DiscoveredAt.IsZero() {
				t.Error("DiscoveredAt must not be zero")
			}
		}
	}
	if !found {
		t.Error("expected a High-severity CheckContainerRegistryExposed finding")
	}
}

// ---------------------------------------------------------------------------
// Scanner name
// ---------------------------------------------------------------------------

func TestScannerName(t *testing.T) {
	s := containerimage.New()
	if s.Name() != "containerimage" {
		t.Errorf("expected scanner name 'containerimage', got %q", s.Name())
	}
}

// ---------------------------------------------------------------------------
// Context cancellation -- no panic
// ---------------------------------------------------------------------------

func TestContextCancelled_NoPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before Run

	s := containerimage.New()
	findings, _ := s.Run(ctx, "127.0.0.1", module.ScanDeep)
	// Must not panic. Empty or partial results are fine.
	_ = findings
}

// ---------------------------------------------------------------------------
// Unreachable host -- no findings, no panic
// ---------------------------------------------------------------------------

func TestUnreachableHost_NoFindings(t *testing.T) {
	s := containerimage.New()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// 192.0.2.0/24 is TEST-NET-1 (RFC 5737), should be unreachable
	findings, err := s.Run(ctx, "192.0.2.1", module.ScanDeep)
	if err != nil {
		t.Logf("error (acceptable): %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for unreachable host, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Catalog with empty repository list -- no catalog finding
// ---------------------------------------------------------------------------

func TestDeepMode_EmptyCatalog_NoCatalogFinding(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/v2/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{}`)
			return
		}
		http.NotFound(w, r)
	})

	// Catalog returns empty list
	mux.HandleFunc("/v2/_catalog", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"repositories":[]}`)
	})

	// Reject push
	mux.HandleFunc("/v2/beacon-test/blobs/uploads/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	cleanup := startRegistry(t, mux)
	defer cleanup()

	s := containerimage.New()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	findings, err := s.Run(ctx, "127.0.0.1", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have the registry exposed (High) but NOT a catalog finding (Critical)
	exposedCount := countCheckID(findings, finding.CheckContainerRegistryExposed)
	criticalCatalog := 0
	for _, f := range findings {
		if f.CheckID == finding.CheckContainerRegistryExposed && f.Severity == finding.SeverityCritical {
			criticalCatalog++
		}
	}

	if exposedCount == 0 {
		t.Error("expected CheckContainerRegistryExposed (High) for /v2/ returning 200")
	}
	if criticalCatalog != 0 {
		t.Error("expected no Critical catalog finding when repository list is empty")
	}
}
