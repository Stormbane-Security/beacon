// Package containerimage probes Docker Registry V2 APIs for exposed
// registries, unsigned images, latest-tag-only images, and anonymous push.
// Deep mode only — all checks send active HTTP requests to the target.
package containerimage

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const scannerName = "containerimage"

// Scanner probes for exposed Docker/OCI container registries.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType == module.ScanSurface {
		return nil, nil
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	now := time.Now()

	type endpoint struct {
		scheme string
		port   string
	}

	endpoints := []endpoint{
		{"https", "5000"},
		{"https", "443"},
		{"https", "8080"},
		{"http", "5000"},
		{"http", "8080"},
	}

	var mu sync.Mutex
	var findings []finding.Finding
	var wg sync.WaitGroup

	for _, ep := range endpoints {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}

		ep := ep
		wg.Add(1)
		go func() {
			defer wg.Done()

			baseURL := fmt.Sprintf("%s://%s:%s", ep.scheme, asset, ep.port)

			// Step 1: Check if /v2/ is accessible (registry API root).
			v2URL := baseURL + "/v2/"
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, v2URL, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon Security Scanner)")

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return
			}

			mu.Lock()
			findings = append(findings, finding.Finding{
				CheckID:     finding.CheckContainerRegistryExposed,
				Module:      "deep",
				Scanner:     scannerName,
				Severity:    finding.SeverityHigh,
				Asset:       asset,
				Title:       fmt.Sprintf("Docker Registry V2 API exposed on %s:%s", asset, ep.port),
				Description: fmt.Sprintf("The Docker Registry V2 API at %s is publicly accessible. An attacker can enumerate repositories, pull images, and potentially extract secrets embedded in image layers.", v2URL),
				Evidence: map[string]any{
					"url":         v2URL,
					"port":        ep.port,
					"status_code": resp.StatusCode,
					"body":        truncate(string(body), 512),
				},
				ProofCommand: fmt.Sprintf("curl -sk '%s'", v2URL),
				DiscoveredAt: now,
			})
			mu.Unlock()

			// Step 2: Try /v2/_catalog to list repositories.
			catalogURL := baseURL + "/v2/_catalog"
			repos := s.probeCatalog(ctx, client, catalogURL)
			if len(repos) > 0 {
				mu.Lock()
				findings = append(findings, finding.Finding{
					CheckID:     finding.CheckContainerRegistryExposed,
					Module:      "deep",
					Scanner:     scannerName,
					Severity:    finding.SeverityCritical,
					Asset:       asset,
					Title:       fmt.Sprintf("Docker Registry catalog exposed on %s:%s (%d repos)", asset, ep.port, len(repos)),
					Description: fmt.Sprintf("The Docker Registry at %s exposes its full repository catalog without authentication. %d repositories were enumerated. Attackers can pull all images and extract embedded secrets, credentials, and proprietary code.", catalogURL, len(repos)),
					Evidence: map[string]any{
						"url":          catalogURL,
						"port":         ep.port,
						"repositories": truncateSlice(repos, 20),
						"total_repos":  len(repos),
					},
					ProofCommand: fmt.Sprintf("curl -sk '%s' | jq .", catalogURL),
					DiscoveredAt: now,
				})
				mu.Unlock()

				// Step 3: For each repo (up to 10), check signatures and :latest tag.
				limit := len(repos)
				if limit > 10 {
					limit = 10
				}
				for _, repo := range repos[:limit] {
					s.checkRepo(ctx, client, baseURL, asset, ep.port, repo, now, &mu, &findings)
				}
			}

			// Step 4: Test anonymous push on a known repo or the first discovered repo.
			pushRepo := "beacon-test"
			if len(repos) > 0 {
				pushRepo = repos[0]
			}
			s.testAnonymousPush(ctx, client, baseURL, asset, ep.port, pushRepo, now, &mu, &findings)
		}()
	}

	wg.Wait()
	return findings, nil
}

// probeCatalog fetches /v2/_catalog and returns the list of repository names.
func (s *Scanner) probeCatalog(ctx context.Context, client *http.Client, catalogURL string) []string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, catalogURL, nil)
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

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	bodyStr := string(body)

	// Parse simple JSON: {"repositories":["repo1","repo2"]}
	// Use basic string parsing to avoid encoding/json import for a simple list.
	var repos []string
	idx := strings.Index(bodyStr, `"repositories"`)
	if idx < 0 {
		return nil
	}
	start := strings.Index(bodyStr[idx:], "[")
	if start < 0 {
		return nil
	}
	end := strings.Index(bodyStr[idx+start:], "]")
	if end < 0 {
		return nil
	}
	arrayStr := bodyStr[idx+start+1 : idx+start+end]
	for _, item := range strings.Split(arrayStr, ",") {
		item = strings.TrimSpace(item)
		item = strings.Trim(item, `"`)
		if item != "" {
			repos = append(repos, item)
		}
	}
	return repos
}

// checkRepo checks a single repository for :latest tag usage and missing cosign signatures.
func (s *Scanner) checkRepo(ctx context.Context, client *http.Client, baseURL, asset, port, repo string, now time.Time, mu *sync.Mutex, findings *[]finding.Finding) {
	// Check for :latest tag
	latestURL := fmt.Sprintf("%s/v2/%s/manifests/latest", baseURL, repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, latestURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon Security Scanner)")
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json")

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		mu.Lock()
		*findings = append(*findings, finding.Finding{
			CheckID:     finding.CheckContainerImageLatestTag,
			Module:      "deep",
			Scanner:     scannerName,
			Severity:    finding.SeverityMedium,
			Asset:       asset,
			Title:       fmt.Sprintf("Container image uses :latest tag: %s", repo),
			Description: fmt.Sprintf("The repository %q on %s:%s has a :latest tag. Using :latest in production makes deployments non-reproducible and vulnerable to tag overwrite attacks where an attacker pushes a malicious image under the same tag.", repo, asset, port),
			Evidence: map[string]any{
				"url":            latestURL,
				"port":           port,
				"repository":     repo,
				"status_code":    resp.StatusCode,
				"docker_digest":  resp.Header.Get("Docker-Content-Digest"),
				"content_type":   resp.Header.Get("Content-Type"),
			},
			ProofCommand: fmt.Sprintf("curl -skI -H 'Accept: application/vnd.docker.distribution.manifest.v2+json' '%s'", latestURL),
			DiscoveredAt: now,
		})
		mu.Unlock()

		// Check for cosign signature on this manifest.
		// Cosign stores signatures at a tag derived from the digest: sha256-<hash>.sig
		digest := resp.Header.Get("Docker-Content-Digest")
		if digest != "" {
			s.checkSignature(ctx, client, baseURL, asset, port, repo, digest, now, mu, findings)
		}
	}
}

// checkSignature checks whether a cosign signature exists for a given image digest.
// Cosign signatures are stored at the tag: sha256-<hash>.sig
func (s *Scanner) checkSignature(ctx context.Context, client *http.Client, baseURL, asset, port, repo, digest string, now time.Time, mu *sync.Mutex, findings *[]finding.Finding) {
	// Convert "sha256:abc123..." to "sha256-abc123....sig"
	sigTag := strings.Replace(digest, "sha256:", "sha256-", 1) + ".sig"
	sigURL := fmt.Sprintf("%s/v2/%s/manifests/%s", baseURL, repo, sigTag)

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, sigURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon Security Scanner)")

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()

	// If the signature tag does not exist (404), the image is unsigned.
	if resp.StatusCode == http.StatusNotFound {
		mu.Lock()
		*findings = append(*findings, finding.Finding{
			CheckID:     finding.CheckContainerImageUnsigned,
			Module:      "deep",
			Scanner:     scannerName,
			Severity:    finding.SeverityMedium,
			Asset:       asset,
			Title:       fmt.Sprintf("Container image unsigned: %s@%s", repo, truncate(digest, 24)),
			Description: fmt.Sprintf("The image %s@%s on %s:%s has no cosign signature. Without image signing, supply chain attacks via tag overwrite or registry compromise cannot be detected. Deploy a signing policy (e.g., cosign + Sigstore) and enforce verification at admission.", repo, digest, asset, port),
			Evidence: map[string]any{
				"repository":  repo,
				"digest":      digest,
				"sig_tag":     sigTag,
				"sig_url":     sigURL,
				"port":        port,
				"sig_status":  resp.StatusCode,
			},
			ProofCommand: fmt.Sprintf("# Check for cosign signature:\ncurl -skI '%s'\n# Or use cosign:\n# cosign verify --key cosign.pub %s:%s/%s@%s", sigURL, asset, port, repo, digest),
			DiscoveredAt: now,
		})
		mu.Unlock()
	}
}

// testAnonymousPush attempts a blob upload initiation to check for anonymous push.
func (s *Scanner) testAnonymousPush(ctx context.Context, client *http.Client, baseURL, asset, port, repo string, now time.Time, mu *sync.Mutex, findings *[]finding.Finding) {
	uploadURL := fmt.Sprintf("%s/v2/%s/blobs/uploads/", baseURL, repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uploadURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon Security Scanner)")
	req.Header.Set("Content-Length", "0")

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()

	// 202 Accepted means the registry is willing to accept blob uploads without auth.
	if resp.StatusCode == http.StatusAccepted {
		mu.Lock()
		*findings = append(*findings, finding.Finding{
			CheckID:     finding.CheckContainerRegistryAnonymousPush,
			Module:      "deep",
			Scanner:     scannerName,
			Severity:    finding.SeverityCritical,
			Asset:       asset,
			Title:       fmt.Sprintf("Container registry accepts anonymous push on %s:%s", asset, port),
			Description: fmt.Sprintf("The Docker Registry at %s:%s accepts unauthenticated blob uploads (POST to %s returned 202 Accepted). An attacker can push malicious images that may be deployed to production, enabling supply chain compromise.", asset, port, uploadURL),
			Evidence: map[string]any{
				"url":         uploadURL,
				"port":        port,
				"repository":  repo,
				"status_code": resp.StatusCode,
				"location":    resp.Header.Get("Location"),
			},
			ProofCommand: fmt.Sprintf("curl -sk -X POST '%s' -w '%%{http_code}'", uploadURL),
			DiscoveredAt: now,
		})
		mu.Unlock()
	}
}

// truncate limits a string to maxLen characters.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// truncateSlice limits a slice to maxLen entries.
func truncateSlice(s []string, maxLen int) []string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
