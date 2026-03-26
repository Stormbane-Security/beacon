// Package cloudbuckets checks for publicly accessible cloud storage buckets
// (AWS S3, Google Cloud Storage, Azure Blob) associated with a domain.
// Detection is purely via DNS and HTTP — no cloud credentials required.
package cloudbuckets

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const scannerName = "cloudbuckets"

// Scanner probes common bucket naming patterns derived from the target domain.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	// Strip subdomains — bucket names are derived from the root domain.
	// Only run on the root domain itself to avoid reporting the same guessed
	// bucket names once per subdomain (api.acme.com, app.acme.com, etc. all
	// generate identical candidates and would produce duplicate findings).
	root := rootDomain(asset)
	if asset != root {
		return nil, nil
	}

	client := &http.Client{
		Timeout: 8 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // don't follow redirects — 301 is also informative
		},
	}

	now := time.Now()

	// Fetch the asset's root page to correlate guessed bucket names against
	// actual references in the target's HTML/JS. If a bucket URL or name appears
	// in the page source we can confirm ownership, which raises the finding's
	// confidence from "possible" to "confirmed".
	pageText := fetchPageText(ctx, client, asset)

	// Generate candidate bucket names from the domain.
	// Hard-cap at 50 candidates × 3 providers = 150 max probes.
	const maxCandidates = 50
	candidates := bucketCandidates(root)
	if len(candidates) > maxCandidates {
		candidates = candidates[:maxCandidates]
	}

	// Probe all candidates concurrently, up to 15 goroutines at a time.
	// Each goroutine runs up to 3 provider probes (S3, GCS, Azure) sequentially
	// per candidate to avoid hammering multiple providers at the same instant.
	const concurrency = 15
	sem := make(chan struct{}, concurrency)
	var mu sync.Mutex
	var findings []finding.Finding
	var wg sync.WaitGroup

	for _, c := range candidates {
		select {
		case <-ctx.Done():
			wg.Wait()
			return findings, nil
		default:
		}
		sem <- struct{}{}
		c := c
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			var local []*finding.Finding

			// --- AWS S3 ---
			s3URL := fmt.Sprintf("https://%s.s3.amazonaws.com/", c)
			local = append(local, probeURL(ctx, client, asset, s3URL, "AWS S3", c, pageText, now))
			if scanType == module.ScanDeep {
				local = append(local, probeWrite(ctx, client, asset, s3URL, "AWS S3", c, now))
			}

			// --- Google Cloud Storage ---
			gcsURL := fmt.Sprintf("https://storage.googleapis.com/%s/", c)
			local = append(local, probeURL(ctx, client, asset, gcsURL, "GCS", c, pageText, now))
			if scanType == module.ScanDeep {
				local = append(local, probeWrite(ctx, client, asset, gcsURL, "GCS", c, now))
			}

			// --- Azure Blob Storage ---
			azureURL := fmt.Sprintf("https://%s.blob.core.windows.net/", c)
			local = append(local, probeURL(ctx, client, asset, azureURL, "Azure Blob", c, pageText, now))
			if scanType == module.ScanDeep {
				local = append(local, probeWrite(ctx, client, asset, azureURL, "Azure Blob", c, now))
			}

			mu.Lock()
			for _, f := range local {
				if f != nil {
					findings = append(findings, *f)
				}
			}
			mu.Unlock()
		}()
	}
	wg.Wait()

	return findings, nil
}

// fetchPageText fetches the root page of the asset (https first, then http)
// and returns the body as a string, capped at 256 KB. Returns "" on error.
// Used to correlate guessed bucket names against real page references.
func fetchPageText(ctx context.Context, client *http.Client, asset string) string {
	for _, scheme := range []string{"https", "http"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+asset, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
		resp.Body.Close()
		if resp.StatusCode == 200 {
			return string(body)
		}
	}
	return ""
}

// probeURL checks a single bucket URL. Returns a finding if it exists or is public.
// pageText is the target's root page HTML/JS; if it references the bucket URL or
// bucket name, the finding is marked as ownership-confirmed (higher confidence).
func probeURL(ctx context.Context, client *http.Client, asset, url, provider, bucketName, pageText string, now time.Time) *finding.Finding {
	confirmed := pageText != "" && (strings.Contains(pageText, bucketName) || strings.Contains(pageText, strings.TrimSuffix(url, "/")))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon Security Scanner)")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case 200:
		// Read up to 4KB of the response body to determine whether listing is enabled.
		// GCS and S3 both return XML with <ListBucketResult> when the bucket is publicly
		// listable. An empty body or non-XML body means the bucket URL responded (exists,
		// public object access possible) but directory listing is disabled.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if strings.Contains(string(body), "ListBucketResult") {
			listURL := fmt.Sprintf("%s?max-keys=20", url)
			titlePrefix := "Possible"
			desc := fmt.Sprintf("A %s bucket named '%s' (guessed from %s) is publicly listable. Confirm it belongs to the target by reviewing the object keys. If confirmed, anyone can enumerate and download all contents.", provider, bucketName, asset)
			if confirmed {
				titlePrefix = "Confirmed"
				desc = fmt.Sprintf("A %s bucket named '%s' belonging to %s is publicly listable — the target's own page references this bucket. Anyone can enumerate and download all contents.", provider, bucketName, asset)
			}
			return &finding.Finding{
				CheckID:     finding.CheckCloudBucketPublic,
				Module:      "surface",
				Scanner:     scannerName,
				Severity:    finding.SeverityCritical,
				Title:       fmt.Sprintf("%s public %s bucket (listable): %s", titlePrefix, provider, bucketName),
				Description: desc,
				Asset:       asset,
				Evidence: map[string]any{
					"bucket_url":          url,
					"bucket_name":         bucketName,
					"provider":            provider,
					"status_code":         resp.StatusCode,
					"listing":             "enabled",
					"ownership_confirmed": confirmed,
				},
				ProofCommand: fmt.Sprintf(
					"# List up to 20 object keys to confirm ownership and enumerate contents:\ncurl -s '%s' | grep -o '<Key>[^<]*</Key>' | sed 's/<[^>]*>//g'",
					listURL),
				DiscoveredAt: now,
			}
		}
		// Bucket exists and is publicly accessible but listing is disabled.
		listURL := fmt.Sprintf("%s?max-keys=20", url)
		titlePrefix := "Possible"
		desc := fmt.Sprintf("A %s bucket named '%s' (guessed from %s) responded with HTTP 200 but listing is disabled. Bucket ownership is unconfirmed — verify by checking whether the target's HTML/JS references this bucket URL.", provider, bucketName, asset)
		if confirmed {
			titlePrefix = "Confirmed"
			desc = fmt.Sprintf("A %s bucket named '%s' belonging to %s is publicly accessible (listing disabled). The target's own page references this bucket, confirming ownership.", provider, bucketName, asset)
		}
		return &finding.Finding{
			CheckID:     finding.CheckCloudBucketPublic,
			Module:      "surface",
			Scanner:     scannerName,
			Severity:    finding.SeverityMedium,
			Title:       fmt.Sprintf("%s public %s bucket (listing disabled): %s", titlePrefix, provider, bucketName),
			Description: desc,
			Asset:       asset,
			Evidence: map[string]any{
				"bucket_url":          url,
				"bucket_name":         bucketName,
				"provider":            provider,
				"status_code":         resp.StatusCode,
				"listing":             "disabled",
				"ownership_confirmed": confirmed,
			},
			ProofCommand: fmt.Sprintf(
				"# Attempt to list objects (empty = listing disabled, XML = listable):\ncurl -s '%s'\n# If you know an object path, fetch it directly:\n# curl -I '%sPATH/TO/OBJECT'",
				listURL, url),
			DiscoveredAt: now,
		}

	case 403:
		// Bucket exists but is private — still worth noting
		return &finding.Finding{
			CheckID:     finding.CheckCloudBucketExists,
			Module:      "surface",
			Scanner:     scannerName,
			Severity:    finding.SeverityInfo,
			Title:       fmt.Sprintf("%s bucket exists (private): %s", provider, bucketName),
			Description: fmt.Sprintf("A %s bucket named '%s' associated with %s exists but is not publicly accessible. Verify its permissions are correctly configured.", provider, bucketName, asset),
			Asset:       asset,
			Evidence: map[string]any{
				"bucket_url":          url,
				"bucket_name":         bucketName,
				"provider":            provider,
				"status_code":         resp.StatusCode,
				"ownership_confirmed": confirmed,
			},
			ProofCommand: fmt.Sprintf("curl -sI '%s' | grep -i 'HTTP/'", url),
			DiscoveredAt: now,
		}
	}

	return nil
}

// probeWrite attempts a PUT to baseURL+"beacon-scanner-write-test" to check whether
// the bucket accepts unauthenticated writes. If the PUT succeeds (200 or 204) it
// immediately sends a DELETE to clean up the object, then returns a Critical finding.
// A bucket that is publicly writable is more dangerous than one that is publicly
// readable: attackers can upload malware, phishing pages, or poisoned JS assets
// that the target domain will serve to its users.
func probeWrite(ctx context.Context, client *http.Client, asset, baseURL, provider, bucketName string, now time.Time) *finding.Finding {
	const testKey = "beacon-scanner-write-test"
	writeURL := baseURL + testKey

	body := bytes.NewReader([]byte("beacon-scanner-write-test"))
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, writeURL, body)
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon Security Scanner)")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return nil
	}

	// Write succeeded — immediately attempt cleanup.
	delReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, writeURL, nil)
	if err == nil {
		delResp, err := client.Do(delReq)
		if err == nil {
			delResp.Body.Close()
		}
	}

	return &finding.Finding{
		CheckID:  finding.CheckCloudBucketWritable,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Title:    fmt.Sprintf("Publicly writable %s bucket: %s", provider, bucketName),
		Description: fmt.Sprintf(
			"A %s bucket named '%s' associated with %s accepts unauthenticated PUT requests. "+
				"An attacker can upload arbitrary files — including malware, phishing pages, or "+
				"poisoned JavaScript — which may be served directly from your domain. "+
				"The test object was deleted after verification.",
			provider, bucketName, asset,
		),
		Asset: asset,
		Evidence: map[string]any{
			"bucket_url":  baseURL,
			"write_url":   writeURL,
			"bucket_name": bucketName,
			"provider":    provider,
			"status_code": resp.StatusCode,
		},
		ProofCommand: fmt.Sprintf("curl -sI -X PUT -d 'beacon-test' '%s' | grep -i 'HTTP/'", writeURL),
		DiscoveredAt: now,
	}
}

// bucketCandidates generates likely bucket names from a root domain.
// e.g. "acme.com" → ["acme", "acme-assets", "acme-static", "acme-backup", ...]
//
// Org-name-derived candidates were intentionally removed: generating them
// required resolving the asset's IP and querying a third-party IP reputation
// service (ip-api.com), which leaks target IP addresses to an external party.
func bucketCandidates(root string) []string {
	// Extract the base name (drop TLD)
	parts := strings.Split(root, ".")
	base := parts[0]

	suffixes := []string{
		"",
		"-assets",
		"-static",
		"-media",
		"-uploads",
		"-files",
		"-backup",
		"-backups",
		"-data",
		"-dev",
		"-staging",
		"-prod",
		"-logs",
		"-cdn",
		"-images",
		"-public",
		"-private",
		"-storage",
		"-archive",
	}

	seen := make(map[string]struct{})
	var candidates []string

	addCandidate := func(name string) {
		if _, ok := seen[name]; !ok {
			seen[name] = struct{}{}
			candidates = append(candidates, name)
		}
	}

	for _, s := range suffixes {
		addCandidate(base + s)
		// Also try full domain-based names (e.g. "acme-com-assets")
		addCandidate(strings.ReplaceAll(root, ".", "-") + s)
	}

	return candidates
}

// rootDomain strips subdomains, returning e.g. "acme.com" from "app.acme.com".
func rootDomain(asset string) string {
	parts := strings.Split(asset, ".")
	if len(parts) <= 2 {
		return asset
	}
	return strings.Join(parts[len(parts)-2:], ".")
}
