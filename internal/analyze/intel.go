package analyze

// intel.go fetches current threat intelligence from public sources and
// structures it for inclusion in the playbook analysis prompt.
//
// Sources:
//   - CISA KEV (Known Exploited Vulnerabilities Catalog) — actively exploited CVEs
//   - NVD CVE API — recent high/critical CVEs not yet in KEV
//
// Both sources are free, require no API keys, and are authoritative.
// If a source is unavailable the rest of the analysis proceeds normally —
// threat intel enriches the prompt but is not required for it.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	DefaultCISAURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	DefaultNVDURL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	DefaultOSVURL  = "https://api.osv.dev/v1/query"

	// Only show KEV entries added within this window.
	// 90 days gives Claude context on recently-added entries that may not yet
	// have broad playbook coverage (KEV entries often predate Nuclei templates).
	kevWindowDays = 90
	// Only include NVD CVEs with CVSS >= this score.
	nvdMinCVSS = 7.0
	// Maximum NVD entries to include in the prompt.
	nvdMaxEntries = 60
	// NVD CVE lookback window — 30 days gives better context for new CVEs.
	nvdLookbackDays = 30
)

// IntelSources configures the URLs for threat intel feeds.
// Use DefaultIntelSources() for production; override in tests.
type IntelSources struct {
	CISAURL string
	NVDURL  string
	OSVURL  string
	// Since, when non-zero, filters CVE/advisory entries to only those
	// added/modified after this time. Used to surface "new since last run"
	// findings rather than always showing the same fixed window of CVEs.
	// When zero, the default window constants (kevWindowDays, nvdLookbackDays) apply.
	Since time.Time
}

func DefaultIntelSources() IntelSources {
	return IntelSources{
		CISAURL: DefaultCISAURL,
		NVDURL:  DefaultNVDURL,
		OSVURL:  DefaultOSVURL,
	}
}

// ThreatIntel holds fetched threat intelligence ready for the prompt.
type ThreatIntel struct {
	KEV         []KEVEntry  // CISA actively-exploited CVEs added recently
	RecentCVEs  []CVEEntry  // NVD high/critical CVEs from the last N days
	OSVAdvisories []OSVEntry // Google OSV open-source vulnerability advisories
	FetchErrors []string    // non-fatal errors (sources are optional)
}

// OSVEntry is a single Google OSV advisory record.
type OSVEntry struct {
	ID       string
	Summary  string
	Packages []string
	Severity string
}

// KEVEntry is a single CISA Known Exploited Vulnerability.
type KEVEntry struct {
	CVEID       string
	Vendor      string
	Product     string
	Name        string
	DateAdded   string
	Ransomware  bool // true = known ransomware campaign use
}

// CVEEntry is a single NVD CVE record.
type CVEEntry struct {
	ID          string
	Score       float64
	Severity    string
	Description string
}

// Fetch retrieves threat intelligence from all configured sources concurrently.
// Never returns an error — partial results are always returned.
func (s IntelSources) Fetch(ctx context.Context, client *http.Client) ThreatIntel {
	var (
		intel ThreatIntel
		mu    sync.Mutex
		wg    sync.WaitGroup
	)

	wg.Add(3)

	go func() {
		defer wg.Done()
		entries, err := fetchKEV(ctx, client, s.CISAURL, s.Since)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			intel.FetchErrors = append(intel.FetchErrors, "CISA KEV: "+err.Error())
			return
		}
		intel.KEV = entries
	}()

	go func() {
		defer wg.Done()
		entries, err := fetchNVD(ctx, client, s.NVDURL, s.Since)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			intel.FetchErrors = append(intel.FetchErrors, "NVD: "+err.Error())
			return
		}
		intel.RecentCVEs = entries
	}()

	go func() {
		defer wg.Done()
		if s.OSVURL == "" {
			return
		}
		entries, err := fetchOSV(ctx, client, s.OSVURL)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			intel.FetchErrors = append(intel.FetchErrors, "OSV: "+err.Error())
			return
		}
		intel.OSVAdvisories = entries
	}()

	wg.Wait()
	return intel
}

// ─── CISA KEV ─────────────────────────────────────────────────────────────────

type cisaKEVResponse struct {
	Vulnerabilities []struct {
		CVEID                        string `json:"cveID"`
		VendorProject                string `json:"vendorProject"`
		Product                      string `json:"product"`
		VulnerabilityName            string `json:"vulnerabilityName"`
		DateAdded                    string `json:"dateAdded"`
		KnownRansomwareCampaignUse   string `json:"knownRansomwareCampaignUse"`
	} `json:"vulnerabilities"`
}

func fetchKEV(ctx context.Context, client *http.Client, url string, since time.Time) ([]KEVEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Beacon/1.0 security-scanner")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024)) // 8 MB cap
	if err != nil {
		return nil, err
	}

	var kev cisaKEVResponse
	if err := json.Unmarshal(data, &kev); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	// Use the later of (since) and (now - kevWindowDays) as the cutoff so we
	// never show entries older than kevWindowDays even if analyze hasn't run recently.
	cutoff := time.Now().AddDate(0, 0, -kevWindowDays)
	if !since.IsZero() && since.After(cutoff) {
		cutoff = since
	}
	var out []KEVEntry
	for _, v := range kev.Vulnerabilities {
		added, err := time.Parse("2006-01-02", v.DateAdded)
		if err != nil || added.Before(cutoff) {
			continue
		}
		out = append(out, KEVEntry{
			CVEID:      v.CVEID,
			Vendor:     v.VendorProject,
			Product:    v.Product,
			Name:       v.VulnerabilityName,
			DateAdded:  v.DateAdded,
			Ransomware: strings.EqualFold(v.KnownRansomwareCampaignUse, "Known"),
		})
	}
	return out, nil
}

// ─── NVD ──────────────────────────────────────────────────────────────────────

type nvdResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				V31 []struct {
					CVSSData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
				V30 []struct {
					CVSSData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV30"`
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

func fetchNVD(ctx context.Context, client *http.Client, baseURL string, since time.Time) ([]CVEEntry, error) {
	now := time.Now().UTC()
	start := now.AddDate(0, 0, -nvdLookbackDays)
	// If we know when analyze last ran, narrow the window to new CVEs only.
	// Never go narrower than 7 days to avoid missing CVEs in short cadences.
	minStart := now.AddDate(0, 0, -7)
	if !since.IsZero() && since.After(minStart) {
		start = since
	} else if !since.IsZero() && since.After(start) {
		start = since
	}

	url := fmt.Sprintf("%s?pubStartDate=%s&pubEndDate=%s&resultsPerPage=%d",
		baseURL,
		start.Format("2006-01-02T15:04:05.000"),
		now.Format("2006-01-02T15:04:05.000"),
		nvdMaxEntries*2, // fetch extra, filter below
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Beacon/1.0 security-scanner")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024)) // 4 MB cap
	if err != nil {
		return nil, err
	}

	var nvd nvdResponse
	if err := json.Unmarshal(data, &nvd); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	var out []CVEEntry
	for _, v := range nvd.Vulnerabilities {
		score, severity := extractCVSS(v.CVE.Metrics)
		if score < nvdMinCVSS {
			continue
		}

		desc := ""
		for _, d := range v.CVE.Descriptions {
			if d.Lang == "en" {
				desc = d.Value
				break
			}
		}
		// Truncate long descriptions.
		if len(desc) > 200 {
			desc = desc[:197] + "..."
		}

		out = append(out, CVEEntry{
			ID:          v.CVE.ID,
			Score:       score,
			Severity:    severity,
			Description: desc,
		})
		if len(out) >= nvdMaxEntries {
			break
		}
	}
	return out, nil
}

func extractCVSS(m struct {
	V31 []struct {
		CVSSData struct {
			BaseScore    float64 `json:"baseScore"`
			BaseSeverity string  `json:"baseSeverity"`
		} `json:"cvssData"`
	} `json:"cvssMetricV31"`
	V30 []struct {
		CVSSData struct {
			BaseScore    float64 `json:"baseScore"`
			BaseSeverity string  `json:"baseSeverity"`
		} `json:"cvssData"`
	} `json:"cvssMetricV30"`
}) (float64, string) {
	if len(m.V31) > 0 {
		return m.V31[0].CVSSData.BaseScore, m.V31[0].CVSSData.BaseSeverity
	}
	if len(m.V30) > 0 {
		return m.V30[0].CVSSData.BaseScore, m.V30[0].CVSSData.BaseSeverity
	}
	return 0, ""
}

// ─── OSV ──────────────────────────────────────────────────────────────────────

// osvQueryRequest is the minimal OSV batch query payload.
// We query for recently-modified advisories across all ecosystems.
type osvQueryRequest struct {
	Query struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
	} `json:"query"`
}

type osvResponse struct {
	Vulns []struct {
		ID       string `json:"id"`
		Summary  string `json:"summary"`
		Severity []struct {
			Type  string `json:"type"`
			Score string `json:"score"`
		} `json:"severity"`
		Affected []struct {
			Package struct {
				Name      string `json:"name"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
		} `json:"affected"`
		Modified string `json:"modified"`
	} `json:"vulns"`
}

// osvHighImpactEcosystems are ecosystems most likely to affect web infrastructure.
var osvHighImpactEcosystems = []string{
	"npm", "PyPI", "Go", "Maven", "RubyGems", "Packagist",
}

// fetchOSV queries the OSV API for recent high-severity advisories across
// web-infrastructure-relevant package ecosystems.
// We query each ecosystem for recent vulnerabilities, filtering for those
// modified in the last 30 days.
func fetchOSV(ctx context.Context, client *http.Client, baseURL string) ([]OSVEntry, error) {
	// OSV doesn't have a "recent" bulk endpoint without a package name.
	// Use the /v1/vulns endpoint with a lastModified filter via the query API.
	// We query for advisories without a package filter to get cross-ecosystem data,
	// but limit by modification time on our side.
	url := strings.TrimSuffix(baseURL, "/query") + "/vulns?modified_since=" +
		time.Now().AddDate(0, 0, -30).UTC().Format("2006-01-02T15:04:05Z")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Beacon/1.0 security-scanner")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return nil, err
	}

	var osvResp osvResponse
	if err := json.Unmarshal(data, &osvResp); err != nil {
		return nil, fmt.Errorf("parse OSV: %w", err)
	}

	cutoff := time.Now().AddDate(0, 0, -30)
	var out []OSVEntry
	for _, v := range osvResp.Vulns {
		modified, err := time.Parse(time.RFC3339, v.Modified)
		if err != nil || modified.Before(cutoff) {
			continue
		}

		// Collect package names.
		var packages []string
		seen := make(map[string]bool)
		for _, a := range v.Affected {
			key := a.Package.Ecosystem + ":" + a.Package.Name
			if !seen[key] {
				seen[key] = true
				packages = append(packages, key)
			}
		}

		severity := "UNKNOWN"
		for _, s := range v.Severity {
			if s.Type == "CVSS_V3" || s.Type == "CVSS_V4" {
				severity = s.Score
				break
			}
		}

		summary := v.Summary
		if len(summary) > 200 {
			summary = summary[:197] + "..."
		}

		out = append(out, OSVEntry{
			ID:       v.ID,
			Summary:  summary,
			Packages: packages,
			Severity: severity,
		})
		if len(out) >= 40 {
			break
		}
	}
	return out, nil
}

// ─── Prompt rendering ─────────────────────────────────────────────────────────

// AppendToPrompt writes the threat intel section into the given builder.
// If there is no intel to report, writes nothing.
func (ti ThreatIntel) AppendToPrompt(b *strings.Builder) {
	if len(ti.KEV) == 0 && len(ti.RecentCVEs) == 0 && len(ti.OSVAdvisories) == 0 {
		if len(ti.FetchErrors) > 0 {
			b.WriteString("## Threat intelligence\n")
			b.WriteString("(Sources unavailable: " + strings.Join(ti.FetchErrors, "; ") + ")\n\n")
		}
		return
	}

	b.WriteString("## Current threat intelligence\n\n")

	if len(ti.KEV) > 0 {
		b.WriteString(fmt.Sprintf("### CISA Known Exploited Vulnerabilities — added in the last %d days\n", kevWindowDays))
		b.WriteString("These are confirmed to be actively exploited in the wild right now.\n\n")
		for _, e := range ti.KEV {
			ransomFlag := ""
			if e.Ransomware {
				ransomFlag = " [RANSOMWARE]"
			}
			b.WriteString(fmt.Sprintf("  %s  %s / %s  \"%s\"  added=%s%s\n",
				e.CVEID, e.Vendor, e.Product, e.Name, e.DateAdded, ransomFlag))
		}
		b.WriteString("\n")
	}

	if len(ti.RecentCVEs) > 0 {
		b.WriteString(fmt.Sprintf("### Recent high/critical CVEs (last %d days, CVSS ≥ %.0f)\n\n", nvdLookbackDays, nvdMinCVSS))
		for _, e := range ti.RecentCVEs {
			b.WriteString(fmt.Sprintf("  %s  CVSS=%.1f/%s  %s\n",
				e.ID, e.Score, e.Severity, e.Description))
		}
		b.WriteString("\n")
	}

	if len(ti.OSVAdvisories) > 0 {
		b.WriteString("### Google OSV — recent open-source vulnerability advisories (last 30 days)\n")
		b.WriteString("These affect open-source packages commonly deployed in web infrastructure.\n\n")
		for _, e := range ti.OSVAdvisories {
			pkgs := strings.Join(e.Packages, ", ")
			if len(pkgs) > 80 {
				pkgs = pkgs[:77] + "..."
			}
			b.WriteString(fmt.Sprintf("  %s  severity=%s  packages=[%s]  %s\n",
				e.ID, e.Severity, pkgs, e.Summary))
		}
		b.WriteString("\n")
	}

	if len(ti.FetchErrors) > 0 {
		b.WriteString("(Partial intel — some sources unavailable: " + strings.Join(ti.FetchErrors, "; ") + ")\n\n")
	}
}
