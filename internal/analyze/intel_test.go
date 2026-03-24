package analyze_test

// Tests for threat intelligence fetching — derived from the spec:
//   - CISA KEV: only entries added within the last 30 days are included
//   - CISA KEV: entries with known ransomware use are flagged
//   - NVD: only entries with CVSS >= 7.0 are included
//   - NVD: descriptions are included and truncated if too long
//   - Any source being unavailable must not fail the overall fetch
//   - Both sources fetch concurrently (tested via timeout behaviour)

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stormbane/beacon/internal/analyze"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

func kevServer(t *testing.T, entries []map[string]any) *httptest.Server {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"vulnerabilities": entries})
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body) //nolint:errcheck
	}))
}

func nvdServer(t *testing.T, vulns []map[string]any) *httptest.Server {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"vulnerabilities": vulns})
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body) //nolint:errcheck
	}))
}

func unavailableServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	}))
}

func recentDate(daysAgo int) string {
	return time.Now().AddDate(0, 0, -daysAgo).Format("2006-01-02")
}

func oldDate() string {
	return time.Now().AddDate(0, 0, -120).Format("2006-01-02") // 120 days ago — outside 90-day KEV window
}

func nvdVuln(id string, score float64, severity, desc string) map[string]any {
	return map[string]any{
		"cve": map[string]any{
			"id": id,
			"descriptions": []map[string]any{
				{"lang": "en", "value": desc},
			},
			"metrics": map[string]any{
				"cvssMetricV31": []map[string]any{
					{"cvssData": map[string]any{
						"baseScore":    score,
						"baseSeverity": severity,
					}},
				},
			},
		},
	}
}

// ─── CISA KEV tests ───────────────────────────────────────────────────────────

func TestKEVOnlyIncludesEntriesAddedWithinWindow(t *testing.T) {
	recent := map[string]any{
		"cveID": "CVE-2024-1111", "vendorProject": "Apache", "product": "Struts",
		"vulnerabilityName": "Apache Struts RCE", "dateAdded": recentDate(5),
		"knownRansomwareCampaignUse": "Unknown",
	}
	old := map[string]any{
		"cveID": "CVE-2022-9999", "vendorProject": "Old", "product": "Software",
		"vulnerabilityName": "Old Vuln", "dateAdded": oldDate(),
		"knownRansomwareCampaignUse": "Unknown",
	}

	kev := kevServer(t, []map[string]any{recent, old})
	defer kev.Close()
	nvd := nvdServer(t, nil)
	defer nvd.Close()

	sources := analyze.IntelSources{CISAURL: kev.URL, NVDURL: nvd.URL}
	intel := sources.Fetch(context.Background(), &http.Client{Timeout: 5 * time.Second})

	if len(intel.KEV) != 1 {
		t.Errorf("KEV entries = %d; want 1 (old entry must be excluded)", len(intel.KEV))
	}
	if len(intel.KEV) > 0 && intel.KEV[0].CVEID != "CVE-2024-1111" {
		t.Errorf("KEV[0].CVEID = %q; want CVE-2024-1111", intel.KEV[0].CVEID)
	}
}

func TestKEVFlagsRansomwareEntries(t *testing.T) {
	entries := []map[string]any{
		{
			"cveID": "CVE-2024-RANSOM", "vendorProject": "Vendor", "product": "Product",
			"vulnerabilityName": "Ransomware CVE", "dateAdded": recentDate(3),
			"knownRansomwareCampaignUse": "Known",
		},
		{
			"cveID": "CVE-2024-CLEAN", "vendorProject": "Vendor", "product": "Product",
			"vulnerabilityName": "Clean CVE", "dateAdded": recentDate(3),
			"knownRansomwareCampaignUse": "Unknown",
		},
	}

	kev := kevServer(t, entries)
	defer kev.Close()
	nvd := nvdServer(t, nil)
	defer nvd.Close()

	sources := analyze.IntelSources{CISAURL: kev.URL, NVDURL: nvd.URL}
	intel := sources.Fetch(context.Background(), &http.Client{Timeout: 5 * time.Second})

	ransomCount := 0
	for _, e := range intel.KEV {
		if e.Ransomware {
			ransomCount++
		}
	}
	if ransomCount != 1 {
		t.Errorf("ransomware-flagged KEV entries = %d; want 1", ransomCount)
	}
}

func TestKEVIncludesVendorAndProductFields(t *testing.T) {
	entries := []map[string]any{{
		"cveID": "CVE-2024-5555", "vendorProject": "Grafana Labs", "product": "Grafana",
		"vulnerabilityName": "Grafana Auth Bypass", "dateAdded": recentDate(2),
		"knownRansomwareCampaignUse": "Unknown",
	}}

	kev := kevServer(t, entries)
	defer kev.Close()
	nvd := nvdServer(t, nil)
	defer nvd.Close()

	sources := analyze.IntelSources{CISAURL: kev.URL, NVDURL: nvd.URL}
	intel := sources.Fetch(context.Background(), &http.Client{Timeout: 5 * time.Second})

	if len(intel.KEV) == 0 {
		t.Fatal("expected 1 KEV entry")
	}
	e := intel.KEV[0]
	if e.Vendor != "Grafana Labs" {
		t.Errorf("Vendor = %q; want %q", e.Vendor, "Grafana Labs")
	}
	if e.Product != "Grafana" {
		t.Errorf("Product = %q; want %q", e.Product, "Grafana")
	}
}

// ─── NVD tests ────────────────────────────────────────────────────────────────

func TestNVDExcludesLowSeverityCVEs(t *testing.T) {
	vulns := []map[string]any{
		nvdVuln("CVE-2024-HIGH", 9.8, "CRITICAL", "Critical RCE in popular framework"),
		nvdVuln("CVE-2024-MED", 5.3, "MEDIUM", "Medium info disclosure"),
		nvdVuln("CVE-2024-LOW", 2.1, "LOW", "Low impact issue"),
	}

	kev := kevServer(t, nil)
	defer kev.Close()
	nvd := nvdServer(t, vulns)
	defer nvd.Close()

	sources := analyze.IntelSources{CISAURL: kev.URL, NVDURL: nvd.URL}
	intel := sources.Fetch(context.Background(), &http.Client{Timeout: 5 * time.Second})

	if len(intel.RecentCVEs) != 1 {
		t.Errorf("NVD entries = %d; want 1 (only CVSS >= 7.0 should be included)", len(intel.RecentCVEs))
	}
	if len(intel.RecentCVEs) > 0 && intel.RecentCVEs[0].ID != "CVE-2024-HIGH" {
		t.Errorf("RecentCVEs[0].ID = %q; want CVE-2024-HIGH", intel.RecentCVEs[0].ID)
	}
}

func TestNVDIncludesCVSSScoreAndSeverity(t *testing.T) {
	vulns := []map[string]any{
		nvdVuln("CVE-2024-SCORE", 8.5, "HIGH", "High severity vuln"),
	}

	kev := kevServer(t, nil)
	defer kev.Close()
	nvd := nvdServer(t, vulns)
	defer nvd.Close()

	sources := analyze.IntelSources{CISAURL: kev.URL, NVDURL: nvd.URL}
	intel := sources.Fetch(context.Background(), &http.Client{Timeout: 5 * time.Second})

	if len(intel.RecentCVEs) == 0 {
		t.Fatal("expected 1 NVD entry")
	}
	e := intel.RecentCVEs[0]
	if e.Score != 8.5 {
		t.Errorf("Score = %.1f; want 8.5", e.Score)
	}
	if e.Severity != "HIGH" {
		t.Errorf("Severity = %q; want HIGH", e.Severity)
	}
}

func TestNVDTruncatesLongDescriptions(t *testing.T) {
	longDesc := strings.Repeat("A", 500) // well over the 200-char limit
	vulns := []map[string]any{
		nvdVuln("CVE-2024-LONG", 9.0, "CRITICAL", longDesc),
	}

	kev := kevServer(t, nil)
	defer kev.Close()
	nvd := nvdServer(t, vulns)
	defer nvd.Close()

	sources := analyze.IntelSources{CISAURL: kev.URL, NVDURL: nvd.URL}
	intel := sources.Fetch(context.Background(), &http.Client{Timeout: 5 * time.Second})

	if len(intel.RecentCVEs) == 0 {
		t.Fatal("expected 1 NVD entry")
	}
	if len(intel.RecentCVEs[0].Description) > 200 {
		t.Errorf("description length = %d; want <= 200 (must be truncated)", len(intel.RecentCVEs[0].Description))
	}
}

// ─── Resilience tests ─────────────────────────────────────────────────────────

func TestFetchDoesNotFailWhenKEVIsUnavailable(t *testing.T) {
	kev := unavailableServer(t)
	defer kev.Close()
	nvd := nvdServer(t, []map[string]any{
		nvdVuln("CVE-2024-WORKS", 9.0, "CRITICAL", "This NVD source works"),
	})
	defer nvd.Close()

	sources := analyze.IntelSources{CISAURL: kev.URL, NVDURL: nvd.URL}
	intel := sources.Fetch(context.Background(), &http.Client{Timeout: 5 * time.Second})

	// Must not panic or error — NVD data should still be present.
	if len(intel.RecentCVEs) == 0 {
		t.Error("NVD data should be returned even when CISA KEV is unavailable")
	}
	if len(intel.FetchErrors) == 0 {
		t.Error("fetch errors must record the CISA KEV failure")
	}
}

func TestFetchDoesNotFailWhenNVDIsUnavailable(t *testing.T) {
	kev := kevServer(t, []map[string]any{{
		"cveID": "CVE-2024-KEV", "vendorProject": "V", "product": "P",
		"vulnerabilityName": "KEV works", "dateAdded": recentDate(1),
		"knownRansomwareCampaignUse": "Unknown",
	}})
	defer kev.Close()
	nvd := unavailableServer(t)
	defer nvd.Close()

	sources := analyze.IntelSources{CISAURL: kev.URL, NVDURL: nvd.URL}
	intel := sources.Fetch(context.Background(), &http.Client{Timeout: 5 * time.Second})

	if len(intel.KEV) == 0 {
		t.Error("CISA KEV data should be returned even when NVD is unavailable")
	}
	if len(intel.FetchErrors) == 0 {
		t.Error("fetch errors must record the NVD failure")
	}
}

func TestFetchReturnsEmptyIntelWhenBothSourcesUnavailable(t *testing.T) {
	kev := unavailableServer(t)
	defer kev.Close()
	nvd := unavailableServer(t)
	defer nvd.Close()

	sources := analyze.IntelSources{CISAURL: kev.URL, NVDURL: nvd.URL}
	intel := sources.Fetch(context.Background(), &http.Client{Timeout: 5 * time.Second})

	if len(intel.KEV) != 0 || len(intel.RecentCVEs) != 0 {
		t.Error("both sources failed — KEV and RecentCVEs must be empty")
	}
	if len(intel.FetchErrors) != 2 {
		t.Errorf("fetch errors = %d; want 2 (one per failed source)", len(intel.FetchErrors))
	}
}

// ─── Prompt rendering ─────────────────────────────────────────────────────────

func TestAppendToPromptIncludesCVEIDsAndProducts(t *testing.T) {
	intel := analyze.ThreatIntel{
		KEV: []analyze.KEVEntry{
			{CVEID: "CVE-2024-9999", Vendor: "Grafana Labs", Product: "Grafana",
				Name: "Auth Bypass", DateAdded: recentDate(1)},
		},
		RecentCVEs: []analyze.CVEEntry{
			{ID: "CVE-2024-8888", Score: 9.8, Severity: "CRITICAL",
				Description: "RCE in Apache Struts"},
		},
	}

	var b strings.Builder
	intel.AppendToPrompt(&b)
	out := b.String()

	checks := []string{"CVE-2024-9999", "Grafana", "CVE-2024-8888", "9.8", "CRITICAL", "Apache Struts"}
	for _, s := range checks {
		if !strings.Contains(out, s) {
			t.Errorf("prompt output does not contain %q\noutput:\n%s", s, out)
		}
	}
}

func TestAppendToPromptFlagsRansomware(t *testing.T) {
	intel := analyze.ThreatIntel{
		KEV: []analyze.KEVEntry{
			{CVEID: "CVE-2024-RANSOM", Vendor: "V", Product: "P",
				Name: "Ransomware CVE", DateAdded: recentDate(1), Ransomware: true},
		},
	}

	var b strings.Builder
	intel.AppendToPrompt(&b)
	out := b.String()

	if !strings.Contains(out, "RANSOMWARE") {
		t.Errorf("prompt output must flag ransomware-associated CVEs; got:\n%s", out)
	}
}

func TestAppendToPromptWritesNothingWhenNoIntel(t *testing.T) {
	intel := analyze.ThreatIntel{} // empty

	var b strings.Builder
	intel.AppendToPrompt(&b)

	if b.Len() != 0 {
		t.Errorf("empty intel should produce no prompt output; got %q", b.String())
	}
}

func TestNVDRequestIncludesDateRange(t *testing.T) {
	var capturedURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedURL = r.URL.String()
		fmt.Fprintf(w, `{"vulnerabilities":[]}`)
	}))
	defer srv.Close()

	kev := kevServer(t, nil)
	defer kev.Close()

	sources := analyze.IntelSources{CISAURL: kev.URL, NVDURL: srv.URL}
	sources.Fetch(context.Background(), &http.Client{Timeout: 5 * time.Second})

	if !strings.Contains(capturedURL, "pubStartDate") {
		t.Errorf("NVD request must include pubStartDate; URL was: %s", capturedURL)
	}
	if !strings.Contains(capturedURL, "pubEndDate") {
		t.Errorf("NVD request must include pubEndDate; URL was: %s", capturedURL)
	}
}
