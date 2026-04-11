package portscan

import (
	"testing"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
)

// cveMakeF is a minimal findingMaker for CVE version check tests.
func cveMakeF(
	checkID finding.CheckID,
	severity finding.Severity,
	title, description string,
	evidence map[string]any,
) finding.Finding {
	return finding.Finding{
		CheckID:      checkID,
		Severity:     severity,
		Title:        title,
		Description:  description,
		Evidence:     evidence,
		DiscoveredAt: time.Now(),
		Module:       "test",
		Scanner:      "cve_version_check_test",
	}
}

func TestCheckVersionCVEs_NginxVulnerable(t *testing.T) {
	// nginx 1.17.7 should match CVE-2021-23017 (resolver RCE, < 1.21.0)
	// and CVE-2017-7529 (range info leak, < 1.13.3) — wait, 1.17.7 > 1.13.3
	// so only CVE-2021-23017 should match.
	results := CheckVersionCVEs("nginx", "1.17.7", cveMakeF)

	found := map[string]bool{}
	for _, f := range results {
		found[f.CheckID] = true
	}
	if !found[finding.CheckCVENginxResolverRCE] {
		t.Errorf("expected CVE-2021-23017 (nginx resolver RCE) for nginx 1.17.7, got %d findings: %v",
			len(results), checkIDs(results))
	}
	if found[finding.CheckCVENginxRangeInfoLeak] {
		t.Errorf("nginx 1.17.7 should NOT match CVE-2017-7529 (fixed in 1.13.3)")
	}
}

func TestCheckVersionCVEs_NginxSafe(t *testing.T) {
	// nginx 1.25.0 should NOT match any CVE
	results := CheckVersionCVEs("nginx", "1.25.0", cveMakeF)
	if len(results) > 0 {
		t.Errorf("expected no CVEs for nginx 1.25.0, got: %v", checkIDs(results))
	}
}

func TestCheckVersionCVEs_OpenSSHRegreSSHion(t *testing.T) {
	// OpenSSH 9.1 → should match CVE-2024-6387 (8.5–9.8)
	results := CheckVersionCVEs("OpenSSH", "9.1", cveMakeF)
	found := map[string]bool{}
	for _, f := range results {
		found[f.CheckID] = true
	}
	if !found[finding.CheckCVEOpenSSHRegreSSHion] {
		t.Errorf("expected CVE-2024-6387 for OpenSSH 9.1, got: %v", checkIDs(results))
	}
}

func TestCheckVersionCVEs_OpenSSHSafe(t *testing.T) {
	// OpenSSH 9.8 → should NOT match CVE-2024-6387 (max is 9.8, exclusive)
	results := CheckVersionCVEs("OpenSSH", "9.8", cveMakeF)
	for _, f := range results {
		if f.CheckID == finding.CheckCVEOpenSSHRegreSSHion {
			t.Errorf("OpenSSH 9.8 should NOT match CVE-2024-6387 (regreSSHion)")
		}
	}
}

func TestCheckVersionCVEs_OpenSSHTerrapin(t *testing.T) {
	// OpenSSH 9.1 should also match Terrapin (< 9.6) and username enum (< 7.8)?
	// No — 9.1 > 7.8, so only Terrapin and RegreSSHion.
	results := CheckVersionCVEs("OpenSSH", "9.1", cveMakeF)
	found := map[string]bool{}
	for _, f := range results {
		found[f.CheckID] = true
	}
	if !found[finding.CheckCVEOpenSSHTerrapin] {
		t.Errorf("expected CVE-2023-48795 (Terrapin) for OpenSSH 9.1, got: %v", checkIDs(results))
	}
	if found[finding.CheckCVEOpenSSHUsernameEnum] {
		t.Errorf("OpenSSH 9.1 should NOT match CVE-2018-15473 (username enum, < 7.8)")
	}
}

func TestCheckVersionCVEs_GrafanaVulnerable(t *testing.T) {
	// Grafana 8.3.0 → should match CVE-2021-43798 (8.0.0 – 8.3.1)
	results := CheckVersionCVEs("Grafana", "8.3.0", cveMakeF)
	found := map[string]bool{}
	for _, f := range results {
		found[f.CheckID] = true
	}
	if !found[finding.CheckCVEGrafanaPathTraversal] {
		t.Errorf("expected CVE-2021-43798 for Grafana 8.3.0, got: %v", checkIDs(results))
	}
}

func TestCheckVersionCVEs_GrafanaSafe(t *testing.T) {
	// Grafana 10.0 → should NOT match
	results := CheckVersionCVEs("Grafana", "10.0", cveMakeF)
	if len(results) > 0 {
		t.Errorf("expected no CVEs for Grafana 10.0, got: %v", checkIDs(results))
	}
}

func TestCheckVersionCVEs_JenkinsVulnerable(t *testing.T) {
	// Jenkins 2.440 → should match CVE-2024-23897 (< 2.442)
	results := CheckVersionCVEs("Jenkins", "2.440", cveMakeF)
	found := map[string]bool{}
	for _, f := range results {
		found[f.CheckID] = true
	}
	if !found[finding.CheckCVEJenkinsCLIFileRead] {
		t.Errorf("expected CVE-2024-23897 for Jenkins 2.440, got: %v", checkIDs(results))
	}
}

func TestCheckVersionCVEs_JenkinsSafe(t *testing.T) {
	// Jenkins 2.450 → should NOT match CVE-2024-23897 (< 2.442)
	results := CheckVersionCVEs("Jenkins", "2.450", cveMakeF)
	for _, f := range results {
		if f.CheckID == finding.CheckCVEJenkinsCLIFileRead {
			t.Errorf("Jenkins 2.450 should NOT match CVE-2024-23897")
		}
	}
}

func TestCheckVersionCVEs_ApacheTraversal(t *testing.T) {
	// Apache 2.4.49 should match both CVE-2021-41773 and CVE-2021-42013
	results := CheckVersionCVEs("Apache", "2.4.49", cveMakeF)
	found := map[string]bool{}
	for _, f := range results {
		found[f.CheckID] = true
	}
	if !found[finding.CheckCVEApacheTraversal2021] {
		t.Errorf("expected CVE-2021-41773 for Apache 2.4.49")
	}
	if !found[finding.CheckCVEApacheTraversalBypass2021] {
		t.Errorf("expected CVE-2021-42013 for Apache 2.4.49")
	}
}

func TestCheckVersionCVEs_ApacheSafe(t *testing.T) {
	// Apache 2.4.52 should NOT match
	results := CheckVersionCVEs("Apache", "2.4.52", cveMakeF)
	if len(results) > 0 {
		t.Errorf("expected no CVEs for Apache 2.4.52, got: %v", checkIDs(results))
	}
}

func TestCheckVersionCVEs_ElasticsearchGroovy(t *testing.T) {
	// Elasticsearch 1.3.0 should match CVE-2015-1427
	results := CheckVersionCVEs("elasticsearch", "1.3.0", cveMakeF)
	found := map[string]bool{}
	for _, f := range results {
		found[f.CheckID] = true
	}
	if !found[finding.CheckCVEElasticsearchGroovyRCE] {
		t.Errorf("expected CVE-2015-1427 for elasticsearch 1.3.0")
	}
}

func TestCheckVersionCVEs_MySQLAuthBypass(t *testing.T) {
	// MySQL 5.1.60 should match CVE-2012-2122
	results := CheckVersionCVEs("mysql", "5.1.60", cveMakeF)
	found := map[string]bool{}
	for _, f := range results {
		found[f.CheckID] = true
	}
	if !found[finding.CheckCVEMySQLAuthBypass2012] {
		t.Errorf("expected CVE-2012-2122 for MySQL 5.1.60, got: %v", checkIDs(results))
	}
}

func TestCheckVersionCVEs_PostgreSQLCopyRCE(t *testing.T) {
	results := CheckVersionCVEs("postgresql", "10.5", cveMakeF)
	found := map[string]bool{}
	for _, f := range results {
		found[f.CheckID] = true
	}
	if !found[finding.CheckCVEPostgreSQLCopyRCE2019] {
		t.Errorf("expected CVE-2019-9193 for PostgreSQL 10.5, got: %v", checkIDs(results))
	}
}

func TestCheckVersionCVEs_ActiveMQRCE(t *testing.T) {
	// ActiveMQ 5.16.5 should match CVE-2023-46604 (5.16.0–5.16.7)
	results := CheckVersionCVEs("activemq", "5.16.5", cveMakeF)
	found := map[string]bool{}
	for _, f := range results {
		found[f.CheckID] = true
	}
	if !found[finding.CheckCVEActiveMQRCE] {
		t.Errorf("expected CVE-2023-46604 for ActiveMQ 5.16.5, got: %v", checkIDs(results))
	}
}

func TestCheckVersionCVEs_EmptyInputs(t *testing.T) {
	if r := CheckVersionCVEs("", "1.0", cveMakeF); len(r) > 0 {
		t.Error("expected no results for empty service")
	}
	if r := CheckVersionCVEs("nginx", "", cveMakeF); len(r) > 0 {
		t.Error("expected no results for empty version")
	}
}

func TestCheckVersionCVEs_VersionWithSuffix(t *testing.T) {
	// Version strings with distro suffixes should be cleaned.
	// OpenSSH 9.1p1 → 9.1 (p stripped by versionBefore numeric parsing)
	results := CheckVersionCVEs("OpenSSH", "9.1p1", cveMakeF)
	found := map[string]bool{}
	for _, f := range results {
		found[f.CheckID] = true
	}
	if !found[finding.CheckCVEOpenSSHRegreSSHion] {
		t.Errorf("expected CVE-2024-6387 for OpenSSH 9.1p1, got: %v", checkIDs(results))
	}
}

func TestCheckVersionCVEs_VersionWithPrefix(t *testing.T) {
	// "v1.3.0" should be cleaned to "1.3.0"
	results := CheckVersionCVEs("elasticsearch", "v1.3.0", cveMakeF)
	found := map[string]bool{}
	for _, f := range results {
		found[f.CheckID] = true
	}
	if !found[finding.CheckCVEElasticsearchGroovyRCE] {
		t.Errorf("expected CVE-2015-1427 for elasticsearch v1.3.0, got: %v", checkIDs(results))
	}
}

func TestCheckVersionCVEs_ServiceAliases(t *testing.T) {
	// "httpd" should map to "apache"
	results := CheckVersionCVEs("httpd", "2.4.49", cveMakeF)
	found := map[string]bool{}
	for _, f := range results {
		found[f.CheckID] = true
	}
	if !found[finding.CheckCVEApacheTraversal2021] {
		t.Errorf("expected CVE-2021-41773 for httpd 2.4.49 (alias for apache)")
	}
}

func TestCheckVersionCVEs_Deduplication(t *testing.T) {
	// MySQL 5.1.60 should only produce one finding for CVE-2012-2122,
	// even though it matches the 5.1.x rule (not the 5.5.x one, but
	// the dedup logic should prevent duplicates if both somehow matched).
	results := CheckVersionCVEs("mysql", "5.1.60", cveMakeF)
	count := 0
	for _, f := range results {
		if f.CheckID == finding.CheckCVEMySQLAuthBypass2012 {
			count++
		}
	}
	if count > 1 {
		t.Errorf("expected at most 1 finding for CVE-2012-2122, got %d", count)
	}
}

func TestCheckVersionCVEs_Confidence(t *testing.T) {
	// All version-based CVE findings should have "probable" confidence.
	results := CheckVersionCVEs("nginx", "1.17.7", cveMakeF)
	for _, f := range results {
		if f.Confidence != finding.ConfidenceProbable {
			t.Errorf("expected confidence 'probable' for %s, got '%s'", f.CheckID, f.Confidence)
		}
	}
}

func TestCleanVersion(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"1.2.3", "1.2.3"},
		{"v1.2.3", "1.2.3"},
		{"V1.2.3", "1.2.3"},
		{"2.4.49-2ubuntu4", "2.4.49"},
		{"9.6p1", "9.6p1"},
		{"1.0+dfsg", "1.0"},
		{"  1.2.3  ", "1.2.3"},
	}
	for _, tt := range tests {
		got := cleanVersion(tt.input)
		if got != tt.want {
			t.Errorf("cleanVersion(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestVersionInRange(t *testing.T) {
	tests := []struct {
		ver, min, max string
		want          bool
	}{
		{"1.17.7", "", "1.21.0", true},
		{"1.25.0", "", "1.21.0", false},
		{"9.1", "8.5", "9.8", true},
		{"9.8", "8.5", "9.8", false},  // exclusive upper bound
		{"8.5", "8.5", "9.8", true},   // inclusive lower bound
		{"8.4", "8.5", "9.8", false},  // below min
		{"8.3.0", "8.0.0", "8.3.1", true},
		{"8.3.1", "8.0.0", "8.3.1", false}, // exclusive upper
		{"2.440", "", "2.442", true},
		{"2.450", "", "2.442", false},
	}
	for _, tt := range tests {
		got := versionInRange(tt.ver, tt.min, tt.max)
		if got != tt.want {
			t.Errorf("versionInRange(%q, %q, %q) = %v, want %v",
				tt.ver, tt.min, tt.max, got, tt.want)
		}
	}
}

func TestNormalizeService(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"nginx", "nginx"},
		{"Nginx", "nginx"},
		{"OpenSSH", "openssh"},
		{"httpd", "apache"},
		{"Apache", "apache"},
		{"MariaDB", "mysql"},
		{"unknown-thing", "unknown-thing"},
	}
	for _, tt := range tests {
		got := normalizeService(tt.input)
		if got != tt.want {
			t.Errorf("normalizeService(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// checkIDs extracts CheckIDs from a slice of findings for error messages.
func checkIDs(findings []finding.Finding) []string {
	ids := make([]string, len(findings))
	for i, f := range findings {
		ids[i] = f.CheckID
	}
	return ids
}
