package classify

import (
	"strings"
	"testing"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/playbook"
)

// ── CheckVersions ─────────────────────────────────────────────────────────────

func TestCheckVersions_EOLApache22(t *testing.T) {
	ev := playbook.Evidence{
		ServiceVersions: map[string]string{"web_server": "Apache/2.2.34 (Ubuntu)"},
	}
	fs := CheckVersions(ev, "example.com")
	if len(fs) == 0 {
		t.Fatal("expected a finding for Apache/2.2.x (EOL), got none")
	}
	if fs[0].CheckID != finding.CheckVersionOutdated {
		t.Errorf("CheckID = %q; want %q", fs[0].CheckID, finding.CheckVersionOutdated)
	}
	if fs[0].Severity != finding.SeverityHigh {
		t.Errorf("Severity = %v; want High", fs[0].Severity)
	}
}

func TestCheckVersions_EOLPHP5(t *testing.T) {
	ev := playbook.Evidence{
		ServiceVersions: map[string]string{"powered_by": "PHP/5.6.40"},
	}
	fs := CheckVersions(ev, "example.com")
	if len(fs) == 0 {
		t.Fatal("expected a finding for PHP/5.x (EOL), got none")
	}
}

func TestCheckVersions_EOLPHP74(t *testing.T) {
	ev := playbook.Evidence{
		ServiceVersions: map[string]string{"powered_by": "PHP/7.4.33"},
	}
	fs := CheckVersions(ev, "example.com")
	if len(fs) == 0 {
		t.Fatal("expected a finding for PHP/7.4 (EOL Dec 2022), got none")
	}
}

func TestCheckVersions_CurrentPHP8NoFinding(t *testing.T) {
	ev := playbook.Evidence{
		ServiceVersions: map[string]string{"powered_by": "PHP/8.2.10"},
	}
	fs := CheckVersions(ev, "example.com")
	if len(fs) != 0 {
		t.Errorf("expected no finding for supported PHP/8.2, got %d", len(fs))
	}
}

func TestCheckVersions_CurrentNginxNoFinding(t *testing.T) {
	ev := playbook.Evidence{
		ServiceVersions: map[string]string{"web_server": "nginx/1.24.0"},
	}
	fs := CheckVersions(ev, "example.com")
	if len(fs) != 0 {
		t.Errorf("expected no finding for current nginx/1.24.0, got %d", len(fs))
	}
}

func TestCheckVersions_EOLNginx118(t *testing.T) {
	ev := playbook.Evidence{
		ServiceVersions: map[string]string{"web_server": "nginx/1.18.0"},
	}
	fs := CheckVersions(ev, "example.com")
	if len(fs) == 0 {
		t.Fatal("expected a finding for EOL nginx/1.18.x, got none")
	}
}

func TestCheckVersions_EOLIIS6(t *testing.T) {
	ev := playbook.Evidence{
		ServiceVersions: map[string]string{"web_server": "Microsoft-IIS/6.0"},
	}
	fs := CheckVersions(ev, "example.com")
	if len(fs) == 0 {
		t.Fatal("expected a finding for EOL IIS 6.0, got none")
	}
}

func TestCheckVersions_NoVersionsNoFindings(t *testing.T) {
	ev := playbook.Evidence{}
	fs := CheckVersions(ev, "example.com")
	if len(fs) != 0 {
		t.Errorf("expected 0 findings for empty Evidence, got %d", len(fs))
	}
}

func TestCheckVersions_AssetInFinding(t *testing.T) {
	ev := playbook.Evidence{
		ServiceVersions: map[string]string{"web_server": "Apache/2.2.34"},
	}
	fs := CheckVersions(ev, "target.example.com")
	if len(fs) == 0 {
		t.Fatal("expected finding")
	}
	if fs[0].Asset != "target.example.com" {
		t.Errorf("Asset = %q; want target.example.com", fs[0].Asset)
	}
}

// ── VersionNucleiTags ─────────────────────────────────────────────────────────

func TestVersionNucleiTags_ApacheDetected(t *testing.T) {
	ev := playbook.Evidence{
		ServiceVersions: map[string]string{"web_server": "Apache/2.4.54"},
	}
	tags := VersionNucleiTags(ev)
	if !containsStr(tags, "apache") {
		t.Errorf("expected 'apache' tag, got %v", tags)
	}
}

func TestVersionNucleiTags_PHPDetected(t *testing.T) {
	ev := playbook.Evidence{
		ServiceVersions: map[string]string{"powered_by": "PHP/8.1.12"},
	}
	tags := VersionNucleiTags(ev)
	if !containsStr(tags, "php") {
		t.Errorf("expected 'php' tag, got %v", tags)
	}
}

func TestVersionNucleiTags_WordPressFromMeta(t *testing.T) {
	ev := playbook.Evidence{
		ServiceVersions: map[string]string{"generator_meta": "WordPress 6.4.3"},
	}
	tags := VersionNucleiTags(ev)
	if !containsStr(tags, "wordpress") {
		t.Errorf("expected 'wordpress' tag, got %v", tags)
	}
	if !containsStr(tags, "wp") {
		t.Errorf("expected 'wp' tag, got %v", tags)
	}
}

func TestVersionNucleiTags_WordPressFromBody(t *testing.T) {
	ev := playbook.Evidence{
		Body512: `<link rel="stylesheet" href="/wp-content/themes/twentytwenty/style.css">`,
	}
	tags := VersionNucleiTags(ev)
	if !containsStr(tags, "wordpress") {
		t.Errorf("expected 'wordpress' tag from body wp-content signal, got %v", tags)
	}
}

func TestVersionNucleiTags_NoDuplicates(t *testing.T) {
	// Both generator_meta and cookie_tech signal WordPress — should only appear once.
	ev := playbook.Evidence{
		ServiceVersions: map[string]string{
			"generator_meta": "WordPress 6.0",
			"cookie_tech":    "WordPress",
		},
	}
	tags := VersionNucleiTags(ev)
	count := 0
	for _, t := range tags {
		if t == "wordpress" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("'wordpress' tag appeared %d times; want exactly 1", count)
	}
}

func TestVersionNucleiTags_EmptyEvidenceReturnsNil(t *testing.T) {
	ev := playbook.Evidence{}
	tags := VersionNucleiTags(ev)
	if len(tags) != 0 {
		t.Errorf("expected no tags for empty evidence, got %v", tags)
	}
}

func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

// ── extractMetaGenerator ──────────────────────────────────────────────────────

func TestExtractMetaGenerator_NameFirst(t *testing.T) {
	html := `<meta name="generator" content="WordPress 6.4.3" />`
	got := extractMetaGenerator(html)
	if got != "WordPress 6.4.3" {
		t.Errorf("got %q; want WordPress 6.4.3", got)
	}
}

func TestExtractMetaGenerator_ContentFirst(t *testing.T) {
	html := `<meta content="Joomla! - Open Source Content Management" name="generator">`
	got := extractMetaGenerator(html)
	if got != "Joomla! - Open Source Content Management" {
		t.Errorf("got %q", got)
	}
}

func TestExtractMetaGenerator_CaseInsensitive(t *testing.T) {
	html := `<META NAME="GENERATOR" CONTENT="Drupal 10">`
	got := extractMetaGenerator(html)
	if got != "Drupal 10" {
		t.Errorf("got %q; want Drupal 10", got)
	}
}

func TestExtractMetaGenerator_Missing(t *testing.T) {
	html := `<html><head><title>No generator</title></head></html>`
	got := extractMetaGenerator(html)
	if got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

// ── probeRobotsTxt parsing ────────────────────────────────────────────────────

func TestRobotsTxtParsing(t *testing.T) {
	// Test the parsing logic directly by calling the path-extraction inline.
	// Full integration (with mock HTTP) is covered in classify_test.go.
	robotsBody := `User-agent: *
Disallow: /admin/
Disallow: /private/data
Disallow: /wp-admin
Disallow: /
Disallow: *wildcard*
Disallow:
Allow: /public/
`
	paths := parseRobotsTxtBody(robotsBody)

	// Should include /admin/, /private/data, /wp-admin
	want := map[string]bool{"/admin/": true, "/private/data": true, "/wp-admin": true}
	for _, p := range paths {
		if _, ok := want[p]; ok {
			delete(want, p)
		}
	}
	if len(want) != 0 {
		t.Errorf("missing paths: %v (got %v)", want, paths)
	}

	// Should NOT include "/" (root), wildcards, empty, or Allow entries
	for _, p := range paths {
		if p == "/" {
			t.Error("root / should not be included")
		}
		if strings.Contains(p, "*") {
			t.Errorf("wildcard path should not be included: %q", p)
		}
	}
}
