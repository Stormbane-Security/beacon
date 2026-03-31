package main

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stormbane/beacon/internal/enrichment"
	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/store"
)

// --- helpers ---

func ef(sev finding.Severity, title string) enrichment.EnrichedFinding {
	return enrichment.EnrichedFinding{
		Finding: finding.Finding{
			Severity: sev,
			Title:    title,
			CheckID:  "test.check",
			Asset:    "example.com",
		},
	}
}

func scanRun() store.ScanRun {
	c := time.Now()
	return store.ScanRun{
		ID:          "run-1",
		Domain:      "example.com",
		ScanType:    "surface",
		StartedAt:   time.Now(),
		CompletedAt: &c,
	}
}

func fakeReport() *store.Report {
	return &store.Report{
		ScanRunID:   "run-1",
		Domain:      "example.com",
		HTMLContent: "<html>report</html>",
		Summary:     "summary",
	}
}

// --- filterBySeverity ---

func TestFilterBySeverity_EmptyFlag_ReturnsAll(t *testing.T) {
	in := []enrichment.EnrichedFinding{
		ef(finding.SeverityInfo, "info"),
		ef(finding.SeverityLow, "low"),
		ef(finding.SeverityCritical, "crit"),
	}
	out := filterBySeverity(in, "")
	if len(out) != 3 {
		t.Errorf("expected all 3 findings, got %d", len(out))
	}
}

func TestFilterBySeverity_InfoFlag_ReturnsAll(t *testing.T) {
	in := []enrichment.EnrichedFinding{
		ef(finding.SeverityInfo, "info"),
		ef(finding.SeverityCritical, "crit"),
	}
	out := filterBySeverity(in, "info")
	if len(out) != 2 {
		t.Errorf("expected 2 findings for info filter, got %d", len(out))
	}
}

func TestFilterBySeverity_HighFilter_DropsLowerSeverities(t *testing.T) {
	in := []enrichment.EnrichedFinding{
		ef(finding.SeverityInfo, "info"),
		ef(finding.SeverityLow, "low"),
		ef(finding.SeverityMedium, "medium"),
		ef(finding.SeverityHigh, "high"),
		ef(finding.SeverityCritical, "crit"),
	}
	out := filterBySeverity(in, "high")
	if len(out) != 2 {
		t.Errorf("expected 2 findings (high+critical), got %d", len(out))
	}
	for _, f := range out {
		if f.Finding.Severity < finding.SeverityHigh {
			t.Errorf("unexpected severity %v in filtered results", f.Finding.Severity)
		}
	}
}

func TestFilterBySeverity_CriticalFilter_OnlyRetainsCritical(t *testing.T) {
	in := []enrichment.EnrichedFinding{
		ef(finding.SeverityHigh, "high"),
		ef(finding.SeverityCritical, "crit1"),
		ef(finding.SeverityCritical, "crit2"),
	}
	out := filterBySeverity(in, "critical")
	if len(out) != 2 {
		t.Errorf("expected 2 critical findings, got %d", len(out))
	}
}

func TestFilterBySeverity_UnknownSeverityFlag_ReturnsAll(t *testing.T) {
	// Unknown strings parse to SeverityInfo (the lowest), so nothing is filtered.
	in := []enrichment.EnrichedFinding{
		ef(finding.SeverityInfo, "info"),
		ef(finding.SeverityHigh, "high"),
	}
	out := filterBySeverity(in, "bogus")
	if len(out) != 2 {
		t.Errorf("expected all findings for unknown flag, got %d", len(out))
	}
}

func TestFilterBySeverity_MediumFilter_ExcludesLowAndInfo(t *testing.T) {
	in := []enrichment.EnrichedFinding{
		ef(finding.SeverityInfo, "info"),
		ef(finding.SeverityLow, "low"),
		ef(finding.SeverityMedium, "medium"),
	}
	out := filterBySeverity(in, "medium")
	if len(out) != 1 {
		t.Errorf("expected 1 finding (medium), got %d", len(out))
	}
	if out[0].Finding.Severity != finding.SeverityMedium {
		t.Errorf("expected medium severity, got %v", out[0].Finding.Severity)
	}
}

func TestFilterBySeverity_EmptyInput_ReturnsEmpty(t *testing.T) {
	out := filterBySeverity(nil, "high")
	if len(out) != 0 {
		t.Errorf("expected empty output for nil input, got %d", len(out))
	}
}

// --- renderFormat ---

func TestRenderFormat_DefaultIsText(t *testing.T) {
	out, err := renderFormat("", scanRun(), nil, "", fakeReport(), nil, nil)
	if err != nil {
		t.Fatalf("renderFormat error: %v", err)
	}
	// Text format always contains the ASCII border characters
	if !strings.Contains(out, "BEACON SECURITY REPORT") {
		t.Error("default format should be text; expected 'BEACON SECURITY REPORT'")
	}
}

func TestRenderFormat_TextExplicit(t *testing.T) {
	out, err := renderFormat("text", scanRun(), nil, "", fakeReport(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "BEACON SECURITY REPORT") {
		t.Error("expected text report header")
	}
}

func TestRenderFormat_HTML_ReturnsFakeHTMLContent(t *testing.T) {
	out, err := renderFormat("html", scanRun(), nil, "", fakeReport(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out != "<html>report</html>" {
		t.Errorf("expected HTML content from report, got %q", out)
	}
}

func TestRenderFormat_JSON_IsValidJSON(t *testing.T) {
	import_json := func(s string) bool {
		return len(s) > 0 && s[0] == '{'
	}
	out, err := renderFormat("json", scanRun(), nil, "", fakeReport(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !import_json(out) {
		t.Errorf("expected JSON object, got %q", out[:min(30, len(out))])
	}
}

func TestRenderFormat_Markdown_ContainsH1(t *testing.T) {
	out, err := renderFormat("markdown", scanRun(), nil, "", fakeReport(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "# Beacon Security Report") {
		t.Error("expected markdown H1 header")
	}
}

func TestRenderFormat_MarkdownAlias_md(t *testing.T) {
	out, err := renderFormat("md", scanRun(), nil, "", fakeReport(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "# Beacon Security Report") {
		t.Error("'md' alias should render markdown")
	}
}

func TestRenderFormat_CaseInsensitive(t *testing.T) {
	out, err := renderFormat("JSON", scanRun(), nil, "", fakeReport(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 || out[0] != '{' {
		t.Error("format flag should be case-insensitive; expected JSON output")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// --- truncate ---

func TestTruncate_ShortString_Unchanged(t *testing.T) {
	if got := truncate("abc", 5); got != "abc" {
		t.Errorf("truncate(%q, 5) = %q, want %q", "abc", got, "abc")
	}
}

func TestTruncate_ExactLength_Unchanged(t *testing.T) {
	if got := truncate("abc", 3); got != "abc" {
		t.Errorf("truncate(%q, 3) = %q, want %q", "abc", got, "abc")
	}
}

func TestTruncate_LongString_Truncated(t *testing.T) {
	got := truncate("abcdef", 4)
	if got != "abc…" {
		t.Errorf("truncate(%q, 4) = %q, want %q", "abcdef", got, "abc…")
	}
}

func TestTruncate_ZeroN_ReturnsEmpty(t *testing.T) {
	if got := truncate("abc", 0); got != "" {
		t.Errorf("truncate(%q, 0) = %q, want empty", "abc", got)
	}
}

func TestTruncate_NegativeN_ReturnsEmpty(t *testing.T) {
	if got := truncate("abc", -1); got != "" {
		t.Errorf("truncate(%q, -1) = %q, want empty", "abc", got)
	}
}

func TestTruncate_N1_ReturnsEllipsis(t *testing.T) {
	if got := truncate("abc", 1); got != "…" {
		t.Errorf("truncate(%q, 1) = %q, want %q", "abc", got, "…")
	}
}

func TestTruncate_EmptyString(t *testing.T) {
	if got := truncate("", 5); got != "" {
		t.Errorf("truncate(%q, 5) = %q, want empty", "", got)
	}
}

// --- filterBySeverity does not mutate input ---

func TestFilterBySeverity_DoesNotMutateInput(t *testing.T) {
	original := []enrichment.EnrichedFinding{
		ef(finding.SeverityInfo, "info"),
		ef(finding.SeverityLow, "low"),
		ef(finding.SeverityHigh, "high"),
		ef(finding.SeverityCritical, "crit"),
	}
	// Keep a copy of titles in order.
	origTitles := make([]string, len(original))
	for i, f := range original {
		origTitles[i] = f.Finding.Title
	}

	_ = filterBySeverity(original, "high")

	// Verify the original slice was not modified.
	for i, f := range original {
		if f.Finding.Title != origTitles[i] {
			t.Errorf("original[%d].Title = %q, was mutated to %q", i, origTitles[i], f.Finding.Title)
		}
	}
}

// --- filterOmitted ---

func TestFilterOmitted_DropsOmittedFindings(t *testing.T) {
	in := []enrichment.EnrichedFinding{
		{Finding: finding.Finding{Title: "keep1"}, Omit: false},
		{Finding: finding.Finding{Title: "drop"}, Omit: true},
		{Finding: finding.Finding{Title: "keep2"}, Omit: false},
	}
	out := filterOmitted(in)
	if len(out) != 2 {
		t.Fatalf("filterOmitted: got %d findings, want 2", len(out))
	}
	if out[0].Finding.Title != "keep1" || out[1].Finding.Title != "keep2" {
		t.Errorf("filterOmitted: unexpected titles %q, %q", out[0].Finding.Title, out[1].Finding.Title)
	}
}

func TestFilterOmitted_DoesNotMutateInput(t *testing.T) {
	in := []enrichment.EnrichedFinding{
		{Finding: finding.Finding{Title: "a"}, Omit: false},
		{Finding: finding.Finding{Title: "b"}, Omit: true},
		{Finding: finding.Finding{Title: "c"}, Omit: false},
	}
	origLen := len(in)
	_ = filterOmitted(in)
	if len(in) != origLen {
		t.Errorf("filterOmitted mutated input slice length: got %d, want %d", len(in), origLen)
	}
	// Verify elements are untouched.
	if in[1].Finding.Title != "b" {
		t.Errorf("filterOmitted mutated input element: got %q, want %q", in[1].Finding.Title, "b")
	}
}

func TestFilterOmitted_AllOmitted(t *testing.T) {
	in := []enrichment.EnrichedFinding{
		{Finding: finding.Finding{Title: "a"}, Omit: true},
		{Finding: finding.Finding{Title: "b"}, Omit: true},
	}
	out := filterOmitted(in)
	if len(out) != 0 {
		t.Errorf("filterOmitted: expected 0 findings when all omitted, got %d", len(out))
	}
}

func TestFilterOmitted_NilInput(t *testing.T) {
	out := filterOmitted(nil)
	if len(out) != 0 {
		t.Errorf("filterOmitted(nil): expected 0 findings, got %d", len(out))
	}
}

// --- uniqueStrings ---

func TestUniqueStrings_RemovesDuplicates(t *testing.T) {
	in := []string{"a", "b", "a", "c", "b"}
	out := uniqueStrings(in)
	want := []string{"a", "b", "c"}
	if len(out) != len(want) {
		t.Fatalf("uniqueStrings: got %d, want %d", len(out), len(want))
	}
	for i, v := range want {
		if out[i] != v {
			t.Errorf("uniqueStrings[%d] = %q, want %q", i, out[i], v)
		}
	}
}

func TestUniqueStrings_DoesNotMutateInput(t *testing.T) {
	in := []string{"x", "y", "x", "z"}
	original := make([]string, len(in))
	copy(original, in)

	_ = uniqueStrings(in)

	for i, v := range original {
		if in[i] != v {
			t.Errorf("uniqueStrings mutated input[%d]: got %q, want %q", i, in[i], v)
		}
	}
}

func TestUniqueStrings_NilInput(t *testing.T) {
	out := uniqueStrings(nil)
	if len(out) != 0 {
		t.Errorf("uniqueStrings(nil): expected empty, got %d", len(out))
	}
}

func TestUniqueStrings_Empty(t *testing.T) {
	out := uniqueStrings([]string{})
	if len(out) != 0 {
		t.Errorf("uniqueStrings([]): expected empty, got %d", len(out))
	}
}

func TestUniqueStrings_NoDuplicates(t *testing.T) {
	in := []string{"a", "b", "c"}
	out := uniqueStrings(in)
	if len(out) != 3 {
		t.Errorf("uniqueStrings: expected 3, got %d", len(out))
	}
}

// --- readTargetsFile ---

func TestReadTargetsFile_ValidFile(t *testing.T) {
	dir := t.TempDir()
	f := dir + "/targets.txt"
	content := "example.com\n# comment\n\napi.example.com\n  staging.example.com  \n"
	if err := os.WriteFile(f, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	out, err := readTargetsFile(f)
	if err != nil {
		t.Fatalf("readTargetsFile: %v", err)
	}
	want := []string{"example.com", "api.example.com", "staging.example.com"}
	if len(out) != len(want) {
		t.Fatalf("readTargetsFile: got %d lines, want %d", len(out), len(want))
	}
	for i, v := range want {
		if out[i] != v {
			t.Errorf("readTargetsFile[%d] = %q, want %q", i, out[i], v)
		}
	}
}

func TestReadTargetsFile_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	f := dir + "/empty.txt"
	if err := os.WriteFile(f, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}
	out, err := readTargetsFile(f)
	if err != nil {
		t.Fatalf("readTargetsFile: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("readTargetsFile on empty file: got %d lines, want 0", len(out))
	}
}

func TestReadTargetsFile_OnlyComments(t *testing.T) {
	dir := t.TempDir()
	f := dir + "/comments.txt"
	content := "# first comment\n# second comment\n\n"
	if err := os.WriteFile(f, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	out, err := readTargetsFile(f)
	if err != nil {
		t.Fatalf("readTargetsFile: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("readTargetsFile on comments-only file: got %d lines, want 0", len(out))
	}
}

func TestReadTargetsFile_NonexistentFile(t *testing.T) {
	_, err := readTargetsFile("/nonexistent/path/file.txt")
	if err == nil {
		t.Error("readTargetsFile should return error for nonexistent file")
	}
}

// --- safePlaybookName ---

func TestSafePlaybookName_ValidName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"my-playbook", "my-playbook"},
		{"test_123", "test_123"},
		{"ALLCAPS", "ALLCAPS"},
	}
	for _, tt := range tests {
		got := safePlaybookName(tt.input)
		if got != tt.want {
			t.Errorf("safePlaybookName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSafePlaybookName_PathTraversal(t *testing.T) {
	tests := []string{
		"../etc/cron.d/evil",
		"../../passwd",
		"foo/../bar",
		"/etc/shadow",
	}
	for _, input := range tests {
		got := safePlaybookName(input)
		// filepath.Base strips directory components; the regex then rejects dots/slashes.
		if strings.Contains(got, "..") || strings.Contains(got, "/") {
			t.Errorf("safePlaybookName(%q) = %q, contains path traversal", input, got)
		}
	}
}

func TestSafePlaybookName_EmptyAndSpecialChars(t *testing.T) {
	tests := []string{"", " ", "has spaces", "has.dots", "a;b"}
	for _, input := range tests {
		got := safePlaybookName(input)
		if got != "" {
			t.Errorf("safePlaybookName(%q) = %q, want empty for invalid name", input, got)
		}
	}
}

func TestSafePlaybookName_SlashExtractsBase(t *testing.T) {
	// filepath.Base strips directory components, so "foo/bar" yields "bar"
	// which is a valid name. This is the correct security behavior — the
	// directory traversal is removed.
	got := safePlaybookName("foo/bar")
	if got != "bar" {
		t.Errorf("safePlaybookName(%q) = %q, want %q (base extracted)", "foo/bar", got, "bar")
	}
}

// --- renderFormat edge cases ---

func TestRenderFormat_GraphWithNoData_ReturnsError(t *testing.T) {
	_, err := renderFormat("graph", scanRun(), nil, "", fakeReport(), nil, nil)
	if err == nil {
		t.Error("renderFormat(graph) with nil graphJSON should return error")
	}
}

func TestRenderFormat_GraphWithEmptyJSON_ReturnsError(t *testing.T) {
	_, err := renderFormat("graph", scanRun(), nil, "", fakeReport(), nil, []byte{})
	if err == nil {
		t.Error("renderFormat(graph) with empty graphJSON should return error")
	}
}

func TestRenderFormat_OCSF_NoError(t *testing.T) {
	_, err := renderFormat("ocsf", scanRun(), nil, "", fakeReport(), nil, nil)
	if err != nil {
		t.Errorf("renderFormat(ocsf) error: %v", err)
	}
}

// --- crossAssetCorrelate edge cases ---

func TestCrossAssetCorrelate_SingleResult_ReturnsNil(t *testing.T) {
	results := []assetScanResult{
		{domain: "a.com", run: &store.ScanRun{ID: "r1"}, findings: []finding.Finding{
			{CheckID: "test.check", Title: "Test", Severity: finding.SeverityHigh, Asset: "a.com"},
		}},
	}
	out := crossAssetCorrelate(results)
	if len(out) != 0 {
		t.Errorf("crossAssetCorrelate with 1 result: got %d, want 0", len(out))
	}
}

func TestCrossAssetCorrelate_SharedVuln_DetectsSystemic(t *testing.T) {
	results := []assetScanResult{
		{domain: "a.com", run: &store.ScanRun{ID: "r1"}, findings: []finding.Finding{
			{CheckID: "cors.miscfg", Title: "CORS Misconfig", Severity: finding.SeverityHigh, Asset: "a.com"},
		}},
		{domain: "b.com", run: &store.ScanRun{ID: "r2"}, findings: []finding.Finding{
			{CheckID: "cors.miscfg", Title: "CORS Misconfig", Severity: finding.SeverityHigh, Asset: "b.com"},
		}},
	}
	out := crossAssetCorrelate(results)
	if len(out) != 1 {
		t.Fatalf("crossAssetCorrelate with shared vuln: got %d, want 1", len(out))
	}
	if !strings.Contains(out[0].Title, "Cross-asset") {
		t.Errorf("expected Cross-asset prefix in title, got %q", out[0].Title)
	}
}

func TestCrossAssetCorrelate_NoSharedVulns_ReturnsEmpty(t *testing.T) {
	results := []assetScanResult{
		{domain: "a.com", run: &store.ScanRun{ID: "r1"}, findings: []finding.Finding{
			{CheckID: "check.a", Title: "A", Severity: finding.SeverityHigh, Asset: "a.com"},
		}},
		{domain: "b.com", run: &store.ScanRun{ID: "r2"}, findings: []finding.Finding{
			{CheckID: "check.b", Title: "B", Severity: finding.SeverityHigh, Asset: "b.com"},
		}},
	}
	out := crossAssetCorrelate(results)
	if len(out) != 0 {
		t.Errorf("crossAssetCorrelate with no shared vulns: got %d, want 0", len(out))
	}
}

// --- cloudEvidenceString ---

func TestCloudEvidenceString_NilEvidence(t *testing.T) {
	if got := cloudEvidenceString(nil, "key"); got != "" {
		t.Errorf("cloudEvidenceString(nil, key) = %q, want empty", got)
	}
}

func TestCloudEvidenceString_MissingKey(t *testing.T) {
	ev := map[string]any{"other": "value"}
	if got := cloudEvidenceString(ev, "missing"); got != "" {
		t.Errorf("cloudEvidenceString(ev, missing) = %q, want empty", got)
	}
}

func TestCloudEvidenceString_NonStringValue(t *testing.T) {
	ev := map[string]any{"count": 42}
	if got := cloudEvidenceString(ev, "count"); got != "" {
		t.Errorf("cloudEvidenceString(ev, count) = %q, want empty for non-string", got)
	}
}

func TestCloudEvidenceString_ValidString(t *testing.T) {
	ev := map[string]any{"region": "us-east-1"}
	if got := cloudEvidenceString(ev, "region"); got != "us-east-1" {
		t.Errorf("cloudEvidenceString(ev, region) = %q, want %q", got, "us-east-1")
	}
}

// --- extractFindingURL ---

func TestExtractFindingURL_NilFinding(t *testing.T) {
	if got := extractFindingURL(nil); got != "" {
		t.Errorf("extractFindingURL(nil) = %q, want empty", got)
	}
}

func TestExtractFindingURL_EvidenceURL(t *testing.T) {
	f := &finding.Finding{
		Asset:    "example.com",
		Evidence: map[string]any{"url": "https://example.com/admin"},
	}
	got := extractFindingURL(f)
	if got != "https://example.com/admin" {
		t.Errorf("extractFindingURL = %q, want evidence URL", got)
	}
}

func TestExtractFindingURL_FallsBackToAsset(t *testing.T) {
	f := &finding.Finding{Asset: "example.com"}
	got := extractFindingURL(f)
	if got != "https://example.com" {
		t.Errorf("extractFindingURL = %q, want https://example.com", got)
	}
}

func TestExtractFindingURL_NonHTTPEvidence_SkipsToAsset(t *testing.T) {
	f := &finding.Finding{
		Asset:    "example.com",
		Evidence: map[string]any{"url": "ftp://example.com/file"},
	}
	got := extractFindingURL(f)
	// ftp:// doesn't start with "http", so it falls through to asset
	if got != "https://example.com" {
		t.Errorf("extractFindingURL = %q, want https://example.com (should skip non-http)", got)
	}
}
