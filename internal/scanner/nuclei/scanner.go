// Package nuclei wraps the Nuclei CLI as a subprocess scanner.
// Nuclei is the primary scanner for TLS, DNS, HTTP headers, exposure,
// misconfiguration, web vulnerabilities, and subdomain takeover detection.
//
// # WAF interaction
//
// ScanAuthorized Nuclei templates include active exploit probes — fuzzing, path enumeration,
// and exploit PoC payloads.
// Active exploitation probes require ScanAuthorized mode (--authorized flag). These WILL trigger WAF managed rules and may
// result in a source-IP block for the duration of the scan or longer.
// Expected behaviour on WAF-protected targets:
//   - Cloudflare/AWS WAF: probe requests return 403 with a WAF challenge page.
//     Nuclei treats 403 as a non-match; template findings will be suppressed.
//   - Imperva/Akamai: may issue a CAPTCHA or silently drop probes.
//   - Rate-based rules: bursts of requests may trigger temporary 429 blocks.
//
// dos, crash, and destructive tags are always excluded (-etags) regardless of
// scan mode, as those templates could disrupt the target service.
package nuclei

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
	"github.com/stormbane/beacon/internal/scanner/toolinstall"
)

const scannerName = "nuclei"

const staleTemplateThreshold = 30 * 24 * time.Hour // 30 days

// Scanner wraps the nuclei binary as a subprocess.
type Scanner struct {
	bin         string
	surfaceList string // path to curated surface template IDs file
	deepList    string // path to deep template IDs file

	staleOnce    sync.Once
	staleWarning []finding.Finding // emitted once per Scanner instance
}

// New creates a Scanner. bin is the path to the nuclei binary.
func New(bin, surfaceList, deepList string) *Scanner {
	return &Scanner{bin: bin, surfaceList: surfaceList, deepList: deepList}
}

func (s *Scanner) Name() string { return scannerName }

// isValidHostname returns true if s is a well-formed RFC 1123 hostname safe
// to pass as a -target argument to the nuclei subprocess. Rejects anything
// containing hyphens at label boundaries, non-alnum characters, or sequences
// that could be interpreted as CLI flags (e.g. "--config").
func isValidHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for i, c := range label {
			switch {
			case c >= 'a' && c <= 'z':
			case c >= 'A' && c <= 'Z':
			case c >= '0' && c <= '9':
			case c == '-':
				if i == 0 || i == len(label)-1 {
					return false
				}
			default:
				return false
			}
		}
	}
	return true
}

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	// Validate asset is a well-formed hostname before passing to exec.
	// Prevents argument injection (e.g. "--config /etc/passwd") if a
	// malformed hostname slips through discovery filtering.
	if !isValidHostname(asset) {
		return nil, fmt.Errorf("nuclei: invalid hostname %q", asset)
	}
	// Check template freshness once per scanner instance (not per asset).
	s.staleOnce.Do(func() {
		age := s.TemplateAge()
		if age > staleTemplateThreshold {
			s.staleWarning = []finding.Finding{{
				CheckID:      finding.CheckNucleiStaleTemplates,
				Module:       "surface",
				Scanner:      scannerName,
				Severity:     finding.SeverityMedium,
				Title:        fmt.Sprintf("Nuclei templates are %.0f days old — update recommended", age.Hours()/24),
				Description:  "Nuclei vulnerability templates haven't been updated in over 30 days. New CVE checks added since then will not run. Run `nuclei -update-templates` to refresh.",
				Asset:        asset,
				DiscoveredAt: time.Now(),
			}}
		}
	})

	resolvedBin, err := toolinstall.Ensure(s.bin)
	if err != nil {
		return nil, fmt.Errorf("nuclei: %w", err)
	}

	templateList := s.surfaceList
	// Exploitation probes require --authorized (beyond --deep).
	if scanType == module.ScanAuthorized {
		templateList = s.deepList
	}

	args := []string{
		"-target", asset,
		"-tl", templateList, // template list file
		"-json-export", "-", // JSON output to stdout
		"-silent",
		"-no-color",
		"-timeout", "30",
		"-retries", "1",
		// Never run denial-of-service or crash templates regardless of mode.
		// These could disrupt the target service even with authorization.
		"-etags", "dos,crash,destructive",
	}

	cmd := exec.CommandContext(ctx, resolvedBin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// Nuclei exits non-zero when it finds issues — that's expected.
		// Only fail if stdout is empty and stderr has a real error.
		if stdout.Len() == 0 && stderr.Len() > 0 {
			return nil, fmt.Errorf("nuclei: %s", strings.TrimSpace(stderr.String()))
		}
	}

	findings, err := parseOutput(asset, stdout.Bytes())
	if err != nil {
		return nil, err
	}
	// Prepend the stale-template warning (emitted on first asset only via staleOnce).
	// We copy s.staleWarning into a fresh slice to avoid a data race: if two Run()
	// calls are concurrent and s.staleWarning's backing array has spare capacity,
	// append would write into it from two goroutines simultaneously.
	if len(s.staleWarning) == 0 {
		return findings, nil
	}
	result := make([]finding.Finding, len(s.staleWarning), len(s.staleWarning)+len(findings))
	copy(result, s.staleWarning)
	return append(result, findings...), nil
}

// TemplateAge returns the age of the nuclei templates directory, or -1 if it
// cannot be determined. Used to warn when templates are stale.
func (s *Scanner) TemplateAge() time.Duration {
	resolvedBin, err := toolinstall.Ensure(s.bin)
	if err != nil {
		return -1
	}
	// Nuclei stores templates in ~/.local/nuclei-templates by default.
	// We find the binary's parent, then look for nuclei-templates sibling dir.
	home, err := os.UserHomeDir()
	if err != nil {
		_ = resolvedBin
		return -1
	}
	candidates := []string{
		home + "/.local/nuclei-templates",
		home + "/nuclei-templates",
		home + "/.nuclei-templates",
	}
	for _, dir := range candidates {
		info, err := os.Stat(dir)
		if err == nil && info.IsDir() {
			return time.Since(info.ModTime())
		}
	}
	return -1
}

// RunWithTags runs nuclei against the asset using a specific set of tags
// instead of a template list file. Used by the playbook engine.
func (s *Scanner) RunWithTags(ctx context.Context, asset string, tags []string) ([]finding.Finding, error) {
	resolvedBin, err := toolinstall.Ensure(s.bin)
	if err != nil {
		return nil, fmt.Errorf("nuclei: %w", err)
	}

	args := []string{
		"-target", asset,
		"-tags", strings.Join(tags, ","),
		"-json-export", "-",
		"-silent",
		"-no-color",
		"-timeout", "30",
		"-retries", "1",
		"-etags", "dos,crash,destructive",
	}

	cmd := exec.CommandContext(ctx, resolvedBin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if stdout.Len() == 0 && stderr.Len() > 0 {
			return nil, fmt.Errorf("nuclei: %s", strings.TrimSpace(stderr.String()))
		}
	}

	return parseOutput(asset, stdout.Bytes())
}

// nucleiResult is the JSON structure emitted by nuclei -json-export.
type nucleiResult struct {
	TemplateID  string `json:"template-id"`
	Info        struct {
		Name        string `json:"name"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
	} `json:"info"`
	Host          string            `json:"host"`
	MatchedAt     string            `json:"matched-at"`
	ExtractedResults []string       `json:"extracted-results"`
	Meta          map[string]string `json:"meta"`
	Timestamp     time.Time         `json:"timestamp"`
}

func parseOutput(asset string, data []byte) ([]finding.Finding, error) {
	var findings []finding.Finding
	scanner := bufio.NewScanner(bytes.NewReader(data))

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var r nucleiResult
		if err := json.Unmarshal(line, &r); err != nil {
			continue // skip malformed lines
		}

		checkID := finding.MapNucleiTemplate(r.TemplateID)
		sev := finding.ParseSeverity(r.Info.Severity)

		evidence := map[string]any{
			"template_id":       r.TemplateID,
			"matched_at":        r.MatchedAt,
			"extracted_results": r.ExtractedResults,
			"meta":              r.Meta,
		}

		findings = append(findings, finding.Finding{
			CheckID:      checkID,
			Module:       "surface",
			Scanner:      scannerName,
			Severity:     sev,
			Title:        r.Info.Name,
			Description:  r.Info.Description,
			Asset:        asset,
			Evidence:     evidence,
			DiscoveredAt: r.Timestamp,
		})
	}

	return findings, scanner.Err()
}
