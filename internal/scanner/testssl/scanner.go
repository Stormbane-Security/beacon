// Package testssl wraps testssl.sh as a subprocess for deep TLS analysis.
// Only runs in deep scan mode. Checks cipher suites, protocol versions,
// and known TLS vulnerabilities (Heartbleed, POODLE, ROBOT, etc.).
package testssl

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
	"github.com/stormbane/beacon/internal/scanner/toolinstall"
)

const scannerName = "testssl"

// Scanner wraps the testssl.sh script.
type Scanner struct {
	bin string
}

func New(bin string) *Scanner { return &Scanner{bin: bin} }

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanDeep {
		return nil, nil // testssl only runs in deep mode
	}

	resolvedBin, err := toolinstall.EnsureTestssl(s.bin)
	if err != nil {
		return nil, fmt.Errorf("testssl: %w", err)
	}

	args := []string{
		"--jsonfile", "/dev/stdout",
		"--quiet",
		"--color", "0",
		"--nodns", "min",
		asset,
	}

	cmd := exec.CommandContext(ctx, resolvedBin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil && stdout.Len() == 0 {
		return nil, fmt.Errorf("testssl: %s", strings.TrimSpace(stderr.String()))
	}

	return parseOutput(asset, stdout.Bytes())
}

// testsslResult is a single entry from testssl.sh JSON output.
type testsslResult struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Finding  string `json:"finding"`
}

// testsslOutput is the top-level structure from testssl.sh --jsonfile output.
type testsslOutput struct {
	ScanResult []testsslResult `json:"scanResult"`
}

// idToCheckID maps testssl result IDs to canonical CheckIDs.
var idToCheckID = map[string]finding.CheckID{
	"SSLv2":       finding.CheckTLSProtocolSSLv2,
	"SSLv3":       finding.CheckTLSProtocolSSLv3,
	"TLS1":        finding.CheckTLSProtocolTLS10,
	"TLS1_1":      finding.CheckTLSProtocolTLS11,
	"HEARTBLEED":  finding.CheckTLSHeartbleed,
	"POODLE_SSL":  finding.CheckTLSPOODLE,
	"ROBOT":       finding.CheckTLSROBOT,
	"BEAST":       finding.CheckTLSBEAST,
	"RC4":         finding.CheckTLSWeakCipher,
	"EXPORT":      finding.CheckTLSWeakCipher,
	"LOW":         finding.CheckTLSWeakCipher,
	"3DES_IDEA":   finding.CheckTLSWeakCipher,
}

func parseOutput(asset string, data []byte) ([]finding.Finding, error) {
	// testssl.sh outputs multiple JSON objects or a single array — handle both
	var out testsslOutput
	var findings []finding.Finding

	if err := json.Unmarshal(data, &out); err != nil {
		// Try parsing as newline-delimited JSON objects.
		// Raise the token buffer to 1 MB — testssl finding strings can include
		// full certificate chains that exceed the default 64 KB limit, causing
		// scanner.Scan() to silently stop and drop findings.
		scanner := bufio.NewScanner(bytes.NewReader(data))
		scanner.Buffer(make([]byte, 0, 1<<20), 1<<20)
		for scanner.Scan() {
			var r testsslResult
			if err := json.Unmarshal(scanner.Bytes(), &r); err == nil {
				if f := resultToFinding(asset, r); f != nil {
					findings = append(findings, *f)
				}
			}
		}
		return findings, nil
	}

	for _, r := range out.ScanResult {
		if f := resultToFinding(asset, r); f != nil {
			findings = append(findings, *f)
		}
	}
	return findings, nil
}

func resultToFinding(asset string, r testsslResult) *finding.Finding {
	// Skip OK/informational results
	switch strings.ToLower(r.Severity) {
	case "ok", "info", "not tested", "not vulnerable":
		return nil
	}
	if r.Finding == "" || strings.EqualFold(r.Finding, "not vulnerable") {
		return nil
	}

	checkID, ok := idToCheckID[strings.ToUpper(r.ID)]
	if !ok {
		checkID = "tls.issue." + strings.ToLower(r.ID)
	}

	sev := finding.SeverityMedium
	switch strings.ToLower(r.Severity) {
	case "critical":
		sev = finding.SeverityCritical
	case "high":
		sev = finding.SeverityHigh
	case "low":
		sev = finding.SeverityLow
	}

	return &finding.Finding{
		CheckID:      checkID,
		Module:       "surface",
		Scanner:      scannerName,
		Severity:     sev,
		Title:        fmt.Sprintf("TLS issue: %s", r.ID),
		Description:  r.Finding,
		Asset:        asset,
		Evidence:     map[string]any{"testssl_id": r.ID, "finding": r.Finding, "severity": r.Severity},
		DeepOnly:     true,
		DiscoveredAt: time.Now(),
	}
}
