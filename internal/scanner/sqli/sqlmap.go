package sqli

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
)

// runSQLMap shells out to sqlmap for deep exploitation after SQLi is detected.
// Only runs in ScanAuthorized mode. Returns nil if sqlmap is not installed or
// the --no-sqlmap flag was used (sqlmapBin == "").
func runSQLMap(ctx context.Context, targetURL, param, sqlmapBin string) ([]finding.Finding, error) {
	if sqlmapBin == "" {
		return nil, nil
	}

	// Check if sqlmap exists in PATH.
	binPath, err := exec.LookPath(sqlmapBin)
	if err != nil {
		return nil, nil // silently skip — optional tool
	}

	// Create a unique output directory based on URL + param hash.
	h := sha256.Sum256([]byte(targetURL + ":" + param))
	outputDir := filepath.Join(os.TempDir(), fmt.Sprintf("sqlmap-%x", h[:8]))

	args := []string{
		"-u", targetURL,
		"-p", param,
		"--batch",
		"--level=3",
		"--risk=2",
		"--dump",
		"--output-dir=" + outputDir,
		"--forms",
		"--threads=4",
	}

	cmd := exec.CommandContext(ctx, binPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// sqlmap returns non-zero on some conditions that aren't fatal.
		// If context was cancelled, propagate that.
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// Otherwise, log the failure but don't treat it as an error — the
		// native sqli post-exploit may have already found results.
	}

	var findings []finding.Finding

	// Parse sqlmap's output directory for extracted data.
	dumpDir := filepath.Join(outputDir, "dump")
	if entries, dirErr := os.ReadDir(dumpDir); dirErr == nil {
		for _, dbEntry := range entries {
			if !dbEntry.IsDir() {
				continue
			}
			dbPath := filepath.Join(dumpDir, dbEntry.Name())
			tables, _ := os.ReadDir(dbPath)
			for _, tableFile := range tables {
				if tableFile.IsDir() {
					continue
				}
				tablePath := filepath.Join(dbPath, tableFile.Name())
				data, readErr := os.ReadFile(tablePath)
				if readErr != nil || len(data) == 0 {
					continue
				}

				tableName := strings.TrimSuffix(tableFile.Name(), filepath.Ext(tableFile.Name()))
				rowCount := strings.Count(string(data), "\n")
				if rowCount > 0 {
					rowCount-- // header line
				}

				findings = append(findings, finding.Finding{
					CheckID:    finding.CheckExploitDataExtracted,
					Module:     "deep",
					Scanner:    scannerName,
					Severity:   finding.SeverityCritical,
					Confidence: finding.ConfidenceVerified,
					Title:      fmt.Sprintf("sqlmap extracted data from %s.%s (%d rows)", dbEntry.Name(), tableName, rowCount),
					Description: fmt.Sprintf(
						"sqlmap successfully dumped %d rows from table %q in database %q. "+
							"Full dump saved to %s.",
						rowCount, tableName, dbEntry.Name(), tablePath),
					Asset:    extractHost(targetURL),
					DeepOnly: true,
					Evidence: map[string]any{
						"tool":       "sqlmap",
						"database":   dbEntry.Name(),
						"table":      tableName,
						"row_count":  rowCount,
						"dump_path":  tablePath,
						"parameter":  param,
						"target_url": targetURL,
					},
					ProofCommand: fmt.Sprintf(
						"sqlmap -u '%s' -p '%s' --batch --level=3 --risk=2 --dump",
						targetURL, param),
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	// Also check sqlmap's stdout for injection confirmations when no dump was produced.
	if len(findings) == 0 && len(output) > 0 {
		outStr := string(output)
		if strings.Contains(outStr, "is vulnerable") || strings.Contains(outStr, "injectable") {
			findings = append(findings, finding.Finding{
				CheckID:    finding.CheckExploitDataExtracted,
				Module:     "deep",
				Scanner:    scannerName,
				Severity:   finding.SeverityHigh,
				Confidence: finding.ConfidenceVerified,
				Title:      fmt.Sprintf("sqlmap confirmed SQLi in parameter %s", param),
				Description: fmt.Sprintf(
					"sqlmap confirmed SQL injection vulnerability at %s in parameter %q. "+
						"No tables were dumped (target may have limited data or restricted queries).",
					targetURL, param),
				Asset:    extractHost(targetURL),
				DeepOnly: true,
				Evidence: map[string]any{
					"tool":       "sqlmap",
					"parameter":  param,
					"target_url": targetURL,
					"output_dir": outputDir,
				},
				ProofCommand: fmt.Sprintf(
					"sqlmap -u '%s' -p '%s' --batch --level=3 --risk=2",
					targetURL, param),
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings, nil
}

// extractHost pulls the host:port from a URL string.
func extractHost(rawURL string) string {
	// Simple extraction — avoid importing net/url just for this.
	s := rawURL
	if idx := strings.Index(s, "://"); idx != -1 {
		s = s[idx+3:]
	}
	if idx := strings.Index(s, "/"); idx != -1 {
		s = s[:idx]
	}
	return s
}

// SqlmapResult holds parsed sqlmap JSON output for testing.
type SqlmapResult struct {
	Database string `json:"database"`
	Table    string `json:"table"`
	Rows     int    `json:"rows"`
}

// parseSqlmapJSON parses sqlmap's JSON log format (if available).
func parseSqlmapJSON(data []byte) ([]SqlmapResult, error) {
	var results []SqlmapResult
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, err
	}
	return results, nil
}
