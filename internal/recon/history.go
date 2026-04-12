package recon

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
)

// HistoryEntry is a persisted scan result for cross-run dedup.
type HistoryEntry struct {
	ScanID      string            `json:"scan_id"`
	Domain      string            `json:"domain"`
	CompletedAt time.Time         `json:"completed_at"`
	Findings    []finding.Finding `json:"findings"`
}

// FindingKey produces a comparison key for cross-run dedup.
// The key combines check_id + asset + evidence_hash so that the same
// vulnerability on the same asset with the same evidence is considered
// a duplicate across runs.
func FindingKey(f finding.Finding) string {
	return string(f.CheckID) + "|" + f.Asset + "|" + EvidenceHash(f)
}

// EvidenceHash produces a stable hash of the significant evidence fields.
// Minor evidence variations (timestamps, request IDs) are excluded so that
// repeat occurrences of the same vulnerability are correctly identified.
func EvidenceHash(f finding.Finding) string {
	if f.Evidence == nil {
		return "empty"
	}

	// Extract the stable evidence fields that identify this specific finding.
	stable := make(map[string]any)
	for _, key := range []string{
		"path", "port", "parameter", "url", "endpoint",
		"status_code", "method", "header", "value",
		"bucket_url", "cname", "nameserver",
		"protocol", "cipher", "version",
	} {
		if v, ok := f.Evidence[key]; ok {
			stable[key] = v
		}
	}

	// If no stable keys matched, hash all evidence.
	if len(stable) == 0 {
		stable = f.Evidence
	}

	b, _ := json.Marshal(stable)
	h := sha256.Sum256(b)
	return fmt.Sprintf("%x", h[:8])
}

// historyDir returns the path to ~/.beacon/history/<domain>/.
func historyDir(domain string) (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	// Sanitize domain to prevent path traversal.
	safe := strings.ReplaceAll(domain, "/", "_")
	safe = strings.ReplaceAll(safe, "..", "_")
	return filepath.Join(homeDir, ".beacon", "history", safe), nil
}

// SaveScanHistory persists a scan's findings to the history directory.
func SaveScanHistory(scanID, domain string, findings []finding.Finding) error {
	dir, err := historyDir(domain)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	entry := HistoryEntry{
		ScanID:      scanID,
		Domain:      domain,
		CompletedAt: time.Now(),
		Findings:    findings,
	}

	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return err
	}

	path := filepath.Join(dir, scanID+".json")
	return os.WriteFile(path, data, 0o600)
}

// LoadScanHistory loads a specific scan history entry.
func LoadScanHistory(domain, scanID string) (*HistoryEntry, error) {
	dir, err := historyDir(domain)
	if err != nil {
		return nil, err
	}

	path := filepath.Join(dir, scanID+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var entry HistoryEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

// ListScanHistory returns all history entries for a domain, sorted by
// completion time (most recent first).
func ListScanHistory(domain string) ([]HistoryEntry, error) {
	dir, err := historyDir(domain)
	if err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var history []HistoryEntry
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var entry HistoryEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			continue
		}
		history = append(history, entry)
	}

	sort.Slice(history, func(i, j int) bool {
		return history[i].CompletedAt.After(history[j].CompletedAt)
	})
	return history, nil
}

// LatestScanHistory returns the most recent history entry for a domain,
// or nil if no history exists.
func LatestScanHistory(domain string) (*HistoryEntry, error) {
	history, err := ListScanHistory(domain)
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		return nil, nil
	}
	return &history[0], nil
}

// FilterNewFindings returns only findings that were NOT present in the
// previous scan of the same domain. Comparison uses FindingKey (check_id +
// asset + evidence_hash).
func FilterNewFindings(current []finding.Finding, previous []finding.Finding) []finding.Finding {
	if len(previous) == 0 {
		return current
	}

	prevKeys := make(map[string]bool, len(previous))
	for _, f := range previous {
		prevKeys[FindingKey(f)] = true
	}

	var newFindings []finding.Finding
	for _, f := range current {
		if !prevKeys[FindingKey(f)] {
			newFindings = append(newFindings, f)
		}
	}
	return newFindings
}
