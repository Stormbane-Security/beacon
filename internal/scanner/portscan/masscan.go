package portscan

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// masscanRecord represents a single entry in masscan's JSON output.
type masscanRecord struct {
	IP    string        `json:"ip"`
	Ports []masscanPort `json:"ports"`
}

type masscanPort struct {
	Port     int    `json:"port"`
	Proto    string `json:"proto"`
	Status   string `json:"status"`
	Reason   string `json:"reason"`
	TTL      int    `json:"ttl"`
}

// runMasscan shells out to masscan for fast CIDR/subnet port scanning.
// Returns a list of "ip:port" strings for open ports found.
// Only for CIDR targets, not single hosts. Returns nil if masscan is not
// installed or the --no-masscan flag was used (masscanBin == "").
func runMasscan(ctx context.Context, cidr string, ports string, masscanBin string) ([]string, error) {
	if masscanBin == "" {
		return nil, nil
	}

	// Only use masscan for CIDR notation (contains "/").
	if !strings.Contains(cidr, "/") {
		return nil, nil
	}

	// Check if masscan exists in PATH.
	binPath, err := exec.LookPath(masscanBin)
	if err != nil {
		return nil, nil // silently skip — optional tool
	}

	// Create a unique output file based on target hash.
	h := sha256.Sum256([]byte(cidr + ":" + ports))
	outputFile := filepath.Join(os.TempDir(), fmt.Sprintf("masscan-%x.json", h[:8]))
	defer func() { _ = os.Remove(outputFile) }()

	args := []string{
		cidr,
		"-p" + ports,
		"--rate=1000",
		"-oJ", outputFile,
	}

	cmd := exec.CommandContext(ctx, binPath, args...)
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// masscan may fail for permissions (needs root for raw sockets).
		return nil, nil
	}

	return parseMasscanOutput(outputFile)
}

// parseMasscanOutput reads and parses masscan's JSON output file.
// Returns a list of "ip:port" strings.
func parseMasscanOutput(outputFile string) ([]string, error) {
	data, err := os.ReadFile(outputFile)
	if err != nil {
		return nil, nil
	}

	// masscan JSON output has a trailing comma issue and opening/closing
	// brackets. Clean it up for proper parsing.
	content := strings.TrimSpace(string(data))
	if content == "" {
		return nil, nil
	}

	// masscan outputs one JSON object per line between [ and ] with possible
	// trailing commas. Try parsing as-is first, then fix up if needed.
	var records []masscanRecord
	if err := json.Unmarshal([]byte(content), &records); err != nil {
		// Fix masscan's malformed JSON: strip trailing whitespace/commas,
		// remove the outer brackets, strip again, then re-wrap.
		fixed := strings.TrimPrefix(content, "[")
		fixed = strings.TrimSuffix(fixed, "]")
		fixed = strings.TrimRight(strings.TrimSpace(fixed), ",")
		fixed = "[" + fixed + "]"
		if err := json.Unmarshal([]byte(fixed), &records); err != nil {
			return nil, fmt.Errorf("parse masscan output: %w", err)
		}
	}

	var results []string
	seen := make(map[string]bool)
	for _, rec := range records {
		for _, p := range rec.Ports {
			if p.Status != "open" {
				continue
			}
			entry := rec.IP + ":" + strconv.Itoa(p.Port)
			if !seen[entry] {
				seen[entry] = true
				results = append(results, entry)
			}
		}
	}

	return results, nil
}
