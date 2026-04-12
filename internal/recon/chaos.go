// Package recon provides bug bounty reconnaissance utilities:
// Chaos API integration, scope management, and target list handling.
package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ChaosProgram represents a bug bounty program from the ProjectDiscovery Chaos dataset.
type ChaosProgram struct {
	Name       string   `json:"name"`
	URL        string   `json:"URL"`
	Bounty     bool     `json:"bounty"`
	Domains    []string `json:"domains"`
	IsNew      bool     `json:"is_new"`
	Platform   string   `json:"platform"`
	LastUpdate string   `json:"last_updated"`
}

const chaosIndexURL = "https://chaos-data.projectdiscovery.io/index.json"

// FetchChaosPrograms returns the full list of bug bounty programs from the
// ProjectDiscovery Chaos public index. The index is freely available without
// authentication.
func FetchChaosPrograms(ctx context.Context) ([]ChaosProgram, error) {
	client := &http.Client{Timeout: 30 * time.Second}

	req, err := http.NewRequestWithContext(ctx, "GET", chaosIndexURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "beacon-scanner/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("chaos: fetch index: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("chaos: HTTP %d fetching index", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("chaos: read index: %w", err)
	}

	var programs []ChaosProgram
	if err := json.Unmarshal(body, &programs); err != nil {
		return nil, fmt.Errorf("chaos: parse index: %w", err)
	}
	return programs, nil
}

// FindChaosProgram searches the Chaos index for a program matching the given
// name (case-insensitive substring match). Returns nil if not found.
func FindChaosProgram(ctx context.Context, name string) (*ChaosProgram, error) {
	programs, err := FetchChaosPrograms(ctx)
	if err != nil {
		return nil, err
	}

	name = strings.ToLower(name)
	for i := range programs {
		if strings.EqualFold(programs[i].Name, name) {
			return &programs[i], nil
		}
	}
	// Substring match as fallback.
	for i := range programs {
		if strings.Contains(strings.ToLower(programs[i].Name), name) {
			return &programs[i], nil
		}
	}
	return nil, fmt.Errorf("chaos: program %q not found", name)
}

// FetchChaosDomains returns all in-scope subdomains for a Chaos program.
// It first checks for a local dataset file at ~/.beacon/chaos/<program>.txt,
// then falls back to querying the program's domain list from the index.
func FetchChaosDomains(ctx context.Context, program string) ([]string, error) {
	// Check local dataset first.
	if domains, err := loadLocalChaos(program); err == nil && len(domains) > 0 {
		return domains, nil
	}

	// Fall back to the Chaos index — programs list their root domains
	// which we return as the target list.
	prog, err := FindChaosProgram(ctx, program)
	if err != nil {
		return nil, err
	}
	if len(prog.Domains) == 0 {
		return nil, fmt.Errorf("chaos: program %q has no domains listed", program)
	}
	return prog.Domains, nil
}

// loadLocalChaos reads a local Chaos dataset file from ~/.beacon/chaos/<program>.txt.
// Returns nil, nil if the file doesn't exist.
func loadLocalChaos(program string) ([]string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	// Sanitize program name to prevent path traversal.
	safe := filepath.Base(program)
	path := filepath.Join(homeDir, ".beacon", "chaos", safe+".txt")

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var domains []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			domains = append(domains, line)
		}
	}
	return domains, nil
}
