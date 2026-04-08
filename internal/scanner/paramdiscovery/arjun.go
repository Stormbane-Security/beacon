package paramdiscovery

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
)

// arjunOutput represents the JSON output from arjun.
// The format is: { "url": ["param1", "param2", ...], ... }
type arjunOutput map[string][]string

// runArjun shells out to arjun for parameter discovery using its battle-tested
// wordlists. Returns discovered parameter names. Returns nil if arjun is not
// installed or the --no-arjun flag was used (arjunBin == "").
// When wordlistPath is non-empty, arjun uses that file as its wordlist (-w flag).
func runArjun(ctx context.Context, targetURL string, arjunBin string, wordlistPath string) ([]string, error) {
	if arjunBin == "" {
		return nil, nil
	}

	// Check if arjun exists in PATH.
	binPath, err := exec.LookPath(arjunBin)
	if err != nil {
		return nil, nil // silently skip — optional tool
	}

	// Create a unique output file based on URL hash.
	h := sha256.Sum256([]byte(targetURL))
	outputFile := filepath.Join(os.TempDir(), fmt.Sprintf("arjun-%x.json", h[:8]))
	defer func() { _ = os.Remove(outputFile) }()

	args := []string{
		"-u", targetURL,
		"--stable",
		"-oJ", outputFile,
	}
	if wordlistPath != "" {
		args = append(args, "-w", wordlistPath)
	}

	cmd := exec.CommandContext(ctx, binPath, args...)
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// arjun may fail for various reasons (network, target down, etc.).
		return nil, nil
	}

	return parseArjunOutput(outputFile)
}

// parseArjunOutput reads and parses arjun's JSON output file.
// Returns a deduplicated, sorted list of discovered parameter names.
func parseArjunOutput(outputFile string) ([]string, error) {
	data, err := os.ReadFile(outputFile)
	if err != nil {
		return nil, nil
	}

	var result arjunOutput
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("parse arjun output: %w", err)
	}

	// Collect all parameters across all URLs (arjun may report multiple endpoints).
	seen := make(map[string]struct{})
	for _, params := range result {
		for _, p := range params {
			seen[p] = struct{}{}
		}
	}

	params := make([]string, 0, len(seen))
	for p := range seen {
		params = append(params, p)
	}
	sort.Strings(params)
	return params, nil
}
