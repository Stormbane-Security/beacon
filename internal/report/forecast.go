package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/enrichment"
	"github.com/stormbane/beacon/internal/store"
)

// forecastScanResult mirrors the Forecast API's scan ingestion format.
type forecastScanResult struct {
	ProjectID string            `json:"project_id"`
	Domain    string            `json:"domain"`
	ScanTime  time.Time         `json:"scan_time"`
	ScanMode  string            `json:"scan_mode"`
	Duration  float64           `json:"duration_seconds"`
	Findings  []forecastFinding `json:"findings"`
}

type forecastFinding struct {
	CheckID  string            `json:"check_id"`
	Asset    string            `json:"asset"`
	Title    string            `json:"title"`
	Severity string            `json:"severity"`
	Scanner  string            `json:"scanner"`
	Details  string            `json:"details,omitempty"`
	Proof    string            `json:"proof,omitempty"`
	Attrs    map[string]string `json:"attrs,omitempty"`
}

// SendToForecast pushes scan results to a Forecast instance.
// The forecastURL should be like "forecast://host:port/project-id" or
// "http://host:port" with projectID passed separately.
func SendToForecast(forecastURL, apiKey string, run store.ScanRun, enriched []enrichment.EnrichedFinding) error {
	// Parse the URL: forecast://host:port/project-id
	baseURL, projectID := parseForecastURL(forecastURL)
	if baseURL == "" || projectID == "" {
		return fmt.Errorf("invalid forecast URL %q — expected forecast://host:port/project-id", forecastURL)
	}

	// Build the scan result.
	result := forecastScanResult{
		ProjectID: projectID,
		Domain:    run.Domain,
		ScanTime:  time.Now().UTC(),
		ScanMode:  string(run.ScanType),
	}
	if run.CompletedAt != nil {
		result.Duration = run.CompletedAt.Sub(run.StartedAt).Seconds()
	}

	for _, ef := range enriched {
		f := ef.Finding
		ff := forecastFinding{
			CheckID:  string(f.CheckID),
			Asset:    f.Asset,
			Title:    f.Title,
			Severity: f.Severity.String(),
			Scanner:  f.Scanner,
			Details:  f.Description,
			Proof:    f.ProofCommand,
		}
		result.Findings = append(result.Findings, ff)
	}

	body, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("marshaling scan result: %w", err)
	}

	endpoint := baseURL + "/v1/scans"
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("sending to Forecast: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
		return fmt.Errorf("Forecast API HTTP %d: %s", resp.StatusCode, string(data))
	}
	return nil
}

// parseForecastURL parses "forecast://host:port/project-id" into baseURL and projectID.
func parseForecastURL(raw string) (baseURL, projectID string) {
	// Strip scheme.
	s := raw
	if strings.HasPrefix(s, "forecast://") {
		s = strings.TrimPrefix(s, "forecast://")
	} else if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		// Direct URL: http://host:port/project-id
		lastSlash := strings.LastIndex(s[strings.Index(s, "//")+2:], "/")
		if lastSlash < 0 {
			return "", ""
		}
		idx := strings.Index(s, "//") + 2 + lastSlash
		return s[:idx], s[idx+1:]
	} else {
		return "", ""
	}

	// s is now "host:port/project-id"
	slashIdx := strings.Index(s, "/")
	if slashIdx < 0 {
		return "", ""
	}
	host := s[:slashIdx]
	projectID = s[slashIdx+1:]
	if host == "" || projectID == "" {
		return "", ""
	}
	return "http://" + host, projectID
}
