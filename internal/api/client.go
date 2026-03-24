package api

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client is a typed HTTP client for the Beacon API.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// NewClient creates a Client for the given server URL and API key.
func NewClient(serverURL, apiKey string) *Client {
	return &Client{
		baseURL: strings.TrimRight(serverURL, "/"),
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// ScanResult is the response from POST /v1/scans.
type ScanResult struct {
	ScanRunID string `json:"scan_run_id"`
	Status    string `json:"status"`
	StreamURL string `json:"stream_url"`
}

// ScanRun is the response from GET /v1/scans/{id}.
type ScanRun struct {
	ID           string     `json:"id"`
	Domain       string     `json:"domain"`
	ScanType     string     `json:"scan_type"`
	Status       string     `json:"status"`
	FindingCount int        `json:"finding_count"`
	StartedAt    time.Time  `json:"started_at"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
	Error        string     `json:"error,omitempty"`
	RecentLogs   []string   `json:"recent_logs,omitempty"`
}

// SubmitScan submits a new scan job to the remote server.
func (c *Client) SubmitScan(domain string, deep, permissionConfirmed bool) (*ScanResult, error) {
	body, _ := json.Marshal(map[string]any{
		"domain":               domain,
		"deep":                 deep,
		"permission_confirmed": permissionConfirmed,
	})

	resp, err := c.do("POST", "/v1/scans", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		return nil, readAPIError(resp)
	}

	var result ScanResult
	return &result, json.NewDecoder(resp.Body).Decode(&result)
}

// GetScan fetches the current status of a scan.
func (c *Client) GetScan(scanRunID string) (*ScanRun, error) {
	resp, err := c.do("GET", "/v1/scans/"+scanRunID, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("scan %s not found", scanRunID)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, readAPIError(resp)
	}

	var run ScanRun
	return &run, json.NewDecoder(resp.Body).Decode(&run)
}

// StreamScan opens an SSE connection and calls onLine for each log line.
// Blocks until the scan completes or ctx is cancelled.
// Uses a separate long-lived HTTP client (no timeout).
func (c *Client) StreamScan(scanRunID string, onLine func(string)) error {
	req, err := http.NewRequest("GET", c.baseURL+"/v1/scans/"+scanRunID+"/stream", nil)
	if err != nil {
		return err
	}
	c.setHeaders(req)
	req.Header.Set("Accept", "text/event-stream")

	streamClient := &http.Client{Timeout: 0} // no timeout for SSE
	resp, err := streamClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return readAPIError(resp)
	}

	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "data: ") {
			data := strings.TrimPrefix(line, "data: ")
			if data != "" {
				onLine(data)
			}
		}
		if strings.HasPrefix(line, "event: done") {
			return nil
		}
	}
	return sc.Err()
}

// GetReport fetches the HTML report for a completed scan.
func (c *Client) GetReport(scanRunID string) (string, error) {
	resp, err := c.do("GET", "/v1/scans/"+scanRunID+"/report", nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("report not ready — scan may still be running")
	}
	if resp.StatusCode != http.StatusOK {
		return "", readAPIError(resp)
	}

	body, err := io.ReadAll(resp.Body)
	return string(body), err
}

// ListScans returns all scans for a domain.
func (c *Client) ListScans(domain string) ([]ScanRun, error) {
	resp, err := c.do("GET", "/v1/scans?domain="+url.QueryEscape(domain), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, readAPIError(resp)
	}

	var result struct {
		Scans []ScanRun `json:"scans"`
	}
	return result.Scans, json.NewDecoder(resp.Body).Decode(&result)
}

// Healthz checks that the server is reachable.
func (c *Client) Healthz() error {
	resp, err := c.do("GET", "/healthz", nil)
	if err != nil {
		return fmt.Errorf("server unreachable: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server unhealthy: status %d", resp.StatusCode)
	}
	return nil
}

// ── internal ──────────────────────────────────────────────────────────────────

func (c *Client) do(method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, c.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	c.setHeaders(req)
	return c.httpClient.Do(req)
}

func (c *Client) setHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
}

func readAPIError(resp *http.Response) error {
	var e struct {
		Error string `json:"error"`
	}
	body, _ := io.ReadAll(resp.Body)
	if json.Unmarshal(body, &e) == nil && e.Error != "" {
		return fmt.Errorf("API error (%d): %s", resp.StatusCode, e.Error)
	}
	return fmt.Errorf("API error: status %d", resp.StatusCode)
}
