package vulndb

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Client talks to a running beacon-vulndb server.
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

// NewClient creates a Client pointing at the given base URL.
func NewClient(baseURL string) *Client {
	return &Client{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// QueryCVEs returns CVE entries matching the given service and version.
func (c *Client) QueryCVEs(service, version string) ([]CVEEntry, error) {
	params := url.Values{"service": {service}}
	if version != "" {
		params.Set("version", version)
	}
	var out []CVEEntry
	if err := c.getJSON("/api/cves?"+params.Encode(), &out); err != nil {
		return nil, err
	}
	return out, nil
}

// QueryCVEsByEcosystem returns CVEs for a specific ecosystem + package.
func (c *Client) QueryCVEsByEcosystem(ecosystem, pkg, version string) ([]CVEEntry, error) {
	params := url.Values{"ecosystem": {ecosystem}, "package": {pkg}}
	if version != "" {
		params.Set("version", version)
	}
	var out []CVEEntry
	if err := c.getJSON("/api/cves?"+params.Encode(), &out); err != nil {
		return nil, err
	}
	return out, nil
}

// QueryPayloads returns verified payloads for a service+version.
func (c *Client) QueryPayloads(service, version string) ([]VerifiedPayload, error) {
	params := url.Values{"service": {service}}
	if version != "" {
		params.Set("version", version)
	}
	var out []VerifiedPayload
	if err := c.getJSON("/api/payloads?"+params.Encode(), &out); err != nil {
		return nil, err
	}
	return out, nil
}

// QueryFingerprints returns fingerprints for a domain.
func (c *Client) QueryFingerprints(domain string) ([]ServiceFingerprint, error) {
	var out []ServiceFingerprint
	if err := c.getJSON("/api/fingerprints?domain="+url.QueryEscape(domain), &out); err != nil {
		return nil, err
	}
	return out, nil
}

// UploadFindings sends scan results to the vulndb.
func (c *Client) UploadFindings(domain string, findingsJSON []byte) error {
	body := map[string]any{
		"domain":   domain,
		"findings": json.RawMessage(findingsJSON),
	}
	return c.postJSON("/api/findings", body)
}

// SavePayload stores a verified payload.
func (c *Client) SavePayload(payload VerifiedPayload) error {
	return c.postJSON("/api/payloads", payload)
}

// Stats returns aggregate database statistics.
func (c *Client) Stats() (DBStats, error) {
	var out DBStats
	if err := c.getJSON("/api/stats", &out); err != nil {
		return out, err
	}
	return out, nil
}

func (c *Client) getJSON(path string, dest any) error {
	resp, err := c.HTTPClient.Get(c.BaseURL + path)
	if err != nil {
		return fmt.Errorf("vulndb client: GET %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("vulndb client: GET %s: %d: %s", path, resp.StatusCode, string(b))
	}
	return json.NewDecoder(resp.Body).Decode(dest)
}

func (c *Client) postJSON(path string, body any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	resp, err := c.HTTPClient.Post(c.BaseURL+path, "application/json",
		bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("vulndb client: POST %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("vulndb client: POST %s: %d: %s", path, resp.StatusCode, string(b))
	}
	return nil
}

// SaveFingerprint stores a service fingerprint.
func (c *Client) SaveFingerprint(fp ServiceFingerprint) error {
	body, err := json.Marshal(fp)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", c.BaseURL+"/api/fingerprints", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("vulndb: save fingerprint: %d", resp.StatusCode)
	}
	return nil
}
