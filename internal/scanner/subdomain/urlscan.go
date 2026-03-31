package subdomain

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"strings"
	"time"
)

// urlscanSubdomains queries the urlscan.io passive search index for subdomains
// of domain. No API key is required for the basic search endpoint.
func urlscanSubdomains(ctx context.Context, domain string) []string {
	url := fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s&size=100", neturl.QueryEscape(domain))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon Security Scanner)")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil
	}

	var response struct {
		Results []struct {
			Page struct {
				Domain string `json:"domain"`
			} `json:"page"`
			Task struct {
				Domain string `json:"domain"`
			} `json:"task"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil
	}

	suffix := "." + domain
	seen := make(map[string]struct{})
	var subs []string

	add := func(candidate string) {
		candidate = strings.ToLower(strings.TrimSpace(candidate))
		if candidate == "" {
			return
		}
		if !strings.HasSuffix(candidate, suffix) {
			return
		}
		if _, ok := seen[candidate]; ok {
			return
		}
		seen[candidate] = struct{}{}
		subs = append(subs, candidate)
	}

	for _, r := range response.Results {
		add(r.Page.Domain)
		add(r.Task.Domain)
	}

	return subs
}
