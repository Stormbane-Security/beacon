package subdomain

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// otxSubdomains queries the AlienVault OTX passive DNS API for subdomains of
// domain. apiKey must be a valid OTX API key; if empty the function returns nil.
func otxSubdomains(ctx context.Context, domain, apiKey string) []string {
	if apiKey == "" {
		return nil
	}

	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("X-OTX-API-KEY", apiKey)
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon Security Scanner)")

	client := &http.Client{Timeout: 20 * time.Second}
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
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil
	}

	suffix := "." + domain
	seen := make(map[string]struct{})
	var subs []string

	for _, entry := range response.PassiveDNS {
		hostname := strings.ToLower(strings.TrimSpace(entry.Hostname))
		if hostname == "" {
			continue
		}
		if hostname != domain && !strings.HasSuffix(hostname, suffix) {
			continue
		}
		if _, ok := seen[hostname]; ok {
			continue
		}
		seen[hostname] = struct{}{}
		subs = append(subs, hostname)
	}

	return subs
}
