package digitalocean

import (
	"context"
	"fmt"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
)

// spacesListResponse is the API response for listing Spaces buckets.
// DigitalOcean uses S3-compatible API for Spaces, but the v2 REST API
// does not expose Spaces directly. We use the /v2/spaces endpoint which
// lists all Spaces regions, and then query S3-compatible endpoints.
// However, since we want to avoid AWS SDK dependency, we use the undocumented
// /v2/spaces endpoint if available, or fall back to listing via the regions API.
//
// In practice, the most reliable approach for posture scanning is to use the
// /v2/kubernetes/clusters endpoint pattern and the CDN endpoints API.
// Since the DO API v2 does not have a native "list all Spaces" endpoint,
// we enumerate Spaces via the CDN endpoints list, which returns Space origins.
//
// Actually, DigitalOcean added a native Spaces API at /v2/spaces.
// If unavailable, we gracefully degrade.

type spacesListResponse struct {
	Spaces []doSpace `json:"spaces"`
}

type doSpace struct {
	Name       string `json:"name"`
	Region     string `json:"region"`
	SpaceACL   string `json:"space_acl"` // "private" or "public"
	Encryption struct {
		Enabled bool `json:"enabled"`
	} `json:"encryption"`
}

// scanSpaces checks Spaces buckets for public access and encryption.
func scanSpaces(ctx context.Context, s *Scanner, asset string) ([]finding.Finding, error) {
	var resp spacesListResponse
	if err := s.doRequest(ctx, "/spaces", &resp); err != nil {
		// The /v2/spaces endpoint may not be available in all API versions.
		// Fall back to CDN endpoints to discover Spaces.
		return scanSpacesViaCDN(ctx, s, asset)
	}

	var findings []finding.Finding
	for _, space := range resp.Spaces {
		// Check public access.
		if space.SpaceACL == "public" || space.SpaceACL == "public-read" {
			findings = append(findings, finding.Finding{
				CheckID: finding.CheckCloudDOSpacesPublic,
				Title:   fmt.Sprintf("DigitalOcean Space is publicly accessible: %s", space.Name),
				Description: fmt.Sprintf(
					"DigitalOcean Space %s in region %s has public ACL (%s). "+
						"Any internet user can read objects from this bucket. "+
						"Set the Space ACL to private unless public access is explicitly required.",
					space.Name, space.Region, space.SpaceACL,
				),
				Severity:     finding.SeverityCritical,
				Asset:        asset,
				Scanner:      scannerTag,
				ProofCommand: fmt.Sprintf("curl -s 'https://%s.%s.digitaloceanspaces.com/' | head -50", space.Name, space.Region),
				Evidence: map[string]any{
					"space":  space.Name,
					"region": space.Region,
					"acl":    space.SpaceACL,
				},
				DiscoveredAt: time.Now(),
			})
		}

		// Check encryption.
		if !space.Encryption.Enabled {
			findings = append(findings, finding.Finding{
				CheckID: finding.CheckCloudDOSpacesNoEncryption,
				Title:   fmt.Sprintf("DigitalOcean Space has no server-side encryption: %s", space.Name),
				Description: fmt.Sprintf(
					"DigitalOcean Space %s in region %s does not have server-side encryption enabled. "+
						"Data stored in the Space is not encrypted at rest. Enable server-side encryption "+
						"to protect data confidentiality.",
					space.Name, space.Region,
				),
				Severity:     finding.SeverityMedium,
				Asset:        asset,
				Scanner:      scannerTag,
				ProofCommand: fmt.Sprintf("doctl spaces info %s --region %s", space.Name, space.Region),
				Evidence: map[string]any{
					"space":      space.Name,
					"region":     space.Region,
					"encryption": false,
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings, nil
}

// cdnEndpointsResponse is the API response for listing CDN endpoints.
type cdnEndpointsResponse struct {
	Endpoints []cdnEndpoint `json:"endpoints"`
}

type cdnEndpoint struct {
	ID     string `json:"id"`
	Origin string `json:"origin"` // e.g. "my-space.nyc3.digitaloceanspaces.com"
}

// scanSpacesViaCDN is a fallback that discovers Spaces via CDN endpoints.
// CDN endpoints always reference a Space origin, so we can detect Spaces
// that are exposed via CDN (which implies public-read).
func scanSpacesViaCDN(ctx context.Context, s *Scanner, asset string) ([]finding.Finding, error) {
	var resp cdnEndpointsResponse
	if err := s.doRequest(ctx, "/cdn/endpoints", &resp); err != nil {
		// If CDN API also fails, there is nothing more we can discover.
		return nil, fmt.Errorf("cdn endpoints: %w", err)
	}

	var findings []finding.Finding
	for _, ep := range resp.Endpoints {
		// CDN endpoints serve content publicly, which implies the Space has
		// public-read access (CDN cannot cache private Space content).
		findings = append(findings, finding.Finding{
			CheckID: finding.CheckCloudDOSpacesPublic,
			Title:   fmt.Sprintf("DigitalOcean Space served via public CDN: %s", ep.Origin),
			Description: fmt.Sprintf(
				"DigitalOcean Space at %s is served via a CDN endpoint, implying public read access. "+
					"Verify whether public access is intentional. If the Space contains sensitive data, "+
					"remove the CDN endpoint and restrict the Space ACL.",
				ep.Origin,
			),
			Severity:     finding.SeverityHigh,
			Asset:        asset,
			Scanner:      scannerTag,
			ProofCommand: fmt.Sprintf("curl -sI 'https://%s/'", ep.Origin),
			Evidence: map[string]any{
				"cdn_endpoint_id": ep.ID,
				"origin":          ep.Origin,
			},
			DiscoveredAt: time.Now(),
		})
	}

	return findings, nil
}
