package digitalocean

import (
	"context"
	"fmt"
	"time"

	"github.com/stormbane/beacon/internal/finding"
)

// dropletsListResponse is the API response for listing droplets.
type dropletsListResponse struct {
	Droplets []doDroplet `json:"droplets"`
	Meta     struct {
		Total int `json:"total"`
	} `json:"meta"`
	Links struct {
		Pages struct {
			Next string `json:"next"`
		} `json:"pages"`
	} `json:"links"`
}

type doDroplet struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Status   string `json:"status"`
	Region   struct {
		Slug string `json:"slug"`
	} `json:"region"`
	Networks struct {
		V4 []doNetwork `json:"v4"`
	} `json:"networks"`
}

type doNetwork struct {
	IPAddress string `json:"ip_address"`
	Netmask   string `json:"netmask"`
	Gateway   string `json:"gateway"`
	Type      string `json:"type"` // "public" or "private"
}

// firewallsForDropletResponse is the response for listing firewalls assigned to a droplet.
type firewallsForDropletResponse struct {
	Firewalls []doFirewall `json:"firewalls"`
}

// scanDroplets checks droplets for public IP without firewall and related issues.
func scanDroplets(ctx context.Context, s *Scanner, asset string) ([]finding.Finding, error) {
	// First, collect all firewalls to build a map of droplet-to-firewall coverage.
	firewallCoverage, err := buildFirewallCoverage(ctx, s)
	if err != nil {
		// Non-fatal: we can still check public IPs but not firewall coverage.
		firewallCoverage = map[int]bool{}
	}

	var allFindings []finding.Finding
	page := 1
	for {
		path := fmt.Sprintf("/droplets?page=%d&per_page=100", page)
		var resp dropletsListResponse
		if err := s.doRequest(ctx, path, &resp); err != nil {
			if len(allFindings) > 0 {
				break
			}
			return nil, fmt.Errorf("list droplets: %w", err)
		}

		for _, droplet := range resp.Droplets {
			if droplet.Status != "active" {
				continue
			}

			allFindings = append(allFindings, checkDroplet(droplet, firewallCoverage, asset)...)
		}

		if resp.Links.Pages.Next == "" {
			break
		}
		page++
	}

	return allFindings, nil
}

// checkDroplet evaluates a single droplet for security issues.
func checkDroplet(droplet doDroplet, firewallCoverage map[int]bool, asset string) []finding.Finding {
	var findings []finding.Finding

	// Collect public IPs.
	var publicIPs []string
	for _, net := range droplet.Networks.V4 {
		if net.Type == "public" && net.IPAddress != "" {
			publicIPs = append(publicIPs, net.IPAddress)
		}
	}

	// Check: droplet has public IP but no firewall.
	if len(publicIPs) > 0 && !firewallCoverage[droplet.ID] {
		findings = append(findings, finding.Finding{
			CheckID: finding.CheckCloudDONoFirewall,
			Title:   fmt.Sprintf("DigitalOcean Droplet has no firewall: %s", droplet.Name),
			Description: fmt.Sprintf(
				"Droplet %s (ID: %d) in region %s has public IP(s) %v but no DigitalOcean "+
					"Cloud Firewall is attached. Without a firewall, all ports on the droplet are "+
					"reachable from the internet. Create a Cloud Firewall with appropriate inbound "+
					"rules and assign it to this droplet.",
				droplet.Name, droplet.ID, droplet.Region.Slug, publicIPs,
			),
			Severity:     finding.SeverityHigh,
			Asset:        asset,
			Scanner:      scannerTag,
			ProofCommand: fmt.Sprintf("doctl compute droplet get %d --format ID,Name,PublicIPv4,Status", droplet.ID),
			Evidence: map[string]any{
				"droplet_id":   droplet.ID,
				"droplet_name": droplet.Name,
				"region":       droplet.Region.Slug,
				"public_ips":   publicIPs,
				"has_firewall": false,
			},
			DiscoveredAt: time.Now(),
		})
	}

	// Check: droplet has public IP (informational when firewall exists, medium otherwise).
	if len(publicIPs) > 0 {
		sev := finding.SeverityMedium
		desc := fmt.Sprintf(
			"Droplet %s (ID: %d) in region %s has public IP(s) %v. "+
				"Verify that a Cloud Firewall restricts inbound access to only required ports. "+
				"Consider placing the droplet behind a load balancer or using a VPC-only configuration.",
			droplet.Name, droplet.ID, droplet.Region.Slug, publicIPs,
		)
		if firewallCoverage[droplet.ID] {
			// Firewall exists, still worth noting the public exposure.
			sev = finding.SeverityMedium
		}
		findings = append(findings, finding.Finding{
			CheckID: finding.CheckCloudDODropletPublicIP,
			Title:   fmt.Sprintf("DigitalOcean Droplet has public IP: %s", droplet.Name),
			Description: desc,
			Severity:     sev,
			Asset:        asset,
			Scanner:      scannerTag,
			ProofCommand: fmt.Sprintf("doctl compute droplet get %d --format ID,Name,PublicIPv4,Status", droplet.ID),
			Evidence: map[string]any{
				"droplet_id":   droplet.ID,
				"droplet_name": droplet.Name,
				"region":       droplet.Region.Slug,
				"public_ips":   publicIPs,
				"has_firewall": firewallCoverage[droplet.ID],
			},
			DiscoveredAt: time.Now(),
		})
	}

	return findings
}

// buildFirewallCoverage builds a set of droplet IDs that have at least one
// firewall assigned. Uses the /v2/firewalls endpoint.
func buildFirewallCoverage(ctx context.Context, s *Scanner) (map[int]bool, error) {
	var resp firewallsListResponse
	if err := s.doRequest(ctx, "/firewalls", &resp); err != nil {
		return nil, fmt.Errorf("list firewalls: %w", err)
	}

	coverage := make(map[int]bool)
	for _, fw := range resp.Firewalls {
		for _, id := range fw.DropletIDs {
			coverage[id] = true
		}
	}
	return coverage, nil
}
