package gcp

import (
	"context"
	"fmt"
	"time"

	computeapi "google.golang.org/api/compute/v1"
	"google.golang.org/api/option"

	"github.com/stormbane/beacon/internal/finding"
)

func scanFirewallRules(ctx context.Context, projectID, asset string, opts []option.ClientOption) ([]finding.Finding, error) {
	svc, err := computeapi.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("compute service: %w", err)
	}

	var findings []finding.Finding

	if err := svc.Firewalls.List(projectID).Context(ctx).Pages(ctx,
		func(page *computeapi.FirewallList) error {
			for _, rule := range page.Items {
				findings = append(findings, checkFirewallRule(rule, projectID, asset)...)
			}
			return nil
		}); err != nil {
		return nil, fmt.Errorf("list firewalls: %w", err)
	}

	return findings, nil
}

// checkFirewallRule inspects a single firewall rule for overly permissive ingress.
func checkFirewallRule(rule *computeapi.Firewall, projectID, asset string) []finding.Finding {
	// Only check INGRESS rules (direction "INGRESS" or empty, which defaults to INGRESS).
	if rule.Direction != "" && rule.Direction != "INGRESS" {
		return nil
	}

	// Check if source ranges include the entire internet.
	if !hasOpenSource(rule.SourceRanges) {
		return nil
	}

	var findings []finding.Finding
	network := lastPathSegment(rule.Network)

	for _, allowed := range rule.Allowed {
		// Protocol "all" means every port is open.
		if allowed.IPProtocol == "all" {
			findings = append(findings, finding.Finding{
				CheckID: finding.CheckCloudGCPFirewallAllOpen,
				Title:   fmt.Sprintf("Firewall rule allows ALL ports from 0.0.0.0/0: %s", rule.Name),
				Description: fmt.Sprintf(
					"Firewall rule %s in project %s allows all traffic from 0.0.0.0/0 (the entire internet). "+
						"This exposes every service on affected instances to unauthenticated remote access. "+
						"Restrict source ranges to specific IPs or CIDR blocks.",
					rule.Name, projectID,
				),
				Severity:     finding.SeverityCritical,
				Asset:        asset,
				Scanner:      "cloud/gcp",
				ProofCommand: fmt.Sprintf("gcloud compute firewall-rules describe %s --project=%s --format='table(name,direction,sourceRanges,allowed)'", rule.Name, projectID),
				Evidence: map[string]any{
					"firewall_rule": rule.Name,
					"resource_type": "firewall_rule",
					"project_id":    projectID,
					"network":       network,
					"direction":     "INGRESS",
					"source_ranges": rule.SourceRanges,
					"protocol":      "all",
				},
				DiscoveredAt: time.Now(),
			})
			continue
		}

		// Check individual ports for SSH and RDP.
		for _, port := range allowed.Ports {
			if portMatchesSSH(port) {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudGCPFirewallSSHOpen,
					Title:   fmt.Sprintf("Firewall rule allows SSH (port 22) from 0.0.0.0/0: %s", rule.Name),
					Description: fmt.Sprintf(
						"Firewall rule %s in project %s allows SSH (port 22) from 0.0.0.0/0. "+
							"Exposing SSH to the entire internet enables brute-force and credential-stuffing attacks. "+
							"Restrict source ranges to trusted IPs or use IAP for SSH access.",
						rule.Name, projectID,
					),
					Severity:     finding.SeverityCritical,
					Asset:        asset,
					Scanner:      "cloud/gcp",
					ProofCommand: fmt.Sprintf("gcloud compute firewall-rules describe %s --project=%s --format='table(name,direction,sourceRanges,allowed)'", rule.Name, projectID),
					Evidence: map[string]any{
						"firewall_rule": rule.Name,
						"resource_type": "firewall_rule",
						"project_id":    projectID,
						"network":       network,
						"direction":     "INGRESS",
						"source_ranges": rule.SourceRanges,
						"protocol":      allowed.IPProtocol,
						"port":          port,
					},
					DiscoveredAt: time.Now(),
				})
			}
			if portMatchesRDP(port) {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudGCPFirewallRDPOpen,
					Title:   fmt.Sprintf("Firewall rule allows RDP (port 3389) from 0.0.0.0/0: %s", rule.Name),
					Description: fmt.Sprintf(
						"Firewall rule %s in project %s allows RDP (port 3389) from 0.0.0.0/0. "+
							"Exposing RDP to the entire internet enables brute-force and BlueKeep-class attacks. "+
							"Restrict source ranges to trusted IPs or use IAP for RDP access.",
						rule.Name, projectID,
					),
					Severity:     finding.SeverityCritical,
					Asset:        asset,
					Scanner:      "cloud/gcp",
					ProofCommand: fmt.Sprintf("gcloud compute firewall-rules describe %s --project=%s --format='table(name,direction,sourceRanges,allowed)'", rule.Name, projectID),
					Evidence: map[string]any{
						"firewall_rule": rule.Name,
						"resource_type": "firewall_rule",
						"project_id":    projectID,
						"network":       network,
						"direction":     "INGRESS",
						"source_ranges": rule.SourceRanges,
						"protocol":      allowed.IPProtocol,
						"port":          port,
					},
					DiscoveredAt: time.Now(),
				})
			}
		}

		// If no ports are specified but protocol is tcp/udp, all ports for that
		// protocol are open — check for SSH/RDP exposure.
		if len(allowed.Ports) == 0 && (allowed.IPProtocol == "tcp" || allowed.IPProtocol == "udp") {
			findings = append(findings, finding.Finding{
				CheckID: finding.CheckCloudGCPFirewallAllOpen,
				Title:   fmt.Sprintf("Firewall rule allows all %s ports from 0.0.0.0/0: %s", allowed.IPProtocol, rule.Name),
				Description: fmt.Sprintf(
					"Firewall rule %s in project %s allows all %s ports from 0.0.0.0/0. "+
						"This exposes every %s service on affected instances. "+
						"Restrict to specific ports and source ranges.",
					rule.Name, projectID, allowed.IPProtocol, allowed.IPProtocol,
				),
				Severity:     finding.SeverityCritical,
				Asset:        asset,
				Scanner:      "cloud/gcp",
				ProofCommand: fmt.Sprintf("gcloud compute firewall-rules describe %s --project=%s --format='table(name,direction,sourceRanges,allowed)'", rule.Name, projectID),
				Evidence: map[string]any{
					"firewall_rule": rule.Name,
					"resource_type": "firewall_rule",
					"project_id":    projectID,
					"network":       network,
					"direction":     "INGRESS",
					"source_ranges": rule.SourceRanges,
					"protocol":      allowed.IPProtocol,
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings
}

// hasOpenSource returns true if the source ranges include the entire internet.
func hasOpenSource(ranges []string) bool {
	for _, r := range ranges {
		if r == "0.0.0.0/0" || r == "::/0" {
			return true
		}
	}
	return false
}

// portMatchesSSH returns true if the port spec includes port 22.
// Port specs can be "22", "22-80", etc.
func portMatchesSSH(port string) bool {
	return portContains(port, 22)
}

// portMatchesRDP returns true if the port spec includes port 3389.
func portMatchesRDP(port string) bool {
	return portContains(port, 3389)
}

// portContains checks if a GCP firewall port specification includes a given port number.
// Port specs are either a single port ("22") or a range ("0-65535").
func portContains(portSpec string, target int) bool {
	// Single port.
	var single int
	if n, err := fmt.Sscanf(portSpec, "%d", &single); err == nil && n == 1 {
		// Check if it's a range.
		var lo, hi int
		if n, err := fmt.Sscanf(portSpec, "%d-%d", &lo, &hi); err == nil && n == 2 {
			return target >= lo && target <= hi
		}
		return single == target
	}
	return false
}
