package digitalocean

import (
	"context"
	"fmt"
	"time"

	"github.com/stormbane/beacon/internal/finding"
)

// firewallsListResponse is the API response for listing firewalls.
type firewallsListResponse struct {
	Firewalls []doFirewall `json:"firewalls"`
}

type doFirewall struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	Status       string          `json:"status"`
	DropletIDs   []int           `json:"droplet_ids"`
	InboundRules []doFirewallRule `json:"inbound_rules"`
}

type doFirewallRule struct {
	Protocol string `json:"protocol"` // "tcp", "udp", "icmp"
	Ports    string `json:"ports"`    // "0", "22", "80", "1-65535", etc.
	Sources  struct {
		Addresses        []string `json:"addresses"`
		DropletIDs       []int    `json:"droplet_ids"`
		LoadBalancerUIDs []string `json:"load_balancer_uids"`
		Tags             []string `json:"tags"`
	} `json:"sources"`
}

// scanFirewalls checks firewalls for overly permissive inbound rules.
func scanFirewalls(ctx context.Context, s *Scanner, asset string) ([]finding.Finding, error) {
	var resp firewallsListResponse
	if err := s.doRequest(ctx, "/firewalls", &resp); err != nil {
		return nil, fmt.Errorf("list firewalls: %w", err)
	}

	var findings []finding.Finding
	for _, fw := range resp.Firewalls {
		findings = append(findings, checkFirewall(fw, asset)...)
	}

	return findings, nil
}

// checkFirewall evaluates a single firewall for overly permissive rules.
func checkFirewall(fw doFirewall, asset string) []finding.Finding {
	var findings []finding.Finding

	for _, rule := range fw.InboundRules {
		if !hasOpenSource(rule) {
			continue
		}

		// Check: all ports open from 0.0.0.0/0.
		if isAllPorts(rule.Ports) {
			findings = append(findings, finding.Finding{
				CheckID: finding.CheckCloudDOFirewallAllOpen,
				Title:   fmt.Sprintf("DigitalOcean firewall allows all %s inbound from 0.0.0.0/0: %s", rule.Protocol, fw.Name),
				Description: fmt.Sprintf(
					"Firewall %s (ID: %s) has an inbound rule allowing all %s ports from "+
						"0.0.0.0/0 (the entire internet). This effectively disables the firewall "+
						"for %s traffic. Restrict inbound rules to only the required ports and "+
						"source IP ranges.",
					fw.Name, fw.ID, rule.Protocol, rule.Protocol,
				),
				Severity:     finding.SeverityCritical,
				Asset:        asset,
				Scanner:      scannerTag,
				ProofCommand: fmt.Sprintf("doctl compute firewall get %s --format ID,Name,InboundRules", fw.ID),
				Evidence: map[string]any{
					"firewall_id":   fw.ID,
					"firewall_name": fw.Name,
					"protocol":      rule.Protocol,
					"ports":         rule.Ports,
					"sources":       rule.Sources.Addresses,
					"droplet_ids":   fw.DropletIDs,
				},
				DiscoveredAt: time.Now(),
			})
			continue
		}

		// Check: SSH (port 22) open from 0.0.0.0/0.
		if isSSHPort(rule.Ports) && rule.Protocol == "tcp" {
			findings = append(findings, finding.Finding{
				CheckID: finding.CheckCloudDOFirewallSSHOpen,
				Title:   fmt.Sprintf("DigitalOcean firewall allows SSH from 0.0.0.0/0: %s", fw.Name),
				Description: fmt.Sprintf(
					"Firewall %s (ID: %s) has an inbound rule allowing TCP port 22 (SSH) from "+
						"0.0.0.0/0. SSH access from the entire internet exposes the droplet to "+
						"brute-force attacks. Restrict SSH sources to known IP ranges, use "+
						"DigitalOcean VPC, or switch to SSH key-only authentication behind a VPN.",
					fw.Name, fw.ID,
				),
				Severity:     finding.SeverityHigh,
				Asset:        asset,
				Scanner:      scannerTag,
				ProofCommand: fmt.Sprintf("doctl compute firewall get %s --format ID,Name,InboundRules", fw.ID),
				Evidence: map[string]any{
					"firewall_id":   fw.ID,
					"firewall_name": fw.Name,
					"protocol":      rule.Protocol,
					"ports":         rule.Ports,
					"sources":       rule.Sources.Addresses,
					"droplet_ids":   fw.DropletIDs,
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings
}

// hasOpenSource returns true if the rule's source includes 0.0.0.0/0 or ::/0.
func hasOpenSource(rule doFirewallRule) bool {
	for _, addr := range rule.Sources.Addresses {
		if addr == "0.0.0.0/0" || addr == "::/0" {
			return true
		}
	}
	return false
}

// isAllPorts returns true if the ports field represents all ports.
func isAllPorts(ports string) bool {
	return ports == "0" || ports == "1-65535" || ports == "all"
}

// isSSHPort returns true if the ports field includes port 22.
func isSSHPort(ports string) bool {
	return ports == "22" || ports == "22-22"
}
