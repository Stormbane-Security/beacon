package oci

import (
	"context"
	"fmt"
	"time"

	"github.com/stormbane/beacon/internal/finding"
)

// vcnSummary represents a VCN in the list response.
type vcnSummary struct {
	ID            string `json:"id"`
	DisplayName   string `json:"displayName"`
	CompartmentID string `json:"compartmentId"`
}

// securityList represents an OCI VCN security list.
type securityList struct {
	ID              string              `json:"id"`
	DisplayName     string              `json:"displayName"`
	CompartmentID   string              `json:"compartmentId"`
	VcnID           string              `json:"vcnId"`
	IngressRules    []ingressRule       `json:"ingressSecurityRules"`
}

type ingressRule struct {
	Protocol  string         `json:"protocol"` // "6" = TCP, "17" = UDP, "all"
	Source    string         `json:"source"`    // CIDR block, e.g. "0.0.0.0/0"
	SourceType string        `json:"sourceType"` // "CIDR_BLOCK", "SERVICE_CIDR_BLOCK", "NETWORK_SECURITY_GROUP"
	TCPOptions *portOptions  `json:"tcpOptions"`
	UDPOptions *portOptions  `json:"udpOptions"`
}

type portOptions struct {
	DestinationPortRange *portRange `json:"destinationPortRange"`
	SourcePortRange      *portRange `json:"sourcePortRange"`
}

type portRange struct {
	Min int `json:"min"`
	Max int `json:"max"`
}

// nsgSummary represents an NSG in the list response.
type nsgSummary struct {
	ID            string `json:"id"`
	DisplayName   string `json:"displayName"`
	CompartmentID string `json:"compartmentId"`
	VcnID         string `json:"vcnId"`
}

// nsgSecurityRule represents a rule inside an NSG.
type nsgSecurityRule struct {
	ID          string       `json:"id"`
	Direction   string       `json:"direction"` // "INGRESS" or "EGRESS"
	Protocol    string       `json:"protocol"`  // "6" = TCP, "17" = UDP, "all"
	Source      string       `json:"source"`
	SourceType  string       `json:"sourceType"`
	TCPOptions  *portOptions `json:"tcpOptions"`
	UDPOptions  *portOptions `json:"udpOptions"`
}

// scanNetwork checks OCI VCN security lists and NSGs for overly permissive rules.
func scanNetwork(ctx context.Context, s *Scanner, cfg *ociConfig, asset string) ([]finding.Finding, error) {
	host := coreHost(cfg.Region)
	compartmentID := cfg.Tenancy

	var findings []finding.Finding

	// List VCNs.
	vcnPath := fmt.Sprintf("/20160918/vcns?compartmentId=%s", compartmentID)
	var vcns []vcnSummary
	if err := s.doSignedRequest(ctx, cfg, "GET", host, vcnPath, &vcns); err != nil {
		return nil, fmt.Errorf("list VCNs: %w", err)
	}

	for _, vcn := range vcns {
		// Check security lists in this VCN.
		slPath := fmt.Sprintf("/20160918/securityLists?compartmentId=%s&vcnId=%s", compartmentID, vcn.ID)
		var securityLists []securityList
		if err := s.doSignedRequest(ctx, cfg, "GET", host, slPath, &securityLists); err != nil {
			continue
		}

		for _, sl := range securityLists {
			findings = append(findings, checkSecurityList(sl, vcn.DisplayName, cfg.Region, asset)...)
		}

		// Check NSGs in this VCN.
		nsgPath := fmt.Sprintf("/20160918/networkSecurityGroups?compartmentId=%s&vcnId=%s", compartmentID, vcn.ID)
		var nsgs []nsgSummary
		if err := s.doSignedRequest(ctx, cfg, "GET", host, nsgPath, &nsgs); err != nil {
			continue
		}

		for _, nsg := range nsgs {
			// Get rules for each NSG.
			rulesPath := fmt.Sprintf("/20160918/networkSecurityGroups/%s/securityRules", nsg.ID)
			var rules []nsgSecurityRule
			if err := s.doSignedRequest(ctx, cfg, "GET", host, rulesPath, &rules); err != nil {
				continue
			}
			findings = append(findings, checkNSG(nsg, rules, vcn.DisplayName, cfg.Region, asset)...)
		}
	}

	return findings, nil
}

// checkSecurityList evaluates a VCN security list for overly permissive ingress rules.
func checkSecurityList(sl securityList, vcnName, region, asset string) []finding.Finding {
	var findings []finding.Finding

	for _, rule := range sl.IngressRules {
		if rule.Source != "0.0.0.0/0" && rule.Source != "::/0" {
			continue
		}

		// Check: all protocols / all ports open.
		if rule.Protocol == "all" || isAllPortsCovered(rule) {
			findings = append(findings, finding.Finding{
				CheckID: finding.CheckCloudOCISecurityListAllOpen,
				Title:   fmt.Sprintf("OCI security list allows all inbound from 0.0.0.0/0: %s", sl.DisplayName),
				Description: fmt.Sprintf(
					"Security list %s in VCN %s (region %s) has an ingress rule allowing all "+
						"traffic from 0.0.0.0/0. This exposes all ports on associated subnets to "+
						"the internet. Restrict ingress rules to only required protocols and ports.",
					sl.DisplayName, vcnName, region,
				),
				Severity:     finding.SeverityCritical,
				Asset:        asset,
				Scanner:      scannerTag,
				ProofCommand: fmt.Sprintf("oci network security-list get --security-list-id %s --query 'data.\"ingress-security-rules\"'", sl.ID),
				Evidence: map[string]any{
					"security_list_id":   sl.ID,
					"security_list_name": sl.DisplayName,
					"vcn_name":           vcnName,
					"region":             region,
					"protocol":           rule.Protocol,
					"source":             rule.Source,
				},
				DiscoveredAt: time.Now(),
			})
			continue
		}

		// Check: SSH (TCP port 22) open from 0.0.0.0/0.
		if rule.Protocol == "6" && isSSHCovered(rule) { // "6" = TCP
			findings = append(findings, finding.Finding{
				CheckID: finding.CheckCloudOCISecurityListSSHOpen,
				Title:   fmt.Sprintf("OCI security list allows SSH from 0.0.0.0/0: %s", sl.DisplayName),
				Description: fmt.Sprintf(
					"Security list %s in VCN %s (region %s) has an ingress rule allowing "+
						"TCP port 22 (SSH) from 0.0.0.0/0. SSH access from the entire internet "+
						"exposes instances to brute-force attacks. Restrict SSH sources to known IP "+
						"ranges or use OCI Bastion service.",
					sl.DisplayName, vcnName, region,
				),
				Severity:     finding.SeverityHigh,
				Asset:        asset,
				Scanner:      scannerTag,
				ProofCommand: fmt.Sprintf("oci network security-list get --security-list-id %s --query 'data.\"ingress-security-rules\"'", sl.ID),
				Evidence: map[string]any{
					"security_list_id":   sl.ID,
					"security_list_name": sl.DisplayName,
					"vcn_name":           vcnName,
					"region":             region,
					"protocol":           "TCP",
					"port":               22,
					"source":             rule.Source,
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings
}

// checkNSG evaluates a Network Security Group for overly permissive ingress rules.
func checkNSG(nsg nsgSummary, rules []nsgSecurityRule, vcnName, region, asset string) []finding.Finding {
	var findings []finding.Finding

	for _, rule := range rules {
		if rule.Direction != "INGRESS" {
			continue
		}
		if rule.Source != "0.0.0.0/0" && rule.Source != "::/0" {
			continue
		}

		// Check: all protocols / all ports open.
		if rule.Protocol == "all" || isAllPortsCoveredNSG(rule) {
			findings = append(findings, finding.Finding{
				CheckID: finding.CheckCloudOCINSGAllOpen,
				Title:   fmt.Sprintf("OCI NSG allows all inbound from 0.0.0.0/0: %s", nsg.DisplayName),
				Description: fmt.Sprintf(
					"Network Security Group %s in VCN %s (region %s) has an ingress rule "+
						"allowing all traffic from 0.0.0.0/0. This exposes all attached VNICs to "+
						"the internet on all ports. Restrict ingress rules to only required "+
						"protocols and ports.",
					nsg.DisplayName, vcnName, region,
				),
				Severity:     finding.SeverityCritical,
				Asset:        asset,
				Scanner:      scannerTag,
				ProofCommand: fmt.Sprintf("oci network nsg rules list --nsg-id %s --direction INGRESS", nsg.ID),
				Evidence: map[string]any{
					"nsg_id":     nsg.ID,
					"nsg_name":   nsg.DisplayName,
					"vcn_name":   vcnName,
					"region":     region,
					"rule_id":    rule.ID,
					"protocol":   rule.Protocol,
					"source":     rule.Source,
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings
}

// isAllPortsCovered returns true if the ingress rule effectively covers all ports.
func isAllPortsCovered(rule ingressRule) bool {
	if rule.TCPOptions != nil && rule.TCPOptions.DestinationPortRange != nil {
		r := rule.TCPOptions.DestinationPortRange
		if r.Min <= 1 && r.Max >= 65535 {
			return true
		}
	}
	if rule.UDPOptions != nil && rule.UDPOptions.DestinationPortRange != nil {
		r := rule.UDPOptions.DestinationPortRange
		if r.Min <= 1 && r.Max >= 65535 {
			return true
		}
	}
	// When protocol is TCP/UDP but no port options are specified,
	// OCI allows all ports for that protocol.
	if (rule.Protocol == "6" || rule.Protocol == "17") && rule.TCPOptions == nil && rule.UDPOptions == nil {
		return true
	}
	return false
}

// isAllPortsCoveredNSG returns true if the NSG ingress rule effectively covers all ports.
func isAllPortsCoveredNSG(rule nsgSecurityRule) bool {
	if rule.TCPOptions != nil && rule.TCPOptions.DestinationPortRange != nil {
		r := rule.TCPOptions.DestinationPortRange
		if r.Min <= 1 && r.Max >= 65535 {
			return true
		}
	}
	if rule.UDPOptions != nil && rule.UDPOptions.DestinationPortRange != nil {
		r := rule.UDPOptions.DestinationPortRange
		if r.Min <= 1 && r.Max >= 65535 {
			return true
		}
	}
	if (rule.Protocol == "6" || rule.Protocol == "17") && rule.TCPOptions == nil && rule.UDPOptions == nil {
		return true
	}
	return false
}

// isSSHCovered returns true if the ingress rule covers TCP port 22.
func isSSHCovered(rule ingressRule) bool {
	if rule.TCPOptions == nil || rule.TCPOptions.DestinationPortRange == nil {
		// No port restriction means all TCP ports are allowed.
		return true
	}
	r := rule.TCPOptions.DestinationPortRange
	return r.Min <= 22 && r.Max >= 22
}
