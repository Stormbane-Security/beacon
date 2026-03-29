package asset

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/stormbane/beacon/internal/enrichment"
	"github.com/stormbane/beacon/internal/finding"
)

// normalizeIP returns the canonical string representation of an IP address.
// This ensures IPv6 addresses in different formats (e.g., "::1" vs
// "0:0:0:0:0:0:0:1") map to the same asset ID.
func normalizeIP(s string) string {
	ip := net.ParseIP(s)
	if ip == nil {
		return s
	}
	return ip.String()
}

// Builder accumulates assets, relationships, and findings during a scan
// and produces an AssetGraph at the end.
type Builder struct {
	mu            sync.Mutex
	scanRunID     string
	domain        string
	assets        map[string]*Asset        // keyed by ID
	relationships []Relationship
	findingRefs   []FindingRef
	iacRefs       []IaCReference
	// ipIndex maps external IP → asset ID for cross-referencing
	ipIndex map[string]string
}

// NewBuilder creates a new graph builder for a scan run.
func NewBuilder(scanRunID, domain string) *Builder {
	return &Builder{
		scanRunID: scanRunID,
		domain:    domain,
		assets:    make(map[string]*Asset),
		ipIndex:   make(map[string]string),
	}
}

// AddAsset adds or merges an asset into the graph.
// If an asset with the same ID already exists, fields are merged.
func (b *Builder) AddAsset(a Asset) {
	if a.DiscoveredAt.IsZero() {
		a.DiscoveredAt = time.Now()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if existing, ok := b.assets[a.ID]; ok {
		// Merge: keep higher-confidence fields, union aliases/labels
		if a.Confidence > existing.Confidence {
			existing.Confidence = a.Confidence
		}
		existing.Aliases = unionStrings(existing.Aliases, a.Aliases)
		for k, v := range a.Labels {
			if existing.Labels == nil {
				existing.Labels = make(map[string]string)
			}
			existing.Labels[k] = v
		}
		if a.IAMContext != nil && existing.IAMContext == nil {
			existing.IAMContext = a.IAMContext
		}
		if a.Fingerprint != nil {
			if existing.Fingerprint == nil {
				existing.Fingerprint = a.Fingerprint
			} else {
				existing.Fingerprint.Tech = append(existing.Fingerprint.Tech, a.Fingerprint.Tech...)
				existing.Fingerprint.ConfirmedSignals = append(existing.Fingerprint.ConfirmedSignals, a.Fingerprint.ConfirmedSignals...)
			}
		}
		return
	}
	b.assets[a.ID] = &a

	// Index IPs for cross-referencing (normalized for IPv6 consistency).
	if a.Type == AssetTypeIP {
		b.ipIndex[normalizeIP(a.Name)] = a.ID
	}
	if a.Type == AssetTypeGCPInstance || a.Type == AssetTypeAWSEC2 || a.Type == AssetTypeAzureVM {
		if ip, ok := a.Metadata["external_ip"].(string); ok && ip != "" {
			b.ipIndex[normalizeIP(ip)] = a.ID
		}
	}
}

// AddDomainAsset registers a domain or subdomain and its resolved IPs,
// then attempts cross-referencing with any known cloud assets.
func (b *Builder) AddDomainAsset(hostname string, resolvedIPs []string, discoveredBy string) {
	typ := AssetTypeDomain
	if !strings.EqualFold(hostname, b.domain) && strings.HasSuffix(hostname, "."+b.domain) {
		typ = AssetTypeSubdomain
	}
	a := Asset{
		ID:           fmt.Sprintf("domain:%s", hostname),
		Type:         typ,
		Provider:     "web",
		Name:         hostname,
		DiscoveredBy: discoveredBy,
		Confidence:   1.0,
	}
	b.AddAsset(a)

	for _, ip := range resolvedIPs {
		if net.ParseIP(ip) == nil {
			continue
		}
		normIP := normalizeIP(ip)
		ipID := fmt.Sprintf("ip:%s", normIP)
		b.AddAsset(Asset{
			ID:           ipID,
			Type:         AssetTypeIP,
			Provider:     "network",
			Name:         normIP,
			DiscoveredBy: discoveredBy,
			Confidence:   1.0,
		})
		b.AddRelationship(Relationship{
			FromID:     a.ID,
			ToID:       ipID,
			Type:       RelPointsTo,
			Confidence: 1.0,
		})
		// Cross-reference: if a cloud asset has this IP, link them.
		b.mu.Lock()
		if cloudID, ok := b.ipIndex[normIP]; ok && cloudID != ipID {
			b.relationships = append(b.relationships, Relationship{
				FromID:     a.ID,
				ToID:       cloudID,
				Type:       RelLikelySameAs,
				Confidence: 0.98,
				Evidence:   map[string]any{"ip": ip, "method": "ip_match"},
			})
		}
		b.mu.Unlock()
	}
}

// AddRelationship adds a directed edge to the graph.
func (b *Builder) AddRelationship(r Relationship) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.relationships = append(b.relationships, r)
}

// AddFindings converts scan findings into FindingRef entries attached to assets.
func (b *Builder) AddFindings(scanFindings []finding.Finding) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i, f := range scanFindings {
		assetID := fmt.Sprintf("domain:%s", f.Asset)
		if f.Module == "cloud" || f.Module == "github" || strings.Contains(f.Asset, ":") {
			assetID = f.Asset
		}
		// If this asset exists as a cloud asset (via alias), prefer that ID.
		tags := finding.ComplianceTags(f.CheckID)
		b.findingRefs = append(b.findingRefs, FindingRef{
			FindingID:      fmt.Sprintf("%s-%d", f.Scanner, i),
			AssetID:        assetID,
			CheckID:        string(f.CheckID),
			Severity:       f.Severity.String(),
			Title:          f.Title,
			ProofCommand:   f.ProofCommand,
			ComplianceTags: tags,
		})
	}
}

// AddEnrichedFindings converts enriched findings into FindingRef entries.
func (b *Builder) AddEnrichedFindings(efs []enrichment.EnrichedFinding) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i, ef := range efs {
		f := ef.Finding
		assetID := fmt.Sprintf("domain:%s", f.Asset)
		if f.Module == "cloud" || f.Module == "github" || strings.Contains(f.Asset, ":") {
			assetID = f.Asset
		}
		tags := ef.ComplianceTags
		if len(tags) == 0 {
			tags = finding.ComplianceTags(f.CheckID)
		}
		b.findingRefs = append(b.findingRefs, FindingRef{
			FindingID:      fmt.Sprintf("%s-%d", f.Scanner, i),
			AssetID:        assetID,
			CheckID:        string(f.CheckID),
			Severity:       f.Severity.String(),
			Title:          f.Title,
			ProofCommand:   f.ProofCommand,
			ComplianceTags: tags,
		})
	}
}

// AddIaCReference registers a confirmed Terraform → cloud asset mapping.
func (b *Builder) AddIaCReference(ref IaCReference) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.iacRefs = append(b.iacRefs, ref)
}

// CrossReferenceByIP runs after all scanners complete.
// For each cloud asset with an external IP, it looks for a matching domain asset
// and creates a likely_same_as relationship.
func (b *Builder) CrossReferenceByIP() {
	b.mu.Lock()
	defer b.mu.Unlock()

	var newRels []Relationship
	for _, a := range b.assets {
		if a.Type != AssetTypeGCPInstance && a.Type != AssetTypeAWSEC2 && a.Type != AssetTypeAzureVM {
			continue
		}
		extIP, _ := a.Metadata["external_ip"].(string)
		if extIP == "" {
			continue
		}
		ipID := fmt.Sprintf("ip:%s", normalizeIP(extIP))
		for _, rel := range b.relationships {
			if rel.Type == RelPointsTo && rel.ToID == ipID {
				newRels = append(newRels, Relationship{
					FromID:     rel.FromID,
					ToID:       a.ID,
					Type:       RelLikelySameAs,
					Confidence: 0.98,
					Evidence:   map[string]any{"ip": extIP, "method": "ip_match"},
				})
			}
		}
	}
	b.relationships = append(b.relationships, newRels...)
}

// Build assembles the final AssetGraph.
func (b *Builder) Build() AssetGraph {
	b.CrossReferenceByIP()
	b.mu.Lock()
	defer b.mu.Unlock()

	assets := make([]Asset, 0, len(b.assets))
	for _, a := range b.assets {
		assets = append(assets, *a)
	}

	return AssetGraph{
		ScanRunID:     b.scanRunID,
		Domain:        b.domain,
		GeneratedAt:   time.Now(),
		Assets:        assets,
		Relationships: b.relationships,
		Findings:      b.findingRefs,
		IaCReferences: b.iacRefs,
	}
}

func unionStrings(a, b []string) []string {
	seen := make(map[string]bool, len(a))
	for _, s := range a {
		seen[s] = true
	}
	for _, s := range b {
		if !seen[s] {
			a = append(a, s)
		}
	}
	return a
}
