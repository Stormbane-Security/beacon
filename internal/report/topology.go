package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/playbook"
	"github.com/stormbane/beacon/internal/store"
)

// serviceEntry is one discovered TCP service (non-HTTP) on a host.
type serviceEntry struct {
	port    int
	service string
}

// topoEntry is one hostname within a topology group.
type topoEntry struct {
	name     string
	tech     string // web server (e.g. "nginx"), empty if unknown
	status   int    // HTTP status code, 0 if no HTTP
	cname    string // first CNAME hop, empty if direct
	services []serviceEntry
}

// topoGroup is one (provider, IP) cluster of hostnames.
type topoGroup struct {
	provider string
	ip       string
	hosts    []topoEntry
}

// buildTopology groups scanned assets by cloud provider and IP address.
// findings is the full findings list; port-scan findings are extracted to
// populate service sub-nodes on each host. Pass nil if unavailable.
func buildTopology(executions []store.AssetExecution, findings []finding.Finding) []topoGroup {
	// Build a map of host → discovered services from port-scan findings.
	hostServices := map[string][]serviceEntry{}
	for _, f := range findings {
		port := evidenceInt(f.Evidence, "port")
		svc, _ := f.Evidence["service"].(string)
		if port > 0 && svc != "" {
			// Deduplicate: only add each (port, service) once per host.
			existing := hostServices[f.Asset]
			dupe := false
			for _, e := range existing {
				if e.port == port {
					dupe = true
					break
				}
			}
			if !dupe {
				hostServices[f.Asset] = append(existing, serviceEntry{port: port, service: svc})
			}
		}
	}

	type ipKey struct{ prov, ip string }
	order := []ipKey{}
	seen := map[ipKey]bool{}
	slots := map[ipKey][]topoEntry{}

	for _, ex := range executions {
		ev := ex.Evidence
		prov := deriveProviderFromEvidence(ev)
		ip := ev.IP
		if ip == "" {
			ip = "?"
		}
		tech := ""
		if ws := ev.ServiceVersions["web_server"]; ws != "" {
			if i := strings.IndexAny(ws, "/ "); i > 0 {
				tech = ws[:i]
			} else {
				tech = ws
			}
		}
		cname := ""
		if len(ev.CNAMEChain) > 0 {
			cname = ev.CNAMEChain[0]
		}
		svcs := hostServices[ex.Asset]
		sort.Slice(svcs, func(a, b int) bool { return svcs[a].port < svcs[b].port })

		k := ipKey{prov: prov, ip: ip}
		if !seen[k] {
			seen[k] = true
			order = append(order, k)
		}
		slots[k] = append(slots[k], topoEntry{
			name: ex.Asset, tech: tech, status: ev.StatusCode, cname: cname,
			services: svcs,
		})
	}

	// Sort groups by provider then IP for deterministic output.
	sort.Slice(order, func(i, j int) bool {
		if order[i].prov != order[j].prov {
			return order[i].prov < order[j].prov
		}
		return order[i].ip < order[j].ip
	})

	groups := make([]topoGroup, 0, len(order))
	for _, k := range order {
		hosts := slots[k]
		sort.Slice(hosts, func(a, b int) bool { return hosts[a].name < hosts[b].name })
		groups = append(groups, topoGroup{provider: k.prov, ip: k.ip, hosts: hosts})
	}
	return groups
}

// DeriveProvider classifies an asset's network provider from raw evidence fields.
// Exported so the live progress renderer can use it without importing Evidence.
func DeriveProvider(cnameChain []string, asnOrg, ip string) string {
	for _, cname := range cnameChain {
		lower := strings.ToLower(cname)
		switch {
		case strings.Contains(lower, "cloudfront"):
			return "CloudFront (AWS CDN)"
		case strings.Contains(lower, "cloudflare"):
			return "Cloudflare"
		case strings.Contains(lower, "akamai"):
			return "Akamai"
		case strings.Contains(lower, "fastly"):
			return "Fastly"
		case strings.Contains(lower, "azureedge"):
			return "Azure CDN"
		}
	}
	asnLower := strings.ToLower(asnOrg)
	switch {
	case strings.Contains(asnLower, "cloudflare"):
		return "Cloudflare"
	case strings.Contains(asnLower, "amazon"):
		return "AWS"
	case strings.Contains(asnLower, "google"):
		return "GCP"
	case strings.Contains(asnLower, "microsoft") || strings.Contains(asnLower, "azure"):
		return "Azure"
	case strings.Contains(asnLower, "fastly"):
		return "Fastly"
	case strings.Contains(asnLower, "akamai"):
		return "Akamai"
	}
	if ip == "" {
		return "Unresolved"
	}
	return "Direct"
}

func deriveProviderFromEvidence(ev playbook.Evidence) string {
	return DeriveProvider(ev.CNAMEChain, ev.ASNOrg, ev.IP)
}

// RenderTopologyText returns an ASCII tree section suitable for the text report.
func RenderTopologyText(executions []store.AssetExecution, findings []finding.Finding, width int) string {
	groups := buildTopology(executions, findings)
	if len(groups) == 0 {
		return ""
	}

	var b strings.Builder
	sep := strings.Repeat("─", width)

	b.WriteString("\n" + sep + "\n")
	b.WriteString("\nNETWORK TOPOLOGY\n\n")

	prevProv := ""
	for gi, g := range groups {
		if g.provider != prevProv {
			if gi > 0 {
				b.WriteString("\n")
			}
			b.WriteString("  " + g.provider + "\n")
			prevProv = g.provider
		}

		lastIPInProv := gi == len(groups)-1 || groups[gi+1].provider != g.provider
		ipBranch := "  ├─ "
		hostIndent := "  │  "
		if lastIPInProv {
			ipBranch = "  └─ "
			hostIndent = "     "
		}

		sharedNote := ""
		if len(g.hosts) > 1 {
			sharedNote = fmt.Sprintf("  (%d virtual hosts)", len(g.hosts))
		}
		b.WriteString(fmt.Sprintf("%s%s%s\n", ipBranch, g.ip, sharedNote))

		for hi, h := range g.hosts {
			lastHost := hi == len(g.hosts)-1
			hostBranch := hostIndent + "├─ "
			svcIndent := hostIndent + "│  "
			if lastHost {
				hostBranch = hostIndent + "└─ "
				svcIndent = hostIndent + "   "
			}
			detail := hostDetail(h)
			name := h.name
			if len(name) > 40 {
				name = "…" + name[len(name)-39:]
			}
			b.WriteString(fmt.Sprintf("%s%-40s  %s\n", hostBranch, name, detail))

			for si, svc := range h.services {
				svcBranch := svcIndent + "├─ "
				if si == len(h.services)-1 {
					svcBranch = svcIndent + "└─ "
				}
				b.WriteString(fmt.Sprintf("%s%s:%d\n", svcBranch, svc.service, svc.port))
			}
		}
	}
	b.WriteString("\n")
	return b.String()
}

// RenderTopologyMermaid returns a Mermaid graph definition for the markdown report.
func RenderTopologyMermaid(executions []store.AssetExecution, findings []finding.Finding) string {
	groups := buildTopology(executions, findings)
	if len(groups) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString("## Network Topology\n\n")
	b.WriteString("```mermaid\ngraph LR\n")

	declaredProvs := map[string]bool{}

	for gi, g := range groups {
		provID := mermaidID("prov_" + g.provider)
		ipID := mermaidID(fmt.Sprintf("ip_%d_%s", gi, g.ip))

		if !declaredProvs[g.provider] {
			declaredProvs[g.provider] = true
			b.WriteString(fmt.Sprintf("    %s[\"%s\"]\n", provID, g.provider))
		}

		ipLabel := g.ip
		if len(g.hosts) > 1 {
			ipLabel = fmt.Sprintf("%s\\n(%d hosts)", g.ip, len(g.hosts))
		}
		b.WriteString(fmt.Sprintf("    %s([\"%s\"])\n", ipID, ipLabel))
		b.WriteString(fmt.Sprintf("    %s --> %s\n", provID, ipID))

		for hi, h := range g.hosts {
			hostID := mermaidID(fmt.Sprintf("h_%d_%d_%s", gi, hi, h.name))
			label := h.name
			if d := hostDetail(h); d != "" {
				label += "\\n" + d
			}
			b.WriteString(fmt.Sprintf("    %s[\"%s\"]\n", hostID, label))
			b.WriteString(fmt.Sprintf("    %s --> %s\n", ipID, hostID))

			for si, svc := range h.services {
				svcID := mermaidID(fmt.Sprintf("svc_%d_%d_%d_%s", gi, hi, si, svc.service))
				b.WriteString(fmt.Sprintf("    %s{{\":%d %s\"}}\n", svcID, svc.port, svc.service))
				b.WriteString(fmt.Sprintf("    %s --> %s\n", hostID, svcID))
			}
		}
	}

	b.WriteString("```\n\n")
	return b.String()
}

func hostDetail(h topoEntry) string {
	var parts []string
	if h.status > 0 {
		parts = append(parts, fmt.Sprintf("HTTP %d", h.status))
	}
	if h.tech != "" {
		parts = append(parts, h.tech)
	}
	if h.cname != "" {
		parts = append(parts, "→ "+h.cname)
	}
	if len(parts) == 0 && len(h.services) == 0 {
		return "no HTTP"
	}
	return strings.Join(parts, " · ")
}

func mermaidID(s string) string {
	r := strings.NewReplacer(".", "_", "-", "_", ":", "_", "/", "_", " ", "_", "(", "_", ")", "_")
	return r.Replace(s)
}

// evidenceInt extracts an integer from a finding evidence map.
// JSON round-trips through SQLite turn int into float64, so both are handled.
func evidenceInt(ev map[string]any, key string) int {
	if ev == nil {
		return 0
	}
	switch v := ev[key].(type) {
	case int:
		return v
	case float64:
		return int(v)
	case int64:
		return int(v)
	}
	return 0
}
