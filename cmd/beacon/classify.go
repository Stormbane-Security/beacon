package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/stormbane-security/beacon/internal/config"
	"github.com/stormbane-security/beacon/internal/fingerprintdb"
	"github.com/stormbane-security/beacon/internal/playbook"
	"github.com/stormbane-security/beacon/internal/scanner/classify"
	sqlitestore "github.com/stormbane-security/beacon/internal/store/sqlite"
)

// classifyOutput is the JSON representation of classification results.
type classifyOutput struct {
	Target           string            `json:"target"`
	IP               string            `json:"ip"`
	CloudProvider    string            `json:"cloud_provider"`
	ProxyType        string            `json:"proxy_type"`
	InfraLayer       string            `json:"infra_layer"`
	Framework        string            `json:"framework"`
	AuthSystem       string            `json:"auth_system"`
	BackendServices  []string          `json:"backend_services"`
	IsKubernetes     bool              `json:"is_kubernetes"`
	IsServerless     bool              `json:"is_serverless"`
	IsReverseProxy   bool              `json:"is_reverse_proxy"`
	ServiceVersions  map[string]string `json:"service_versions"`
	CookieNames      []string          `json:"cookie_names"`
	RespondingPaths  []string          `json:"responding_paths"`
	CertIssuer       string            `json:"cert_issuer"`
	HTTP2Enabled     bool              `json:"http2_enabled"`
	StatusCode       int               `json:"status_code"`
	Title            string            `json:"title"`
	ASNOrg           string            `json:"asn_org"`
	CNAMEChain       []string          `json:"cname_chain"`
	DNSSuffix        string            `json:"dns_suffix"`
	JARMFingerprint  string            `json:"jarm_fingerprint"`
	FaviconHash      string            `json:"favicon_hash"`
	Web3Signals      []string          `json:"web3_signals"`
	AIEndpoints      []string          `json:"ai_endpoints"`
	VendorSignals    []string          `json:"vendor_signals"`
	MXProvider       string            `json:"mx_provider"`
	HasDMARC         bool              `json:"has_dmarc"`
	DMARCPolicy      string            `json:"dmarc_policy"`
	MatchedPlaybooks []string          `json:"matched_playbooks"`
}

func cmdClassify(cfg *config.Config, args []string) {
	var target, format string
	format = "text"

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--format":
			if i+1 >= len(args) {
				fatalf("--format requires a value (json or text)")
			}
			i++
			format = args[i]
		default:
			if strings.HasPrefix(args[i], "-") {
				fatalf("unknown flag: %s", args[i])
			}
			if target != "" {
				fatalf("unexpected argument: %s (target already set to %q)", args[i], target)
			}
			target = args[i]
		}
	}

	if target == "" {
		fatalf("usage: beacon classify <target> [--format json|text]")
	}
	if format != "json" && format != "text" {
		fatalf("unsupported format %q: use json or text", format)
	}

	ctx := context.Background()

	// Collect evidence from the target.
	ev := classify.Collect(ctx, target)

	// Apply fingerprint database rules to fill gaps left by deterministic detection.
	db, err := sqlitestore.Open(cfg.Store.Path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "beacon: warning: could not open store for fingerprint rules: %v\n", err)
	} else {
		defer db.Close()
		if seedErr := fingerprintdb.Seed(ctx, db); seedErr != nil {
			fmt.Fprintf(os.Stderr, "beacon: warning: fingerprint seed failed: %v\n", seedErr)
		}
		rules, rulesErr := db.GetFingerprintRules(ctx, "active")
		if rulesErr != nil {
			fmt.Fprintf(os.Stderr, "beacon: warning: could not load fingerprint rules: %v\n", rulesErr)
		} else {
			fingerprintdb.Apply(rules, &ev)
		}
	}

	// Load playbook registry and match against evidence.
	registry, err := playbook.Load()
	if err != nil {
		fatalf("load playbooks: %v", err)
	}
	matched := registry.Match(ev)
	var playbookNames []string
	for _, p := range matched {
		playbookNames = append(playbookNames, p.Name)
	}

	switch format {
	case "json":
		printClassifyJSON(target, ev, playbookNames)
	default:
		printClassifyText(target, ev, playbookNames)
	}
}

func printClassifyJSON(target string, ev playbook.Evidence, playbooks []string) {
	out := classifyOutput{
		Target:           target,
		IP:               ev.IP,
		CloudProvider:    ev.CloudProvider,
		ProxyType:        ev.ProxyType,
		InfraLayer:       ev.InfraLayer,
		Framework:        ev.Framework,
		AuthSystem:       ev.AuthSystem,
		BackendServices:  nonNilSlice(ev.BackendServices),
		IsKubernetes:     ev.IsKubernetes,
		IsServerless:     ev.IsServerless,
		IsReverseProxy:   ev.IsReverseProxy,
		ServiceVersions:  nonNilMap(ev.ServiceVersions),
		CookieNames:      nonNilSlice(ev.CookieNames),
		RespondingPaths:  nonNilSlice(ev.RespondingPaths),
		CertIssuer:       ev.CertIssuer,
		HTTP2Enabled:     ev.HTTP2Enabled,
		StatusCode:       ev.StatusCode,
		Title:            ev.Title,
		ASNOrg:           ev.ASNOrg,
		CNAMEChain:       nonNilSlice(ev.CNAMEChain),
		DNSSuffix:        ev.DNSSuffix,
		JARMFingerprint:  ev.JARMFingerprint,
		FaviconHash:      ev.FaviconHash,
		Web3Signals:      nonNilSlice(ev.Web3Signals),
		AIEndpoints:      nonNilSlice(ev.AIEndpoints),
		VendorSignals:    nonNilSlice(ev.VendorSignals),
		MXProvider:       ev.MXProvider,
		HasDMARC:         ev.HasDMARC,
		DMARCPolicy:      ev.DMARCPolicy,
		MatchedPlaybooks: nonNilSlice(playbooks),
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fatalf("encode JSON: %v", err)
	}
}

func printClassifyText(target string, ev playbook.Evidence, playbooks []string) {
	fmt.Printf("Target: %s\n", target)
	fmt.Printf("IP: %s\n", ev.IP)

	// Stack: proxy -> framework (or individual components)
	var stack []string
	if ev.ProxyType != "" {
		stack = append(stack, ev.ProxyType)
	}
	if ev.Framework != "" {
		stack = append(stack, ev.Framework)
	}
	if len(stack) > 0 {
		fmt.Printf("Stack: %s\n", strings.Join(stack, " -> "))
	} else {
		fmt.Printf("Stack: (none)\n")
	}

	if ev.CloudProvider != "" {
		fmt.Printf("Cloud: %s\n", ev.CloudProvider)
	} else {
		fmt.Printf("Cloud: (none)\n")
	}

	if ev.AuthSystem != "" {
		fmt.Printf("Auth: %s\n", ev.AuthSystem)
	} else {
		fmt.Printf("Auth: (none)\n")
	}

	if len(ev.BackendServices) > 0 {
		fmt.Printf("Services: %s\n", strings.Join(ev.BackendServices, ", "))
	} else {
		fmt.Printf("Services: (none)\n")
	}

	if len(playbooks) > 0 {
		fmt.Printf("Playbooks: %s\n", strings.Join(playbooks, ", "))
	} else {
		fmt.Printf("Playbooks: (none)\n")
	}
}

// nonNilSlice returns s if non-nil, or an empty slice. This ensures JSON
// output contains [] instead of null for empty lists.
func nonNilSlice(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// nonNilMap returns m if non-nil, or an empty map. This ensures JSON
// output contains {} instead of null for empty maps.
func nonNilMap(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}
