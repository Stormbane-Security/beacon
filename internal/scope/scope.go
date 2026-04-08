// Package scope provides bug bounty program scope resolution.
//
// It queries public program APIs (HackerOne, Bugcrowd, Intigriti) to determine
// which assets are in scope for a given program. Results are cached locally.
//
// Usage:
//
//	scope, err := scope.FetchProgram("hackerone", "uber")
//	if scope.InScope("api.uber.com") { ... }
//	if scope.InScope("*.uber.com") { ... }
package scope

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Asset represents a single in-scope or out-of-scope asset.
type Asset struct {
	Identifier    string `json:"identifier"`     // domain, URL, IP range, etc.
	Type          string `json:"type"`           // url, domain, cidr, wildcard, mobile, etc.
	MaxSeverity   string `json:"max_severity"`   // critical, high, medium, low
	EligibleBugs  string `json:"eligible_bugs"`  // all, web, mobile, api, etc.
	InScope       bool   `json:"in_scope"`       // true = in scope, false = out of scope
	Instruction   string `json:"instruction"`    // special instructions for this asset
}

// Program represents a bug bounty program's scope.
type Program struct {
	Platform    string  `json:"platform"`     // hackerone, bugcrowd, intigriti
	Handle      string  `json:"handle"`       // program handle/slug
	Name        string  `json:"name"`         // program display name
	Assets      []Asset `json:"assets"`       // all scope entries
	FetchedAt   time.Time `json:"fetched_at"`
}

// InScope returns true if the given domain/URL is within the program's scope.
func (p *Program) InScope(target string) bool {
	target = strings.ToLower(strings.TrimSpace(target))
	for _, a := range p.Assets {
		if !a.InScope {
			continue
		}
		id := strings.ToLower(a.Identifier)
		// Exact match
		if id == target {
			return true
		}
		// Wildcard match: *.example.com matches sub.example.com
		if strings.HasPrefix(id, "*.") {
			suffix := id[1:] // .example.com
			if strings.HasSuffix(target, suffix) || target == id[2:] {
				return true
			}
		}
		// URL match: strip scheme
		stripped := strings.TrimPrefix(strings.TrimPrefix(id, "https://"), "http://")
		stripped = strings.TrimSuffix(stripped, "/")
		if stripped == target {
			return true
		}
	}
	return false
}

// InScopeAssets returns all in-scope domain/URL assets.
func (p *Program) InScopeAssets() []Asset {
	var result []Asset
	for _, a := range p.Assets {
		if a.InScope {
			result = append(result, a)
		}
	}
	return result
}

// OutOfScopeAssets returns all explicitly out-of-scope assets.
func (p *Program) OutOfScopeAssets() []Asset {
	var result []Asset
	for _, a := range p.Assets {
		if !a.InScope {
			result = append(result, a)
		}
	}
	return result
}

// FetchProgram queries the given platform's API for program scope.
// Supports: "hackerone", "bugcrowd", "intigriti".
func FetchProgram(ctx context.Context, platform, handle string) (*Program, error) {
	switch strings.ToLower(platform) {
	case "hackerone", "h1":
		return fetchHackerOne(ctx, handle)
	case "bugcrowd", "bc":
		return fetchBugcrowd(ctx, handle)
	case "intigriti", "ig":
		return fetchIntigriti(ctx, handle)
	default:
		return nil, fmt.Errorf("unsupported platform %q (use hackerone, bugcrowd, or intigriti)", platform)
	}
}

// fetchHackerOne queries the HackerOne public program API.
// The structured_scopes endpoint is publicly accessible for disclosed programs.
func fetchHackerOne(ctx context.Context, handle string) (*Program, error) {
	url := fmt.Sprintf("https://hackerone.com/programs/%s/scopes.json", handle)
	client := &http.Client{Timeout: 15 * time.Second}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hackerone: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		// Try the public GraphQL-style API
		return fetchHackerOneGraphQL(ctx, handle)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result struct {
		Data []struct {
			Attributes struct {
				AssetIdentifier string `json:"asset_identifier"`
				AssetType       string `json:"asset_type"`
				MaxSeverity     string `json:"max_severity"`
				EligibleBugs    string `json:"eligible_for_bounty"`
				Instruction     string `json:"instruction"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("hackerone: parse: %w", err)
	}

	prog := &Program{
		Platform:  "hackerone",
		Handle:    handle,
		FetchedAt: time.Now(),
	}
	for _, d := range result.Data {
		prog.Assets = append(prog.Assets, Asset{
			Identifier:   d.Attributes.AssetIdentifier,
			Type:         d.Attributes.AssetType,
			MaxSeverity:  d.Attributes.MaxSeverity,
			EligibleBugs: d.Attributes.EligibleBugs,
			InScope:      true, // scopes.json only returns in-scope assets
			Instruction:  d.Attributes.Instruction,
		})
	}
	return prog, nil
}

// fetchHackerOneGraphQL uses the HackerOne GraphQL API for program scope.
func fetchHackerOneGraphQL(ctx context.Context, handle string) (*Program, error) {
	query := fmt.Sprintf(`{"query":"query{team(handle:\"%s\"){name,in_scope_assets:structured_scopes(first:100,archived:false,eligible_for_submission:true){edges{node{asset_identifier,asset_type,max_severity,eligible_for_bounty,instruction}}},out_of_scope_assets:structured_scopes(first:100,archived:false,eligible_for_submission:false){edges{node{asset_identifier,asset_type}}}}}"}`, handle)

	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "POST", "https://hackerone.com/graphql", strings.NewReader(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hackerone graphql: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var gql struct {
		Data struct {
			Team struct {
				Name     string `json:"name"`
				InScope  struct {
					Edges []struct {
						Node struct {
							AssetIdentifier string `json:"asset_identifier"`
							AssetType       string `json:"asset_type"`
							MaxSeverity     string `json:"max_severity"`
							Eligible        bool   `json:"eligible_for_bounty"`
							Instruction     string `json:"instruction"`
						} `json:"node"`
					} `json:"edges"`
				} `json:"in_scope_assets"`
				OutOfScope struct {
					Edges []struct {
						Node struct {
							AssetIdentifier string `json:"asset_identifier"`
							AssetType       string `json:"asset_type"`
						} `json:"node"`
					} `json:"edges"`
				} `json:"out_of_scope_assets"`
			} `json:"team"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &gql); err != nil {
		return nil, fmt.Errorf("hackerone graphql: parse: %w", err)
	}

	prog := &Program{
		Platform:  "hackerone",
		Handle:    handle,
		Name:      gql.Data.Team.Name,
		FetchedAt: time.Now(),
	}
	for _, e := range gql.Data.Team.InScope.Edges {
		prog.Assets = append(prog.Assets, Asset{
			Identifier:   e.Node.AssetIdentifier,
			Type:         e.Node.AssetType,
			MaxSeverity:  e.Node.MaxSeverity,
			InScope:      true,
			Instruction:  e.Node.Instruction,
		})
	}
	for _, e := range gql.Data.Team.OutOfScope.Edges {
		prog.Assets = append(prog.Assets, Asset{
			Identifier: e.Node.AssetIdentifier,
			Type:       e.Node.AssetType,
			InScope:    false,
		})
	}
	return prog, nil
}

// fetchBugcrowd queries the Bugcrowd public program API.
func fetchBugcrowd(ctx context.Context, handle string) (*Program, error) {
	url := fmt.Sprintf("https://bugcrowd.com/%s.json", handle)
	client := &http.Client{Timeout: 15 * time.Second}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("bugcrowd: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result struct {
		Name   string `json:"name"`
		Targets struct {
			InScope    []struct {
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"in_scope"`
			OutOfScope []struct {
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"out_of_scope"`
		} `json:"target_groups"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("bugcrowd: parse: %w", err)
	}

	prog := &Program{
		Platform:  "bugcrowd",
		Handle:    handle,
		Name:      result.Name,
		FetchedAt: time.Now(),
	}
	for _, t := range result.Targets.InScope {
		prog.Assets = append(prog.Assets, Asset{
			Identifier: t.Name,
			Type:       t.Type,
			InScope:    true,
		})
	}
	for _, t := range result.Targets.OutOfScope {
		prog.Assets = append(prog.Assets, Asset{
			Identifier: t.Name,
			Type:       t.Type,
			InScope:    false,
		})
	}
	return prog, nil
}

// fetchIntigriti queries the Intigriti public program API.
// Public programs are accessible without authentication.
func fetchIntigriti(ctx context.Context, handle string) (*Program, error) {
	url := fmt.Sprintf("https://app.intigriti.com/api/v1/programs/%s", handle)
	client := &http.Client{Timeout: 15 * time.Second}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("intigriti: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("intigriti: HTTP %d for program %q", resp.StatusCode, handle)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result struct {
		Name    string `json:"name"`
		Domains []struct {
			Endpoint string `json:"endpoint"`
			Type     string `json:"type"`
		} `json:"domains"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("intigriti: parse: %w", err)
	}

	prog := &Program{
		Platform:  "intigriti",
		Handle:    handle,
		Name:      result.Name,
		FetchedAt: time.Now(),
	}
	for _, d := range result.Domains {
		prog.Assets = append(prog.Assets, Asset{
			Identifier: d.Endpoint,
			Type:       d.Type,
			InScope:    true,
		})
	}
	return prog, nil
}
