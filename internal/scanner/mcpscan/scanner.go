// Package mcpscan detects exposed Model Context Protocol (MCP) servers
// and inspects their tool schemas for poisoning indicators.
//
// MCP servers expose tools via JSON-RPC or SSE transports. When unauthenticated,
// they allow arbitrary tool invocation. Tool poisoning embeds hidden instructions
// in tool descriptions/schemas that manipulate connected LLM agents.
//
// Surface mode: probes for exposed MCP endpoints.
// Deep mode: inspects tool schemas for poisoning patterns, tests command injection.
package mcpscan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/scan"
	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scanner/authctx"
	"github.com/stormbane-security/beacon/internal/scanner/schemedetect"
)


func init() {
	scan.RegisterWithCheckDecls(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	},
		scan.Check(finding.CheckMCPToolPoisoning, finding.SeverityHigh, finding.ModeDeep),
		scan.Check(finding.CheckMCPUnauthenticated, finding.SeverityCritical, finding.ModeSurface),
	)
}
const scannerName = "mcpscan"

// mcpPaths are common MCP server endpoint paths.
var mcpPaths = []string{
	"/mcp",
	"/mcp/init",
	"/mcp/tools",
	"/rpc",
	"/sse",
	"/api/tools",
	"/v1/tools",
}

// poisonPatterns match hidden instructions in tool schemas.
var poisonPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bignore\s+(previous|prior|all)\s+instructions?\b`),
	regexp.MustCompile(`(?i)\bdo\s+not\s+(tell|reveal|show|mention)\b`),
	regexp.MustCompile(`(?i)\byou\s+must\s+(always|never)\b`),
	regexp.MustCompile(`(?i)\bhidden\b.*\binstructions?\b`),
	regexp.MustCompile(`(?i)"lc"\s*:\s*1`), // LangChain serialization injection
	regexp.MustCompile(`(?i)\bsystem\s*:\s*["']`),
	regexp.MustCompile(`(?i)\b(exec|eval|system|subprocess|os\.)\b`),
}

type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanSurface && scanType != module.ScanDeep && scanType != module.ScanAuthorized {
		return nil, nil
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if c := authctx.HTTPClient(ctx); c != nil {
		client = c
	}

	base := schemedetect.Base(ctx, client, asset)
	var findings []finding.Finding

	// Surface: probe for MCP endpoint exposure.
	for _, path := range mcpPaths {
		if ctx.Err() != nil {
			break
		}
		f := s.probeMCPEndpoint(ctx, client, base, path, asset)
		if f != nil {
			findings = append(findings, *f)
			break // one finding is enough for unauthenticated access
		}
	}

	// Deep: check tool schemas for poisoning.
	if scanType == module.ScanDeep || scanType == module.ScanAuthorized {
		f := s.checkToolPoisoning(ctx, client, base, asset)
		if f != nil {
			findings = append(findings, *f)
		}
	}

	return findings, nil
}

func (s *Scanner) probeMCPEndpoint(ctx context.Context, client *http.Client, base, path, asset string) *finding.Finding {
	url := base + path

	// Try JSON-RPC initialize request.
	rpcBody, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  "initialize",
		"id":      1,
		"params": map[string]any{
			"protocolVersion": "2024-11-05",
			"clientInfo":      map[string]string{"name": "beacon-probe", "version": "1.0"},
		},
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(rpcBody))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner)")

	resp, err := client.Do(req)
	if err != nil {
		// Try GET for SSE transport.
		return s.probeSSE(ctx, client, url, asset)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	bodyStr := strings.ToLower(string(body))
	if strings.Contains(bodyStr, "protocolversion") ||
		strings.Contains(bodyStr, "servercapabilities") ||
		strings.Contains(bodyStr, "serverinfo") ||
		strings.Contains(bodyStr, "capabilities") {
		return &finding.Finding{
			CheckID:  finding.CheckMCPUnauthenticated,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityCritical,
			Title:    fmt.Sprintf("MCP server at %s accepts unauthenticated requests", path),
			Description: fmt.Sprintf(
				"A Model Context Protocol (MCP) server at %s responds to initialization "+
					"requests without authentication. MCP servers expose tools that can read/write "+
					"files, execute commands, or interact with external services. Unauthenticated "+
					"access allows attackers to invoke any registered tool.",
				asset),
			Asset: asset,
			ProofCommand: fmt.Sprintf(
				`curl -s -X POST '%s' -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","method":"initialize","id":1,"params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"test"}}}'`,
				url),
			Evidence: map[string]any{
				"url":           url,
				"transport":     "json-rpc",
				"response_size": len(body),
			},
			DiscoveredAt: time.Now(),
		}
	}

	return nil
}

func (s *Scanner) probeSSE(ctx context.Context, client *http.Client, url, asset string) *finding.Finding {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner)")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	resp.Body.Close()

	ct := resp.Header.Get("Content-Type")
	if resp.StatusCode == http.StatusOK &&
		(strings.Contains(ct, "text/event-stream") ||
			strings.Contains(string(body), "event:") ||
			strings.Contains(string(body), "data:")) {
		return &finding.Finding{
			CheckID:  finding.CheckMCPUnauthenticated,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityCritical,
			Title:    "MCP server SSE transport exposed without authentication",
			Description: fmt.Sprintf(
				"A Model Context Protocol (MCP) server at %s exposes an SSE (Server-Sent Events) "+
					"transport without authentication. Connected LLM agents can invoke all "+
					"registered tools via this endpoint.",
				asset),
			Asset: asset,
			ProofCommand: fmt.Sprintf(
				"curl -s -H 'Accept: text/event-stream' '%s'", url),
			Evidence: map[string]any{
				"url":          url,
				"transport":    "sse",
				"content_type": ct,
			},
			DiscoveredAt: time.Now(),
		}
	}
	return nil
}

func (s *Scanner) checkToolPoisoning(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	// Request tool listing via JSON-RPC.
	toolPaths := []string{"/mcp/tools", "/api/tools", "/v1/tools", "/rpc"}

	for _, path := range toolPaths {
		if ctx.Err() != nil {
			break
		}

		url := base + path
		rpcBody, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0",
			"method":  "tools/list",
			"id":      2,
		})

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(rpcBody))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			continue
		}

		bodyStr := string(body)
		for _, re := range poisonPatterns {
			if match := re.FindString(bodyStr); match != "" {
				return &finding.Finding{
					CheckID:  finding.CheckMCPToolPoisoning,
					Module:   "deep",
					Scanner:  scannerName,
					Severity: finding.SeverityHigh,
					Title:    "MCP tool schema contains hidden instructions (tool poisoning)",
					Description: fmt.Sprintf(
						"An MCP server at %s contains tool schemas with embedded instructions "+
							"that can manipulate connected LLM agents. The pattern %q was found in "+
							"a tool definition. Tool poisoning tricks LLM agents into performing "+
							"unintended actions when they read tool descriptions.",
						asset, match),
					Asset: asset,
					ProofCommand: fmt.Sprintf(
						`curl -s -X POST '%s' -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'`,
						url),
					Evidence: map[string]any{
						"url":           url,
						"poison_match":  match,
						"response_size": len(body),
					},
					DiscoveredAt: time.Now(),
				}
			}
		}
	}

	return nil
}
