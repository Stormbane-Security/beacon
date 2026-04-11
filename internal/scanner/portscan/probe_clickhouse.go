package portscan

import (
	"context"
	"fmt"
	"strings"

	"github.com/stormbane-security/beacon/internal/finding"
)

func init() {
	registerProbe(ServiceProbe{
		Name:         "clickhouse",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{8123},
		Detect:       detectClickHouse,
	})
}

func detectClickHouse(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	body, ok := probeHTTPBody(ctx, host, port, false, "/")
	if !ok {
		return nil
	}
	// ClickHouse returns "Ok." for non-browser UAs, or its HTML playground
	// (containing "ClickHouse" in the title/body) for browser-like UAs.
	trimmed := strings.TrimSpace(body)
	if trimmed != "Ok." && !strings.Contains(strings.ToLower(body), "clickhouse") {
		return nil
	}

	ev := map[string]any{"port": port, "service": "clickhouse"}
	if verBody, ok2 := probeHTTPBody(ctx, host, port, false, "/?query=SELECT+version()"); ok2 {
		ver := strings.TrimSpace(verBody)
		if ver != "" && !strings.ContainsAny(ver, "<>{") {
			ev["clickhouse_version"] = ver
			ev["version"] = ver
			ev["product"] = "ClickHouse " + ver
		}
	}

	return []finding.Finding{makeF(
		finding.CheckPortClickHouseExposed,
		finding.SeverityHigh,
		fmt.Sprintf("ClickHouse analytics database HTTP interface exposed on port %d", port),
		"The ClickHouse HTTP interface is publicly accessible. In default configuration, "+
			"ClickHouse allows unauthenticated read access via the HTTP API. "+
			"CVE-2018-14668 (CVSS 7.5) and CVE-2018-14669 (CVSS 9.1) allow arbitrary file "+
			"reads and unauthorized network access on older versions. Restrict to trusted networks "+
			"and enable authentication (user/password) in the ClickHouse configuration.",
		ev,
	)}
}
