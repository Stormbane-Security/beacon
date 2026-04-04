package portscan

import (
	"context"
	"fmt"

	"github.com/stormbane-security/beacon/internal/finding"
)

func init() {
	registerProbe(ServiceProbe{
		Name:         "redis",
		Category:     ProbeCatProtocol,
		DefaultPorts: []int{6379},
		Detect:       detectRedis,
	})
}

func detectRedis(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	unauth, redisVersion := probeRedis(ctx, host, port)
	if !unauth {
		return nil
	}

	ev := map[string]any{"port": port, "service": "redis", "authenticated": false, "banner": banner}
	if redisVersion != "" {
		ev["redis_version"] = redisVersion
	}
	findings := []finding.Finding{makeF(
		finding.CheckPortRedisUnauth,
		finding.SeverityCritical,
		fmt.Sprintf("Unauthenticated Redis exposed on port %d", port),
		"A Redis instance is accepting connections without authentication. "+
			"An attacker can read, write, or delete all cached data, potentially "+
			"achieving remote code execution via CONFIG SET and cron jobs.",
		ev,
	)}

	if redisVersion != "" && isVulnerableRedis(redisVersion) {
		cveEv := map[string]any{"port": port, "service": "redis", "redis_version": redisVersion, "cve": "CVE-2025-49844"}
		findings = append(findings, makeF(
			finding.CheckPortRedisVulnerableCVE2025,
			finding.SeverityCritical,
			fmt.Sprintf("Redis %s is vulnerable to CVE-2025-49844 (unauthenticated RCE)", redisVersion),
			"CVE-2025-49844 (CVSS 9.8) allows an unauthenticated attacker to execute arbitrary commands "+
				"on the Redis server via crafted Lua scripts. Patched in 7.2.11, 7.4.6, 8.0.4, 8.2.2. "+
				"Combined with unauthenticated access, this enables full server compromise without credentials.",
			cveEv,
		))
	}
	return findings
}
