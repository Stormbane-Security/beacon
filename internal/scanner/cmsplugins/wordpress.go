package cmsplugins

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
)

// probeWordPressUsers enumerates WordPress users via two methods:
// 1. Author archive enumeration (?author=1, ?author=2, ...)
// 2. REST API user listing (/wp-json/wp/v2/users)
func probeWordPressUsers(ctx context.Context, client *http.Client, asset, base string) []finding.Finding {
	var findings []finding.Finding
	now := time.Now()

	// Method 1: REST API user listing (fastest, most data)
	usersURL := base + "/wp-json/wp/v2/users"
	req, err := http.NewRequestWithContext(ctx, "GET", usersURL, nil)
	if err == nil {
		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
			bodyStr := string(body)

			if resp.StatusCode == 200 && strings.Contains(bodyStr, "slug") {
				// Count users by counting "id": occurrences
				userCount := strings.Count(bodyStr, `"id":`)
				findings = append(findings, finding.Finding{
					CheckID:     finding.CheckCMSWordPressRestAPI,
					Module:      "surface",
					Scanner:     scannerName,
					Severity:    finding.SeverityMedium,
					Title:       fmt.Sprintf("WordPress REST API exposes %d users on %s", userCount, asset),
					Description: "The WordPress REST API at /wp-json/wp/v2/users returns user data (usernames, names, avatar URLs) without authentication. An attacker can enumerate all users for targeted password attacks.",
					Asset:       asset,
					Evidence: map[string]any{
						"endpoint":   "/wp-json/wp/v2/users",
						"user_count": userCount,
						"cms":        "WordPress",
					},
					ProofCommand: fmt.Sprintf("curl -s '%s/wp-json/wp/v2/users' | python3 -c \"import sys,json; [print(u['slug']) for u in json.load(sys.stdin)]\"", base),
					DiscoveredAt: now,
				})
			}
		}
	}

	// Method 2: Author archive enumeration (works even if REST API is disabled)
	usernames := []string{}
	for id := 1; id <= 5; id++ {
		if ctx.Err() != nil {
			break
		}
		authorURL := fmt.Sprintf("%s/?author=%d", base, id)
		req, err := http.NewRequestWithContext(ctx, "GET", authorURL, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		// WordPress redirects to /author/<username>/ on valid author IDs
		if resp.StatusCode == 301 || resp.StatusCode == 302 {
			loc := resp.Header.Get("Location")
			if strings.Contains(loc, "/author/") {
				parts := strings.Split(strings.TrimSuffix(loc, "/"), "/author/")
				if len(parts) > 1 {
					usernames = append(usernames, parts[1])
				}
			}
		}
	}

	if len(usernames) > 0 && len(findings) == 0 {
		// Only emit if REST API didn't already find users
		findings = append(findings, finding.Finding{
			CheckID:     finding.CheckCMSWordPressUserEnum,
			Module:      "surface",
			Scanner:     scannerName,
			Severity:    finding.SeverityMedium,
			Title:       fmt.Sprintf("WordPress user enumeration: %d users found on %s", len(usernames), asset),
			Description: fmt.Sprintf("WordPress author archives expose usernames: %s. An attacker can use these for brute-force login attacks.", strings.Join(usernames, ", ")),
			Asset:       asset,
			Evidence: map[string]any{
				"method":    "author_archive",
				"usernames": usernames,
				"cms":       "WordPress",
			},
			ProofCommand: fmt.Sprintf("curl -sI '%s/?author=1' | grep Location", base),
			DiscoveredAt: now,
		})
	}

	return findings
}

// probeWordPressThemes detects the active WordPress theme by parsing HTML source.
func probeWordPressThemes(ctx context.Context, client *http.Client, asset, base string) []finding.Finding {
	var findings []finding.Finding
	now := time.Now()

	req, err := http.NewRequestWithContext(ctx, "GET", base+"/", nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	bodyStr := string(body)

	// Extract theme from /wp-content/themes/<name>/
	if idx := strings.Index(bodyStr, "/wp-content/themes/"); idx >= 0 {
		rest := bodyStr[idx+len("/wp-content/themes/"):]
		if slashIdx := strings.IndexAny(rest, "/'\""); slashIdx > 0 {
			theme := rest[:slashIdx]
			if theme != "" && !strings.Contains(theme, " ") {
				findings = append(findings, finding.Finding{
					CheckID:     finding.CheckCMSWordPressThemeFound,
					Module:      "surface",
					Scanner:     scannerName,
					Severity:    finding.SeverityInfo,
					Title:       fmt.Sprintf("WordPress theme detected: %s on %s", theme, asset),
					Description: fmt.Sprintf("The active WordPress theme is %q. Theme version and vulnerabilities should be checked.", theme),
					Asset:       asset,
					Evidence: map[string]any{
						"theme": theme,
						"cms":   "WordPress",
					},
					DiscoveredAt: now,
				})
			}
		}
	}

	return findings
}

// probeWordPressExtras checks for xmlrpc, debug.log, directory listing, wp-cron.
func probeWordPressExtras(ctx context.Context, client *http.Client, asset, base string) []finding.Finding {
	var findings []finding.Finding
	now := time.Now()

	// XML-RPC
	if status, body := quickGet(ctx, client, base+"/xmlrpc.php"); status == 200 || status == 405 {
		if strings.Contains(body, "XML-RPC server accepts POST requests only") || status == 405 {
			findings = append(findings, finding.Finding{
				CheckID:     finding.CheckCMSWordPressXMLRPC,
				Module:      "surface",
				Scanner:     scannerName,
				Severity:    finding.SeverityMedium,
				Title:       fmt.Sprintf("WordPress XML-RPC enabled on %s", asset),
				Description: "XML-RPC is enabled at /xmlrpc.php. This enables brute-force attacks (wp.getUsersBlogs), SSRF via pingback, and DDoS amplification via system.multicall.",
				Asset:       asset,
				Evidence:    map[string]any{"endpoint": "/xmlrpc.php", "cms": "WordPress"},
				ProofCommand: fmt.Sprintf("curl -s -X POST '%s/xmlrpc.php' -d '<?xml version=\"1.0\"?><methodCall><methodName>system.listMethods</methodName></methodCall>'", base),
				DiscoveredAt: now,
			})
		}
	}

	// Debug log
	if status, body := quickGet(ctx, client, base+"/wp-content/debug.log"); status == 200 && len(body) > 50 {
		findings = append(findings, finding.Finding{
			CheckID:     finding.CheckCMSWordPressDebugLog,
			Module:      "surface",
			Scanner:     scannerName,
			Severity:    finding.SeverityHigh,
			Title:       fmt.Sprintf("WordPress debug.log exposed on %s", asset),
			Description: "The WordPress debug log at /wp-content/debug.log is publicly accessible. It contains PHP errors, database queries, file paths, and potentially sensitive data.",
			Asset:       asset,
			Evidence:    map[string]any{"endpoint": "/wp-content/debug.log", "size": len(body), "cms": "WordPress"},
			ProofCommand: fmt.Sprintf("curl -s '%s/wp-content/debug.log' | head -20", base),
			DiscoveredAt: now,
		})
	}

	// Directory listing on uploads
	if status, body := quickGet(ctx, client, base+"/wp-content/uploads/"); status == 200 {
		if strings.Contains(body, "Index of") || strings.Contains(body, "<title>Index") {
			findings = append(findings, finding.Finding{
				CheckID:     finding.CheckCMSWordPressDirListing,
				Module:      "surface",
				Scanner:     scannerName,
				Severity:    finding.SeverityMedium,
				Title:       fmt.Sprintf("WordPress uploads directory listing on %s", asset),
				Description: "Directory listing is enabled on /wp-content/uploads/, exposing all uploaded files including potentially sensitive documents.",
				Asset:       asset,
				Evidence:    map[string]any{"endpoint": "/wp-content/uploads/", "cms": "WordPress"},
				ProofCommand: fmt.Sprintf("curl -s '%s/wp-content/uploads/' | grep -o 'href=\"[^\"]*\"'", base),
				DiscoveredAt: now,
			})
		}
	}

	return findings
}

func quickGet(ctx context.Context, client *http.Client, url string) (int, string) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, ""
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	return resp.StatusCode, string(body)
}
