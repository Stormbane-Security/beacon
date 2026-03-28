package analyze

// deterministicrules.go — compound attack pattern detection that runs
// without any AI calls. Rules fire when two or more individual findings
// that are each low-severity or harmless in isolation combine into a
// meaningful attack chain.
//
// Each rule specifies:
//   - a set of required CheckIDs (all must be present for the same domain)
//   - whether the checks must be on the same asset or any asset in the domain
//   - the resulting CorrelationFinding to emit

import (
	"context"
	"fmt"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/store"
)

// compoundRule describes one deterministic correlation pattern.
type compoundRule struct {
	// id is the CheckID to emit when the rule fires.
	id finding.CheckID
	// title and description for the emitted CorrelationFinding.
	title       string
	description string
	remediation string
	severity    finding.Severity
	// required is the set of CheckIDs that must ALL be present.
	required []finding.CheckID
	// sameAsset: if true, all required checks must be on the same asset.
	// If false, they may span any assets in the same domain/scan run.
	sameAsset bool
}

// deterministicRules is the authoritative rule list.
// Rules are evaluated against all findings for a scan run.
// Add new rules here; the engine in RunDeterministicCorrelations handles the rest.
var deterministicRules = []compoundRule{
	// ── Email spoofing + authentication bypass ──────────────────────────
	// Weak email auth alone is a spam/phishing risk. A login portal on the
	// same domain means an attacker can also spoof password-reset emails and
	// take over user accounts.
	{
		id:       finding.CheckCorrelationEmailPlusLogin,
		severity: finding.SeverityHigh,
		title:    "Email spoofing enables account takeover via password reset",
		description: "The domain has weak email authentication (missing or permissive SPF/DMARC) " +
			"and an OAuth or login endpoint. An attacker can spoof password-reset or verification " +
			"emails from this domain and use them to take over user accounts on the login endpoint. " +
			"Neither issue is critical alone; together they form a full account-takeover chain.",
		remediation: "Set DMARC policy to 'reject' and tighten SPF to '-all'. " +
			"Enforce email verification with a DKIM-signed token rather than a plain link.",
		required: []finding.CheckID{
			finding.CheckEmailDMARCMissing,
			finding.CheckOAuthMissingState, // OAuth login present
		},
		sameAsset: false,
	},
	{
		id:       finding.CheckCorrelationEmailPlusLogin,
		severity: finding.SeverityHigh,
		title:    "Email spoofing enables account takeover via password reset",
		description: "The domain has a DMARC policy of 'none' (monitoring only) " +
			"and an OAuth or login endpoint. A 'none' policy does not prevent delivery of spoofed mail, " +
			"allowing an attacker to send convincing password-reset emails and hijack user accounts.",
		remediation: "Escalate DMARC policy from 'none' to 'quarantine' then 'reject'. " +
			"Enforce email verification with a DKIM-signed token.",
		required: []finding.CheckID{
			finding.CheckEmailDMARCPolicyNone,
			finding.CheckOAuthMissingState,
		},
		sameAsset: false,
	},

	// ── CI/CD secret exposure + deployed infrastructure ─────────────────
	// Secrets echoed in logs alone may only affect the CI environment.
	// When those secrets control deployed production infrastructure, the
	// blast radius becomes a full production compromise.
	{
		id:       finding.CheckCorrelationCICDToProd,
		severity: finding.SeverityCritical,
		title:    "CI/CD secret leakage chains to production infrastructure compromise",
		description: "GitHub Actions workflows echo or expose secrets in logs, " +
			"and those same workflows deploy to infrastructure discovered in this scan. " +
			"An attacker with access to workflow logs (e.g. via a fork PR or compromised runner) " +
			"can extract the secrets and directly compromise the production environment.",
		remediation: "Rotate all secrets exposed in workflow logs immediately. " +
			"Use GitHub's secret masking and audit all 'run:' steps that reference secrets. " +
			"Restrict pull_request_target triggers and require approval for fork PRs.",
		required: []finding.CheckID{
			finding.CheckGHActionSecretsEchoed,
			finding.CheckGHActionDeployTargets,
		},
		sameAsset: true,
	},
	{
		id:       finding.CheckCorrelationCICDToProd,
		severity: finding.SeverityCritical,
		title:    "Unsafe pull_request_target + secrets chains to production deployment",
		description: "A GitHub Actions workflow uses pull_request_target (which runs with repository " +
			"secrets) and also controls deployment to infrastructure observed in this scan. " +
			"A fork PR can trigger this workflow, gain access to repository secrets, and use them " +
			"to alter or compromise the production deployment.",
		remediation: "Replace pull_request_target with pull_request for any workflow that accesses " +
			"secrets. Add an explicit approval gate before any deployment step triggered by external PRs.",
		required: []finding.CheckID{
			finding.CheckGHActionPRTargetUnsafe,
			finding.CheckGHActionDeployTargets,
		},
		sameAsset: true,
	},

	// ── CORS + credentials exposure ─────────────────────────────────────
	// CORS misconfiguration is critical on its own, but when the same asset
	// also leaks a credential (API key, private key, database URL), an
	// attacker who exploits CORS can immediately pivot to backend systems.
	{
		id:       finding.CheckCorrelationAuthBypassViaProxy,
		severity: finding.SeverityCritical,
		title:    "CORS misconfiguration + credential leakage enables direct backend access",
		description: "The asset has a CORS misconfiguration that allows arbitrary origins to make " +
			"credentialed cross-origin requests, and also exposes a credential (API key, database URL, " +
			"or private key) in HTTP responses. An attacker who tricks a logged-in user into visiting " +
			"a malicious page can exfiltrate the session and use the leaked credential to access " +
			"backend systems directly.",
		remediation: "Fix the CORS policy to an explicit allowlist. Immediately rotate all leaked " +
			"credentials. Audit what backend access the leaked credential grants.",
		required: []finding.CheckID{
			finding.CheckCORSMisconfiguration,
			finding.CheckDLPAPIKey,
		},
		sameAsset: true,
	},
	{
		id:       finding.CheckCorrelationAuthBypassViaProxy,
		severity: finding.SeverityCritical,
		title:    "CORS misconfiguration + database credential leakage",
		description: "The asset has a CORS misconfiguration and a database connection string " +
			"exposed in its HTTP responses. An attacker can exploit CORS to exfiltrate both the " +
			"user session and the database credential, enabling direct database access.",
		remediation: "Fix the CORS policy to an explicit allowlist. Rotate all database credentials immediately.",
		required: []finding.CheckID{
			finding.CheckCORSMisconfiguration,
			finding.CheckDLPDatabaseURL,
		},
		sameAsset: true,
	},

	// ── Subdomain takeover + OAuth/login ────────────────────────────────
	// A dangling subdomain takeover on its own is serious. When an OAuth
	// redirect_uri or login flow can be pointed at that subdomain, it
	// becomes a full account-takeover primitive.
	{
		id:       finding.CheckCorrelationLateralMovement,
		severity: finding.SeverityCritical,
		title:    "Subdomain takeover enables OAuth redirect hijacking",
		description: "A subdomain is vulnerable to takeover (dangling DNS CNAME to a defunct " +
			"external service), and the domain uses OAuth. An attacker who claims the dangling " +
			"subdomain can register it as an OAuth redirect_uri and steal authorization codes or " +
			"access tokens from legitimate users, achieving full account takeover.",
		remediation: "Immediately remove or update the dangling DNS record. " +
			"Audit OAuth redirect_uri allowlists to ensure they cannot be pointed at uncontrolled subdomains.",
		required: []finding.CheckID{
			finding.CheckSubdomainTakeover,
			finding.CheckOAuthMissingState,
		},
		sameAsset: false,
	},
	{
		id:       finding.CheckCorrelationLateralMovement,
		severity: finding.SeverityCritical,
		title:    "Subdomain takeover enables OAuth redirect hijacking",
		description: "A subdomain is vulnerable to takeover and the domain has an OAuth open redirect. " +
			"An attacker who claims the dangling subdomain can receive authorization codes or tokens " +
			"redirected there, achieving full account takeover without any user interaction beyond " +
			"clicking a crafted link.",
		remediation: "Remove the dangling DNS record. Fix the OAuth redirect_uri allowlist to reject " +
			"unregistered domains. Enforce exact-match redirect validation (no prefix matching).",
		required: []finding.CheckID{
			finding.CheckSubdomainTakeover,
			finding.CheckOAuthOpenRedirect,
		},
		sameAsset: false,
	},

	// ── Private key leakage + live service ──────────────────────────────
	// A leaked private key is always critical, but pairing it with a live
	// TLS or authentication service makes exploitation immediate.
	{
		id:       finding.CheckCorrelationCredentialReuse,
		severity: finding.SeverityCritical,
		title:    "Leaked private key enables TLS or code-signing impersonation",
		description: "A PEM private key is exposed in HTTP responses and the same asset serves " +
			"HTTPS. If the exposed key matches the TLS certificate or a code-signing cert, an " +
			"attacker can impersonate the service, decrypt recorded traffic, or sign malicious artifacts.",
		remediation: "Rotate the private key and reissue all certificates signed with it immediately. " +
			"Audit where the private key file is stored and restrict access.",
		required: []finding.CheckID{
			finding.CheckDLPPrivateKey,
			finding.CheckTLSCertExpiry30d, // TLS is in use on this asset
		},
		sameAsset: true,
	},

	// ── Script injection + workflow_run / self-hosted runner ────────────
	// Script injection alone risks poisoning the build environment.
	// Combining with a self-hosted runner on a public repo means an attacker
	// can run arbitrary code on the runner host.
	{
		id:       finding.CheckCorrelationCICDToProd,
		severity: finding.SeverityCritical,
		title:    "Script injection + self-hosted runner enables runner host compromise",
		description: "A GitHub Actions workflow is vulnerable to script injection via untrusted " +
			"input (e.g. PR title or issue body used in a 'run:' step) and uses a self-hosted runner " +
			"on a public repository. An attacker can open a PR or issue with crafted content to " +
			"execute arbitrary commands on the runner host, potentially pivoting to internal infrastructure.",
		remediation: "Sanitize all untrusted input before using it in 'run:' steps. " +
			"Use GitHub-hosted runners for public-facing workflows, or restrict self-hosted runners " +
			"to private repositories with required reviewer approval.",
		required: []finding.CheckID{
			finding.CheckGHActionScriptInjection,
			finding.CheckGHActionSelfHostedPublic,
		},
		sameAsset: true,
	},

	// ── Staging exposed to prod ─────────────────────────────────────────
	// A staging asset with weak auth plus a credential leak means an attacker
	// can authenticate to staging and reuse those credentials on prod.
	{
		id:       finding.CheckCorrelationStagingToProd,
		severity: finding.SeverityHigh,
		title:    "Exposed staging credentials may be reused on production",
		description: "A staging or development asset is publicly reachable and leaks credentials " +
			"(API key or database URL) in its HTTP responses. Development environments frequently " +
			"share credentials with production or use production-adjacent services. An attacker who " +
			"accesses staging can pivot to production systems using the exposed credentials.",
		remediation: "Restrict staging access to VPN or IP allowlists. " +
			"Use separate credentials for each environment and rotate the exposed credentials immediately.",
		required: []finding.CheckID{
			finding.CheckDLPAPIKey,
			finding.CheckDLPDatabaseURL,
		},
		sameAsset: false, // may be on different staging vs prod assets
	},
}

// RunDeterministicCorrelations evaluates all deterministic compound rules
// against the findings for the given scan run. When a rule fires it:
//   1. Saves a CorrelationFinding (for beacon analyze / history).
//   2. Also saves a regular finding.Finding so the result appears in the TUI
//      findings list and on the relevant asset detail view immediately — no AI
//      analysis step required.
//
// Asset assignment: sameAsset rules attach to the matching asset. Cross-asset
// rules attach to the domain root (the scan domain itself) so the finding
// always has a visible home in the TUI.
//
// Each rule fires at most once per scan run (deduplicated by title).
func RunDeterministicCorrelations(ctx context.Context, st store.Store, scanRunID, domain string) ([]store.CorrelationFinding, error) {
	rawFindings, err := st.GetFindings(ctx, scanRunID)
	if err != nil {
		return nil, fmt.Errorf("deterministicrules: get findings: %w", err)
	}
	if len(rawFindings) == 0 {
		return nil, nil
	}

	// Build two indexes:
	//   byAsset[asset][checkID] = true  → for sameAsset rules
	//   allCheckIDs[checkID] = []asset  → for cross-asset rules
	byAsset := make(map[string]map[finding.CheckID]bool)
	allCheckIDs := make(map[finding.CheckID][]string)

	for _, f := range rawFindings {
		asset := f.Asset
		if byAsset[asset] == nil {
			byAsset[asset] = make(map[finding.CheckID]bool)
		}
		byAsset[asset][f.CheckID] = true
		allCheckIDs[f.CheckID] = append(allCheckIDs[f.CheckID], asset)
	}

	// contributing returns all assets that have any of the required CheckIDs,
	// or (nil, false) if any required CheckID is entirely absent from the run.
	contributing := func(ids []finding.CheckID) ([]string, bool) {
		seen := make(map[string]bool)
		for _, id := range ids {
			if _, ok := allCheckIDs[id]; !ok {
				return nil, false
			}
		}
		for _, id := range ids {
			for _, a := range allCheckIDs[id] {
				seen[a] = true
			}
		}
		out := make([]string, 0, len(seen))
		for a := range seen {
			out = append(out, a)
		}
		return out, true
	}

	emitted := make(map[string]bool) // deduplicate by title
	var corrResults []store.CorrelationFinding
	var plainFindings []finding.Finding

	for _, rule := range deterministicRules {
		if emitted[rule.title] {
			continue
		}

		var fired bool
		var affectedAssets []string
		var primaryAsset string // asset the finding.Finding is attached to
		var contributingChecks []string
		for _, id := range rule.required {
			contributingChecks = append(contributingChecks, string(id))
		}

		if rule.sameAsset {
			// All required checks must appear on a single asset.
			for asset, checks := range byAsset {
				allPresent := true
				for _, id := range rule.required {
					if !checks[id] {
						allPresent = false
						break
					}
				}
				if allPresent {
					fired = true
					affectedAssets = []string{asset}
					primaryAsset = asset
					break
				}
			}
		} else {
			var ok bool
			affectedAssets, ok = contributing(rule.required)
			if ok {
				fired = true
				// Cross-asset: attach to the domain root so the finding is always visible.
				primaryAsset = domain
			}
		}

		if !fired {
			continue
		}

		emitted[rule.title] = true

		// 1. CorrelationFinding for history / beacon analyze.
		corrResults = append(corrResults, store.CorrelationFinding{
			ScanRunID:          scanRunID,
			Domain:             domain,
			Title:              rule.title,
			Severity:           rule.severity,
			Description:        rule.description,
			AffectedAssets:     affectedAssets,
			ContributingChecks: contributingChecks,
			Remediation:        rule.remediation,
			CreatedAt:          time.Now(),
		})

		// 2. Regular finding.Finding so it appears in TUI and asset detail.
		desc := rule.description
		if len(affectedAssets) > 1 {
			desc += fmt.Sprintf("\n\nAffected assets: %s", joinAssets(affectedAssets))
		}
		plainFindings = append(plainFindings, finding.Finding{
			CheckID:      rule.id,
			Module:       "correlation",
			Scanner:      "deterministicrules",
			Severity:     rule.severity,
			Asset:        primaryAsset,
			Title:        rule.title,
			Description:  desc,
			ProofCommand: proofCommandForRule(rule.required, affectedAssets),
			Evidence: map[string]any{
				"contributing_checks": contributingChecks,
				"affected_assets":     affectedAssets,
			},
			DiscoveredAt: time.Now(),
		})
	}

	if len(corrResults) == 0 {
		return nil, nil
	}

	if err := st.SaveCorrelationFindings(ctx, corrResults); err != nil {
		return nil, fmt.Errorf("deterministicrules: save correlations: %w", err)
	}
	if len(plainFindings) > 0 {
		if err := st.SaveFindings(ctx, scanRunID, plainFindings); err != nil {
			return nil, fmt.Errorf("deterministicrules: save findings: %w", err)
		}
	}
	return corrResults, nil
}

// joinAssets formats a list of asset names for display, capped to avoid huge strings.
func joinAssets(assets []string) string {
	const max = 5
	if len(assets) <= max {
		return fmt.Sprintf("%v", assets)
	}
	return fmt.Sprintf("%v (+%d more)", assets[:max], len(assets)-max)
}

// proofCommandForRule builds a minimal proof command listing the contributing checks.
func proofCommandForRule(ids []finding.CheckID, assets []string) string {
	checks := make([]string, len(ids))
	for i, id := range ids {
		checks[i] = string(id)
	}
	if len(assets) == 1 {
		return fmt.Sprintf("# Compound rule on %s: requires %v", assets[0], checks)
	}
	return fmt.Sprintf("# Cross-asset compound rule: requires %v across %s", checks, joinAssets(assets))
}
