package analyze

import (
	"fmt"
	"strings"

	"github.com/stormbane-security/beacon/internal/finding"
)

// AttackChain represents a set of findings that combine into a higher-impact attack path.
type AttackChain struct {
	// Findings is the subset of findings involved in this chain.
	Findings []finding.Finding
	// Impact describes the combined outcome: "Account takeover", "RCE + data exfil", etc.
	Impact string
	// Narrative is a plain-English attack path description.
	Narrative string
	// Severity is the chain's combined severity (usually the highest component or elevated).
	Severity finding.Severity
}

// chainPattern is an internal rule: if ALL of these CheckIDs are present in a finding set,
// it constitutes an attack chain.
type chainPattern struct {
	ids       []string // all must be present
	impact    string
	narrative string
	severity  finding.Severity
}

var knownChainPatterns = []chainPattern{
	{
		ids:    []string{"jwt.algorithm_confusion", "oauth.token_long_expiry"},
		impact: "Persistent authentication bypass",
		narrative: "An attacker can forge JWT tokens using the RS256-to-HS256 confusion attack, " +
			"and the long token expiry means forged tokens remain valid for extended periods.",
		severity: finding.SeverityCritical,
	},
	{
		ids:    []string{"iam.scim_unauthenticated", "iam.dynamic_client_reg"},
		impact: "Full account takeover via identity provider",
		narrative: "Unauthenticated SCIM exposes the full user directory. Dynamic client registration " +
			"allows creating a malicious OAuth client to phish any user with a legitimate-looking auth flow.",
		severity: finding.SeverityCritical,
	},
	{
		ids:    []string{"web.crlf_injection", "web.open_redirect"},
		impact: "Session hijacking via response splitting",
		narrative: "CRLF injection allows injecting arbitrary headers into responses. Combined with an " +
			"open redirect, an attacker can craft a URL that sets a malicious cookie and redirects to a " +
			"controlled page, enabling session fixation.",
		severity: finding.SeverityHigh,
	},
	{
		ids:    []string{"saml.signature_not_validated", "iam.idp_admin_exposed"},
		impact: "Admin account takeover via SAML bypass",
		narrative: "The SAML SP accepts unsigned assertions, allowing an attacker to craft an assertion " +
			"claiming admin identity. The exposed IdP admin panel provides a target endpoint to attack.",
		severity: finding.SeverityCritical,
	},
	{
		ids:    []string{"web.ssrf", "iam.cloud_metadata_ssrf"},
		impact: "Cloud credential theft via SSRF chain",
		narrative: "An SSRF vulnerability allows making server-side requests. The cloud metadata endpoint " +
			"(169.254.169.254) is reachable, enabling theft of IAM credentials that could grant AWS/GCP/Azure access.",
		severity: finding.SeverityCritical,
	},
	{
		ids:    []string{"web.ssti", "tls.cert_expiry_30d"},
		impact: "RCE on degraded security posture",
		narrative: "Server-side template injection enables remote code execution. The expiring TLS certificate " +
			"indicates the service may be neglected, reducing the chance of prompt patching.",
		severity: finding.SeverityCritical,
	},
	{
		ids:    []string{"jwt.audience_missing", "iam.token_introspect_exposed"},
		impact: "Cross-service token reuse",
		narrative: "JWT audience validation is missing, so tokens issued for one service can be replayed " +
			"against another. The exposed token introspection endpoint lets an attacker verify which tokens are still active.",
		severity: finding.SeverityHigh,
	},

	// ── Kubernetes lateral movement chains ───────────────────────────────

	{
		ids:    []string{"cloud.gcp.gke_legacy_metadata", "cloud.gcp.gke_node_default_sa"},
		impact: "GKE cluster takeover via metadata + default SA",
		narrative: "Legacy metadata endpoints (v0.1/v1beta1) do not require the Metadata-Flavor header, " +
			"so any pod with SSRF or code execution can reach 169.254.169.254. The nodes run the default " +
			"Compute Engine service account (project-editor), so stolen credentials grant full project access " +
			"including Compute, Storage, and IAM.",
		severity: finding.SeverityCritical,
	},
	{
		ids:    []string{"cloud.gcp.gke_no_network_policy", "cloud.gcp.gke_legacy_metadata"},
		impact: "Unrestricted pod-to-pod + metadata lateral movement",
		narrative: "Without network policy enforcement, any compromised pod can reach all other pods and " +
			"services in the cluster. Combined with the legacy metadata endpoint, an attacker can move laterally " +
			"between pods and escalate to node-level cloud credentials.",
		severity: finding.SeverityCritical,
	},
	{
		ids:    []string{"cloud.aws.eks_no_irsa", "cloud.aws.eks_no_secret_encryption"},
		impact: "EKS credential theft via unencrypted secrets + node role",
		narrative: "Without IRSA, all pods share the node's IAM role. Kubernetes secrets are stored unencrypted " +
			"in etcd, so an attacker with etcd access or API server read permissions can extract all secrets " +
			"and use the broad node IAM role for cloud API access.",
		severity: finding.SeverityCritical,
	},
	{
		ids:    []string{"cloud.aws.eks_no_network_policy", "cloud.aws.eks_no_irsa"},
		impact: "EKS lateral movement with shared IAM credentials",
		narrative: "No network policy enforcement allows unrestricted pod-to-pod communication. Without IRSA, " +
			"all pods inherit the node's IAM role. An attacker can move between pods freely and use the shared " +
			"IAM credentials for cloud access from any compromised workload.",
		severity: finding.SeverityHigh,
	},
	{
		ids:    []string{"cloud.aws.eks_no_private_endpoint", "cloud.aws.eks_no_secret_encryption"},
		impact: "EKS API exposure with unprotected secrets",
		narrative: "The public EKS API endpoint allows external access to the cluster control plane. " +
			"Kubernetes secrets stored without KMS encryption can be read by anyone with API access, " +
			"potentially exposing database credentials, API keys, and TLS certificates.",
		severity: finding.SeverityHigh,
	},
	{
		ids:    []string{"cloud.azure.aks_no_managed_identity", "cloud.azure.aks_no_aad_integration"},
		impact: "AKS cluster with weak identity controls",
		narrative: "Using a service principal instead of managed identity means long-lived credentials that " +
			"can be leaked. Without Azure AD integration, Kubernetes RBAC is not tied to organizational " +
			"identity, making access control and audit trails significantly weaker.",
		severity: finding.SeverityHigh,
	},
	{
		ids:    []string{"port.etcd_exposed", "port.k8s_api_exposed"},
		impact: "Full Kubernetes cluster compromise via exposed control plane",
		narrative: "The etcd database (containing all cluster state including secrets) and the Kubernetes " +
			"API server are both externally accessible. An attacker can read all secrets from etcd or " +
			"create privileged pods via the API server to take over the entire cluster and its workloads.",
		severity: finding.SeverityCritical,
	},
	{
		ids:    []string{"port.kubelet_readonly_exposed", "port.k8s_api_exposed"},
		impact: "K8s reconnaissance + control plane access",
		narrative: "The kubelet read-only port exposes pod listings, resource usage, and container specs " +
			"without authentication. Combined with an exposed API server, an attacker can enumerate all " +
			"workloads and then interact with the control plane to schedule malicious containers.",
		severity: finding.SeverityCritical,
	},

	// ── CI/CD to cloud lateral movement ──────────────────────────────────

	{
		ids:    []string{"ghaction.oidc_trust_too_wide", "ghaction.unpinned_action"},
		impact: "Cloud credential theft via supply chain + OIDC",
		narrative: "A compromised or hijacked unpinned action runs in a workflow with overly broad OIDC " +
			"federation trust. The attacker's code can request cloud credentials (AWS/GCP/Azure) scoped " +
			"beyond the intended repository or environment, gaining persistent cloud access.",
		severity: finding.SeverityCritical,
	},
	{
		ids:    []string{"ghaction.pull_request_target_unsafe", "ghaction.secrets_echoed"},
		impact: "Secret exfiltration via privileged PR workflow",
		narrative: "A pull_request_target workflow with unsafe checkout runs attacker-controlled code with " +
			"access to repository secrets. The workflow also echoes secrets to logs, providing a second " +
			"exfiltration channel. Combined, this enables full secret theft from any fork PR.",
		severity: finding.SeverityCritical,
	},
	{
		ids:    []string{"ghaction.runner_metadata_access", "ghaction.self_hosted_on_public_repo"},
		impact: "Cloud metadata theft from public repo runner",
		narrative: "A self-hosted runner in a public repository can be targeted by any GitHub user via " +
			"fork PRs. The runner can reach the cloud metadata service at 169.254.169.254, allowing " +
			"an attacker to steal cloud credentials from the runner's host environment.",
		severity: finding.SeverityCritical,
	},

	// ── Cross-cloud + SSRF chains ────────────────────────────────────────

	{
		ids:    []string{"web.ssrf", "port.kubelet_readonly_exposed"},
		impact: "K8s workload enumeration via SSRF",
		narrative: "An SSRF vulnerability allows reaching the kubelet read-only API (port 10255), " +
			"which exposes pod specs, environment variables (potentially containing secrets), " +
			"and container resource information without authentication.",
		severity: finding.SeverityHigh,
	},
	{
		ids:    []string{"web.ssrf", "port.etcd_exposed"},
		impact: "Full cluster secret theft via SSRF to etcd",
		narrative: "An SSRF vulnerability can reach the etcd API (port 2379), which stores all " +
			"Kubernetes cluster state including secrets in plaintext. An attacker can extract " +
			"every secret, token, and certificate in the cluster.",
		severity: finding.SeverityCritical,
	},
}

// DetectChains identifies attack chains in a set of findings for a single asset.
// Returns only chains where all component findings are present.
func DetectChains(findings []finding.Finding) []AttackChain {
	// Build a set of all CheckIDs present.
	present := make(map[string]bool)
	byID := make(map[string]finding.Finding)
	for _, f := range findings {
		present[f.CheckID] = true
		byID[f.CheckID] = f
	}

	var chains []AttackChain
	for _, pattern := range knownChainPatterns {
		allPresent := true
		for _, id := range pattern.ids {
			if !present[id] {
				allPresent = false
				break
			}
		}
		if !allPresent {
			continue
		}
		var chainFindings []finding.Finding
		for _, id := range pattern.ids {
			chainFindings = append(chainFindings, byID[id])
		}
		chains = append(chains, AttackChain{
			Findings:  chainFindings,
			Impact:    pattern.impact,
			Narrative: pattern.narrative,
			Severity:  pattern.severity,
		})
	}
	return chains
}

// FormatChain returns a concise text representation of an attack chain for report output.
func FormatChain(c AttackChain) string {
	ids := make([]string, len(c.Findings))
	for i, f := range c.Findings {
		ids[i] = f.CheckID
	}
	return fmt.Sprintf("[%s] %s\n  Chain: %s\n  %s",
		c.Severity, c.Impact, strings.Join(ids, " + "), c.Narrative)
}
