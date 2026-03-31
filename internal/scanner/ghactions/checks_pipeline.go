package ghactions

// checks_pipeline.go — detects supply-chain pipeline issues in CI/CD workflows:
// unsigned container images, mutable image tags, long-lived registry credentials,
// missing SBOMs, and missing vulnerability scans.

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
)

// ── Shared container build detection ────────────────────────────────────────

// reDockerBuildPush matches Docker build+push steps in workflows:
// - docker/build-push-action usage
// - docker build commands
// - docker push commands
// - docker buildx commands
var reDockerBuildPush = regexp.MustCompile(
	`(?i)(docker/build-push-action|docker\s+build\b|docker\s+push\b|docker\s+buildx\b)`)

// hasDockerBuildPush returns true if the workflow contains a container build+push step.
func hasDockerBuildPush(workflowYAML string) bool {
	return reDockerBuildPush.MatchString(workflowYAML)
}

// ── checkImageBuildNoSigning ────────────────────────────────────────────────

// reCosignSigning matches cosign signing steps in workflows.
var reCosignSigning = regexp.MustCompile(
	`(?i)(sigstore/cosign-installer|cosign\s+sign\b|cosign\s+attest\b)`)

// checkImageBuildNoSigning flags workflows that build and push container images
// without a corresponding cosign signing step. Unsigned images cannot be verified
// by downstream consumers, allowing a compromised registry or build pipeline to
// substitute a malicious image without detection.
func checkImageBuildNoSigning(workflowYAML, repo string) []finding.Finding {
	if !hasDockerBuildPush(workflowYAML) {
		return nil
	}
	if reCosignSigning.MatchString(workflowYAML) {
		return nil
	}
	return []finding.Finding{{
		CheckID:  finding.CheckCICDNoImageSigning,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Asset:    repo,
		Title:    fmt.Sprintf("Container image built and pushed without signing in %s", repo),
		Description: "The workflow builds and pushes a container image (via docker/build-push-action, " +
			"docker build, docker push, or docker buildx) but does not include a cosign signing step " +
			"(sigstore/cosign-installer, cosign sign, or cosign attest). Unsigned images cannot be " +
			"verified by downstream consumers — a compromised registry or build pipeline could " +
			"silently substitute a malicious image. " +
			"Fix: add sigstore/cosign-installer and a `cosign sign` step after the image push, " +
			"or use cosign attest to attach SLSA provenance.",
		Evidence: map[string]any{
			"repo":            repo,
			"docker_build":    true,
			"cosign_detected": false,
		},
		ProofCommand: fmt.Sprintf("curl -sH 'Accept: application/vnd.github+json' https://api.github.com/repos/%s/contents/.github/workflows", repo),
		DiscoveredAt: time.Now(),
	}}
}

// ── checkMutableImageTag ────────────────────────────────────────────────────

// mutableTags are image tag patterns considered mutable and dangerous for
// production deployments. These can be silently overwritten, meaning a
// previously-verified image can be replaced without changing the reference.
var mutableTags = []string{
	":latest",
	":main",
	":master",
	":dev",
	":staging",
}

// rePushTagLine matches image push/deploy references that include a tag.
// Looks for docker push, tags: in build-push-action, image: references, etc.
var rePushTagLine = regexp.MustCompile(
	`(?im)(docker\s+push\s+\S+|tags\s*:\s*.+|image\s*:\s*\S+)`)

// reImmutableRef matches immutable image references (SHA-pinned or github.sha).
var reImmutableRef = regexp.MustCompile(
	`(@sha256:|` +
		`\$\{\{\s*github\.sha\s*\}\})`)

// checkMutableImageTag flags workflows that push or deploy container images using
// mutable tags like :latest, :main, :master, :dev, or :staging. Mutable tags can
// be silently overwritten, meaning a previously-verified image can be replaced
// without changing the reference — undermining image provenance and rollback safety.
func checkMutableImageTag(workflowYAML, repo string) []finding.Finding {
	if !hasDockerBuildPush(workflowYAML) {
		return nil
	}

	// Extract all push/tag/image reference lines.
	matches := rePushTagLine.FindAllString(workflowYAML, -1)
	if len(matches) == 0 {
		return nil
	}

	var foundMutable []string
	for _, line := range matches {
		lower := strings.ToLower(line)
		for _, tag := range mutableTags {
			if strings.Contains(lower, tag) {
				// Check this specific line doesn't also have an immutable ref.
				if !reImmutableRef.MatchString(line) {
					foundMutable = append(foundMutable, tag)
				}
			}
		}
	}

	if len(foundMutable) == 0 {
		return nil
	}

	// Deduplicate tags.
	seen := make(map[string]struct{})
	var unique []string
	for _, tag := range foundMutable {
		if _, ok := seen[tag]; !ok {
			seen[tag] = struct{}{}
			unique = append(unique, tag)
		}
	}

	return []finding.Finding{{
		CheckID:  finding.CheckCICDMutableImageTag,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityMedium,
		Asset:    repo,
		Title:    fmt.Sprintf("Container image pushed with mutable tag (%s) in %s", strings.Join(unique, ", "), repo),
		Description: fmt.Sprintf(
			"The workflow pushes a container image using mutable tag(s): %s. "+
				"Mutable tags can be silently overwritten, meaning a previously-verified image "+
				"can be replaced without changing the reference. This undermines image provenance, "+
				"rollback safety, and supply chain integrity. "+
				"Fix: tag images with the git SHA (${{ github.sha }}) or a digest reference "+
				"(@sha256:...) instead of mutable tags. If :latest is needed for convenience, "+
				"also push a SHA-tagged version as the canonical reference.",
			strings.Join(unique, ", ")),
		Evidence: map[string]any{
			"repo":         repo,
			"mutable_tags": unique,
		},
		ProofCommand: fmt.Sprintf("curl -sH 'Accept: application/vnd.github+json' https://api.github.com/repos/%s/contents/.github/workflows", repo),
		DiscoveredAt: time.Now(),
	}}
}

// ── checkLongLivedRegistryCreds ─────────────────────────────────────────────

// registrySecretPatterns are secret names that indicate stored registry
// credentials — long-lived keys that should be replaced with OIDC federation.
var registrySecretPatterns = []string{
	"DOCKER_PASSWORD",
	"DOCKERHUB_TOKEN",
	"AWS_ACCESS_KEY_ID",
	"GCP_SA_KEY",
}

// reOIDCStep matches OIDC authentication steps that replace long-lived credentials.
var reOIDCStep = regexp.MustCompile(
	`(?i)(google-github-actions/auth|aws-actions/configure-aws-credentials[^}]*role-to-assume)`)

// checkLongLivedRegistryCreds flags workflows that use stored registry credential
// secrets (DOCKER_PASSWORD, DOCKERHUB_TOKEN, AWS_ACCESS_KEY_ID, GCP_SA_KEY)
// without a corresponding OIDC authentication step. Long-lived registry credentials
// are high-value targets: if leaked, they grant persistent push access to container
// registries until manually rotated.
func checkLongLivedRegistryCreds(workflowYAML, repo string) []finding.Finding {
	// Check for OIDC steps first — if present, credentials are federated.
	if reOIDCStep.MatchString(workflowYAML) {
		return nil
	}

	// Also check for aws-actions/configure-aws-credentials without role-to-assume
	// separately — the combined regex above handles the role-to-assume case.
	// If configure-aws-credentials is present WITH role-to-assume, the reOIDCStep
	// regex already matched and we returned above.

	// Collect all secret names referenced in this workflow.
	secretsUsed := make(map[string]struct{})
	for _, m := range reSecretRef.FindAllStringSubmatch(workflowYAML, -1) {
		if len(m) == 2 {
			secretsUsed[strings.ToUpper(m[1])] = struct{}{}
		}
	}
	if len(secretsUsed) == 0 {
		return nil
	}

	var found []string
	for _, secretName := range registrySecretPatterns {
		if _, ok := secretsUsed[secretName]; ok {
			found = append(found, secretName)
		}
	}
	if len(found) == 0 {
		return nil
	}

	return []finding.Finding{{
		CheckID:  finding.CheckCICDLongLivedRegistryCreds,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Asset:    repo,
		Title:    fmt.Sprintf("Long-lived registry credentials used without OIDC in %s", repo),
		Description: fmt.Sprintf(
			"The workflow uses stored registry credential secrets (%s) without a corresponding "+
				"OIDC authentication step (google-github-actions/auth or aws-actions/configure-aws-credentials "+
				"with role-to-assume). Long-lived registry credentials are high-value targets: if leaked "+
				"via a supply-chain attack, they grant persistent push access to container registries "+
				"until manually rotated. "+
				"Fix: replace stored secrets with OIDC-based authentication. For AWS, use "+
				"aws-actions/configure-aws-credentials with role-to-assume. For GCP, use "+
				"google-github-actions/auth with workload_identity_provider. For Docker Hub, "+
				"use GITHUB_TOKEN with ghcr.io or a fine-grained access token.",
			strings.Join(found, ", ")),
		Evidence: map[string]any{
			"repo":           repo,
			"secrets_found":  found,
			"oidc_detected":  false,
		},
		ProofCommand: fmt.Sprintf("curl -sH 'Accept: application/vnd.github+json' https://api.github.com/repos/%s/contents/.github/workflows", repo),
		DiscoveredAt: time.Now(),
	}}
}

// ── checkNoSBOM ─────────────────────────────────────────────────────────────

// reSBOMGeneration matches SBOM generation patterns in workflows.
var reSBOMGeneration = regexp.MustCompile(
	`(?i)(sbom:\s*true|syft\b|trivy\s+image\s+.*--format\s+spdx)`)

// checkNoSBOM flags workflows that build and push container images without
// generating a Software Bill of Materials (SBOM). Without an SBOM, downstream
// consumers cannot audit the image's dependencies for known vulnerabilities,
// license compliance issues, or unexpected components. Many supply-chain
// security frameworks (SLSA, EO 14028) require SBOMs for production software.
func checkNoSBOM(workflowYAML, repo string) []finding.Finding {
	if !hasDockerBuildPush(workflowYAML) {
		return nil
	}
	if reSBOMGeneration.MatchString(workflowYAML) {
		return nil
	}
	return []finding.Finding{{
		CheckID:  finding.CheckCICDNoSBOMGeneration,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityLow,
		Asset:    repo,
		Title:    fmt.Sprintf("Container image built without SBOM generation in %s", repo),
		Description: "The workflow builds and pushes a container image but does not generate a " +
			"Software Bill of Materials (SBOM). Without an SBOM, downstream consumers cannot " +
			"audit the image's dependencies for known vulnerabilities, license compliance issues, " +
			"or unexpected components. Many supply-chain security frameworks (SLSA, EO 14028) " +
			"require SBOMs for production software. " +
			"Fix: enable `sbom: true` in docker/build-push-action, or add a syft or " +
			"trivy image --format spdx step after the build to generate and attach an SBOM.",
		Evidence: map[string]any{
			"repo":          repo,
			"docker_build":  true,
			"sbom_detected": false,
		},
		ProofCommand: fmt.Sprintf("curl -sH 'Accept: application/vnd.github+json' https://api.github.com/repos/%s/contents/.github/workflows", repo),
		DiscoveredAt: time.Now(),
	}}
}

// ── checkNoVulnScan ─────────────────────────────────────────────────────────

// reVulnScan matches vulnerability scan patterns in workflows.
var reVulnScan = regexp.MustCompile(
	`(?i)(trivy\s+image\b|grype\b|snyk\s+container\s+test\b|docker\s+scout\b)`)

// checkNoVulnScan flags workflows that build and push container images without
// running a vulnerability scan. Without scanning, known CVEs in base images or
// installed packages ship to production undetected. A single unpatched critical
// vulnerability in a base image can compromise every deployment.
func checkNoVulnScan(workflowYAML, repo string) []finding.Finding {
	if !hasDockerBuildPush(workflowYAML) {
		return nil
	}
	if reVulnScan.MatchString(workflowYAML) {
		return nil
	}
	return []finding.Finding{{
		CheckID:  finding.CheckCICDNoVulnScan,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityMedium,
		Asset:    repo,
		Title:    fmt.Sprintf("Container image built without vulnerability scan in %s", repo),
		Description: "The workflow builds and pushes a container image but does not include a " +
			"vulnerability scan step (trivy image, grype, snyk container test, or docker scout). " +
			"Without scanning, known CVEs in base images or installed packages ship to production " +
			"undetected. A single unpatched critical vulnerability in a base image can compromise " +
			"every deployment. " +
			"Fix: add a vulnerability scanning step after the image build. Use trivy image, " +
			"grype, snyk container test, or docker scout to scan the built image before pushing.",
		Evidence: map[string]any{
			"repo":               repo,
			"docker_build":       true,
			"vuln_scan_detected": false,
		},
		ProofCommand: fmt.Sprintf("curl -sH 'Accept: application/vnd.github+json' https://api.github.com/repos/%s/contents/.github/workflows", repo),
		DiscoveredAt: time.Now(),
	}}
}
