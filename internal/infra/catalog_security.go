package infra

// Security tools: secrets management, WAF, IDS/IPS, SAST/DAST, and identity.

const (
	Vault        Technology = "vault"
	AWSSecretsManager Technology = "aws-secrets-manager"
	GCPSecretMgr Technology = "gcp-secret-manager-tool"
	AzureKeyVaultTool Technology = "azure-key-vault-tool"
	CyberArkConjur Technology = "conjur"
	SOPS         Technology = "sops"

	ModSecurity  Technology = "modsecurity"
	Crowdsec     Technology = "crowdsec"
	Fail2Ban     Technology = "fail2ban"
	Snort        Technology = "snort"
	Suricata     Technology = "suricata"
	OSSEC        Technology = "ossec"
	Wazuh        Technology = "wazuh"
	Falco        Technology = "falco"

	Keycloak     Technology = "keycloak"
	Auth0        Technology = "auth0"
	Okta         Technology = "okta"
	Dex          Technology = "dex"
	Zitadel      Technology = "zitadel"

	Trivy        Technology = "trivy"
	Grype        Technology = "grype"
	SonarQube    Technology = "sonarqube"
	Semgrep      Technology = "semgrep"
	Snyk         Technology = "snyk"
	Dependabot   Technology = "dependabot"
	Renovate     Technology = "renovate"

	CertManager  Technology = "cert-manager"
	LetsEncrypt  Technology = "letsencrypt"
	StepCA       Technology = "step-ca"
)

func init() {
	// ── Secrets Management ──
	for _, m := range []*TechMeta{
		{ID: Vault, Name: "HashiCorp Vault", Category: CategorySecurity, OpenSource: true, Vendor: "HashiCorp", DefaultPorts: []int{8200}, DockerImage: "hashicorp/vault:latest", Tags: []string{"secrets"}},
		{ID: AWSSecretsManager, Name: "AWS Secrets Manager", Category: CategorySecurity, CloudProvider: AWS, Vendor: "Amazon", Tags: []string{"secrets"}},
		{ID: GCPSecretMgr, Name: "GCP Secret Manager", Category: CategorySecurity, CloudProvider: GCP, Vendor: "Google", Tags: []string{"secrets"}},
		{ID: AzureKeyVaultTool, Name: "Azure Key Vault", Category: CategorySecurity, CloudProvider: Azure, Vendor: "Microsoft", Tags: []string{"secrets"}},
		{ID: CyberArkConjur, Name: "CyberArk Conjur", Category: CategorySecurity, OpenSource: true, Vendor: "CyberArk", Tags: []string{"secrets"}},
		{ID: SOPS, Name: "SOPS", Category: CategorySecurity, OpenSource: true, Vendor: "Mozilla/CNCF", Tags: []string{"secrets", "encryption"}},
	} {
		Register(m)
	}

	// ── WAF / IDS / IPS ──
	for _, m := range []*TechMeta{
		{ID: ModSecurity, Name: "ModSecurity", Category: CategorySecurity, OpenSource: true, Vendor: "Trustwave/OWASP", Tags: []string{"waf"}},
		{ID: Crowdsec, Name: "CrowdSec", Category: CategorySecurity, OpenSource: true, Vendor: "CrowdSec", DockerImage: "crowdsecurity/crowdsec:latest", Tags: []string{"ids", "waf"}},
		{ID: Fail2Ban, Name: "Fail2Ban", Category: CategorySecurity, OpenSource: true, Vendor: "Fail2Ban", Tags: []string{"ids"}},
		{ID: Snort, Name: "Snort", Category: CategorySecurity, OpenSource: true, Vendor: "Cisco/Sourcefire", Tags: []string{"ids", "ips"}},
		{ID: Suricata, Name: "Suricata", Category: CategorySecurity, OpenSource: true, Vendor: "OISF", Tags: []string{"ids", "ips"}},
		{ID: OSSEC, Name: "OSSEC", Category: CategorySecurity, OpenSource: true, Vendor: "OSSEC Foundation", Tags: []string{"hids"}},
		{ID: Wazuh, Name: "Wazuh", Category: CategorySecurity, OpenSource: true, Vendor: "Wazuh", DefaultPorts: []int{1514, 1515, 55000}, DockerImage: "wazuh/wazuh-manager:latest", Tags: []string{"siem", "hids"}},
		{ID: Falco, Name: "Falco", Category: CategorySecurity, OpenSource: true, Vendor: "CNCF/Sysdig", Tags: []string{"runtime-security", "k8s"}},
	} {
		Register(m)
	}

	// ── Identity & Auth Providers ──
	for _, m := range []*TechMeta{
		{ID: Keycloak, Name: "Keycloak", Category: CategoryAuth, OpenSource: true, Vendor: "Red Hat/CNCF", DefaultPorts: []int{8080, 8443}, DockerImage: "quay.io/keycloak/keycloak:latest", Tags: []string{"oidc", "saml"}},
		{ID: Auth0, Name: "Auth0", Category: CategoryAuth, Vendor: "Okta", Tags: []string{"oidc", "saml"}},
		{ID: Okta, Name: "Okta", Category: CategoryAuth, Vendor: "Okta", Tags: []string{"oidc", "saml", "sso"}},
		{ID: Dex, Name: "Dex", Category: CategoryAuth, OpenSource: true, Vendor: "CNCF", DefaultPorts: []int{5556}, Tags: []string{"oidc"}},
		{ID: Zitadel, Name: "Zitadel", Category: CategoryAuth, OpenSource: true, Vendor: "Zitadel", Tags: []string{"oidc", "saml"}},
	} {
		Register(m)
	}

	// ── Supply Chain & Vulnerability Scanning ──
	for _, m := range []*TechMeta{
		{ID: Trivy, Name: "Trivy", Category: CategorySecurity, OpenSource: true, Vendor: "Aqua Security", Tags: []string{"container-scanning", "sbom"}},
		{ID: Grype, Name: "Grype", Category: CategorySecurity, OpenSource: true, Vendor: "Anchore", Tags: []string{"container-scanning", "sbom"}},
		{ID: SonarQube, Name: "SonarQube", Category: CategorySecurity, OpenSource: true, Vendor: "SonarSource", DefaultPorts: []int{9000}, DockerImage: "sonarqube:lts-community", Tags: []string{"sast"}},
		{ID: Semgrep, Name: "Semgrep", Category: CategorySecurity, OpenSource: true, Vendor: "Semgrep Inc", Tags: []string{"sast"}},
		{ID: Snyk, Name: "Snyk", Category: CategorySecurity, Vendor: "Snyk", Tags: []string{"sca", "sast"}},
		{ID: Dependabot, Name: "Dependabot", Category: CategorySecurity, Vendor: "GitHub/Microsoft", Tags: []string{"sca"}},
		{ID: Renovate, Name: "Renovate", Category: CategorySecurity, OpenSource: true, Vendor: "Mend", Tags: []string{"sca"}},
	} {
		Register(m)
	}

	// ── Certificate Management ──
	for _, m := range []*TechMeta{
		{ID: CertManager, Name: "cert-manager", Category: CategorySecurity, OpenSource: true, Vendor: "CNCF/Jetstack", Tags: []string{"tls", "k8s"}},
		{ID: LetsEncrypt, Name: "Let's Encrypt", Category: CategorySecurity, OpenSource: true, Vendor: "ISRG", Tags: []string{"tls", "ca"}},
		{ID: StepCA, Name: "step-ca", Category: CategorySecurity, OpenSource: true, Vendor: "Smallstep", Tags: []string{"tls", "ca", "pki"}},
	} {
		Register(m)
	}
}
