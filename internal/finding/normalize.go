package finding

import "strings"

// NucleiTemplateToCheckID maps known Nuclei template IDs to canonical CheckIDs.
// Unmapped templates are stored with a "nuclei." prefix and the template ID.
var NucleiTemplateToCheckID = map[string]CheckID{
	// TLS
	"ssl-dns-names":           CheckTLSCertHostnameMismatch,
	"expired-ssl":             CheckTLSCertExpiry7d,
	"expiring-ssl-30d":        CheckTLSCertExpiry30d,
	"self-signed-ssl":         CheckTLSCertSelfSigned,
	"untrusted-root-certificate": CheckTLSCertChainInvalid,

	// DNS
	"dns-zone-transfer":       CheckDNSAXFRAllowed,
	"missing-caa-record":      CheckDNSMissingCAA,
	"dnssec-detection":        CheckDNSDNSSECMissing,

	// Headers
	"missing-csp":             CheckHeadersMissingCSP,
	"missing-hsts":            CheckHeadersMissingHSTS,
	"missing-x-frame-options": CheckHeadersMissingXFrameOptions,
	"x-content-type-options":  CheckHeadersMissingXContentType,
	"referrer-policy":         CheckHeadersMissingReferrerPolicy,
	"permissions-policy":      CheckHeadersMissingPermissionsPolicy,

	// Exposure
	"git-config":              CheckExposureGitExposed,
	"git-head":                CheckExposureGitExposed,
	"ds-store":                CheckExposureGitExposed,
	"swagger-api":             CheckExposureAPIDocs,
	"swagger-ui":              CheckExposureAPIDocs,
	"graphql-introspection":   CheckExposureAPIDocs,
	"openapi":                 CheckExposureAPIDocs,
	"grafana-default-credentials": CheckExposureMonitoringPanel,
	"grafana-unauth":          CheckExposureMonitoringPanel,
	"prometheus-metrics":      CheckExposureMonitoringPanel,
	"kibana-unauth":           CheckExposureMonitoringPanel,
	"jupyter-unauth":          CheckExposureMonitoringPanel,
	"jenkins-unauth":          CheckExposureCICDPanel,
	"jenkins-login":           CheckExposureCICDPanel,
	"gitlab-unauth":           CheckExposureCICDPanel,
	"spring-actuator":         CheckExposureSpringActuator,
	"spring-actuator-env":     CheckExposureSpringActuator,
	"heapdump":                CheckExposureSpringActuator,
	"s3-bucket-listing":       CheckNucleiS3BucketExposed,
	"aws-bucket-service":      CheckNucleiS3BucketExposed,
	"cors-misconfig":          CheckNucleiMisconfiguredCORS,
	"dotenv-file":             CheckExposureEnvFile,
	"laravel-env":             CheckExposureEnvFile,
	"backup-files":            CheckExposureBackupFile,
	"db-backup-files":         CheckExposureBackupFile,
	"admin-panel":             CheckExposureAdminPath,
	"wp-login":                CheckExposureAdminPath,
	"robots-txt-endpoint":     CheckExposureRobotsLeak,
	"http-missing-security-headers": CheckHeadersMissingHSTS,

	// Subdomain takeover
	"subdomain-takeover":      CheckSubdomainTakeover,
	"azure-takeover-detection": CheckSubdomainTakeover,
	"aws-bucket-takeover":     CheckSubdomainTakeover,
	"github-pages-takeover":   CheckSubdomainTakeover,
	"netlify-takeover":        CheckSubdomainTakeover,
	"heroku-takeover":         CheckSubdomainTakeover,

	// Web
	"xss":                     CheckWebXSS,
	"sqli":                    CheckWebSQLi,
	"open-redirect":           CheckWebOpenRedirect,
	"ssrf":                    CheckWebSSRF,
	"path-traversal":          CheckWebPathTraversal,
	"default-login":           CheckWebDefaultCredentials,
}

// MapNucleiTemplate converts a Nuclei template ID to a CheckID.
// Falls back to "nuclei.<template-id>" if not in the map.
func MapNucleiTemplate(templateID string) CheckID {
	if id, ok := NucleiTemplateToCheckID[templateID]; ok {
		return id
	}
	// Normalize: lowercase, replace spaces with dashes
	normalized := strings.ToLower(strings.ReplaceAll(templateID, " ", "-"))
	return "nuclei." + normalized
}
