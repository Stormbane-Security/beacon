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
	"ds-store":                CheckExposureSensitiveFile,
	"swagger-api":             CheckExposureAPIDocs,
	"swagger-ui":              CheckExposureAPIDocs,
	"graphql-introspection":   CheckGraphQLIntrospection,
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
	"subdomain-takeover":         CheckSubdomainTakeover,
	"azure-takeover-detection":   CheckSubdomainTakeover,
	"aws-bucket-takeover":        CheckSubdomainTakeover,
	"github-pages-takeover":      CheckSubdomainTakeover,
	"netlify-takeover":           CheckSubdomainTakeover,
	"heroku-takeover":            CheckSubdomainTakeover,
	"cname-service-detection":    CheckSubdomainTakeover,
	"s3-subdomain-takeover":      CheckSubdomainTakeover,
	"digitalocean-takeover":      CheckSubdomainTakeover,
	"fastly-takeover":            CheckSubdomainTakeover,
	"shopify-takeover":           CheckSubdomainTakeover,

	// Web
	"xss":                        CheckWebXSS,
	"reflected-xss":              CheckWebXSS,
	"sqli":                       CheckWebSQLi,
	"sql-injection":              CheckWebSQLi,
	"open-redirect":              CheckWebOpenRedirect,
	"open-redirect-detect":       CheckWebOpenRedirect,
	"ssrf":                       CheckWebSSRF,
	"ssrf-via-host-header":       CheckWebSSRF,
	"path-traversal":             CheckWebPathTraversal,
	"lfi":                        CheckWebPathTraversal,
	"default-login":              CheckWebDefaultCredentials,
	"default-credentials":        CheckWebDefaultCredentials,

	// Additional exposure mappings
	"spring-actuator-health":     CheckExposureSpringActuator,
	"spring-actuator-mappings":   CheckExposureSpringActuator,
	"spring-actuator-loggers":    CheckExposureSpringActuator,
	"spring-env":                 CheckExposureSpringActuator,
	"admin-panel-detect":         CheckExposureAdminPath,
	"phpmyadmin":                 CheckExposureAdminPath,
	"adminer":                    CheckExposureAdminPath,
	"wp-admin":                   CheckExposureAdminPath,
	"prometheus-exporter":        CheckExposureMonitoringPanel,
	"prometheus-exposed":         CheckExposureMonitoringPanel,
	"grafana-detect":             CheckExposureMonitoringPanel,
	"kibana-exposed":             CheckExposureMonitoringPanel,
	"elasticsearch-unauth":       CheckExposureMonitoringPanel,
	"jenkins-detect":             CheckExposureCICDPanel,
	"gitlab-detect":              CheckExposureCICDPanel,
	"gitlab-unauth-read":         CheckExposureCICDPanel,
	"argocd-unauth":              CheckExposureCICDPanel,
	"drone-ci-unauth":            CheckExposureCICDPanel,
	"env-file":                   CheckExposureEnvFile,
	"symfony-env":                CheckExposureEnvFile,
	"django-env":                 CheckExposureEnvFile,
	"git-exposed":                CheckExposureGitExposed,
	"svn-exposed":                CheckExposureVCSExposed,
	"hg-exposed":                 CheckExposureVCSExposed,
	"source-map-detect":          CheckExposureSourceMaps,
	"js-sourcemap":               CheckExposureSourceMaps,
	"security-txt":               CheckExposureSecurityTxt,
	"s3-bucket-exposed":          CheckNucleiS3BucketExposed,
	"public-s3-bucket":           CheckNucleiS3BucketExposed,

	// Default credentials (port services)
	"grafana-default-login":      CheckPortGrafanaDefaultCreds,
	"tomcat-default-login":       CheckPortTomcatDefaultCreds,
	"rabbitmq-default-login":     CheckPortRabbitMQDefaultCreds,

	// Additional TLS
	"ssl-weak-cipher":            CheckTLSWeakCipher,
	"tls-version":                CheckTLSProtocolTLS10,

	// CORS variants
	"cors-misconfiguration":      CheckNucleiMisconfiguredCORS,
	"cors-origin-reflection":     CheckNucleiMisconfiguredCORS,
}

// MapNucleiTemplate converts a Nuclei template ID to a CheckID.
// Falls back to "nuclei.<template-id>" if not in the map.
func MapNucleiTemplate(templateID string) CheckID {
	if id, ok := NucleiTemplateToCheckID[templateID]; ok {
		return id
	}
	// Normalize: lowercase, replace spaces with dashes
	normalized := strings.ToLower(strings.ReplaceAll(templateID, " ", "-"))
	id := CheckID("nuclei." + normalized)

	// Register the dynamic check ID as ModeSurface in the registry so
	// the ModeDeep safety gate doesn't drop it. Nuclei templates are
	// explicitly selected per scan mode (surface vs deep), so any finding
	// produced during a surface scan is surface-safe by definition.
	// Without this, unmapped IDs default to ModeDeep and get silently dropped.
	if _, exists := Registry[id]; !exists {
		Registry[id] = CheckMeta{CheckID: id, DefaultSeverity: SeverityInfo, Mode: ModeSurface}
	}
	return id
}
