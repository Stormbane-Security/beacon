package finding

// ComplianceTags returns the compliance framework control IDs that a given
// CheckID maps to. Returns nil if the check has no specific compliance mapping.
func ComplianceTags(id CheckID) []string {
	if tags, ok := complianceMap[id]; ok {
		return tags
	}
	return nil
}

var complianceMap = map[CheckID][]string{
	// Email
	CheckEmailSPFMissing:      {"SOC2-CC6.1", "NIST-PR.IP"},
	CheckEmailSPFSoftfail:     {"SOC2-CC6.1"},
	CheckEmailDMARCMissing:    {"SOC2-CC6.1", "NIST-PR.IP", "ISO27001-A.13.2"},
	CheckEmailDMARCPolicyNone: {"SOC2-CC6.1", "ISO27001-A.13.2"},
	CheckEmailSpoofable:       {"SOC2-CC6.1", "PCI-12.10", "HIPAA-164.308(a)(5)"},

	// TLS
	CheckTLSCertExpiry7d:   {"SOC2-CC9.1", "PCI-4.2.1"},
	CheckTLSCertExpiry30d:  {"SOC2-CC9.1", "PCI-4.2.1"},
	CheckTLSCertSelfSigned: {"SOC2-CC6.7", "PCI-4.2.1", "HIPAA-164.312(e)(2)"},
	CheckTLSProtocolTLS10:  {"PCI-4.2.1", "SOC2-CC6.7"},
	CheckTLSProtocolTLS11:  {"PCI-4.2.1", "SOC2-CC6.7"},
	CheckTLSWeakCipher:     {"PCI-4.2.1", "SOC2-CC6.7", "HIPAA-164.312(e)(2)"},
	CheckTLSHeartbleed:     {"PCI-6.3.3", "SOC2-CC6.6"},
	CheckTLSROBOT:          {"PCI-6.3.3"},

	// DNS
	CheckDNSAXFRAllowed:   {"SOC2-CC6.1", "ISO27001-A.12.4"},
	CheckDNSDanglingCNAME: {"SOC2-CC6.6", "NIST-PR.IP"},

	// Exposure
	CheckExposureEnvFile:         {"SOC2-CC6.1", "PCI-6.3.1", "HIPAA-164.312(a)(1)"},
	CheckExposureGitExposed:      {"SOC2-CC6.1", "PCI-6.3.1"},
	CheckExposureAdminPath:       {"SOC2-CC6.6", "PCI-6.4"},
	CheckExposureSpringActuator:  {"SOC2-CC6.6", "PCI-6.4"},
	CheckExposureMonitoringPanel: {"SOC2-CC6.6"},
	CheckExposureCICDPanel:       {"SOC2-CC8.1", "PCI-6.3"},

	// DLP
	CheckDLPSSN:        {"HIPAA-164.312", "PCI-3.4", "SOC2-CC6.1"},
	CheckDLPCreditCard: {"PCI-3.4", "PCI-3.5", "SOC2-CC6.1"},
	CheckDLPDatabaseURL: {"SOC2-CC6.1", "PCI-6.3.1"},
	CheckDLPPrivateKey: {"SOC2-CC6.1", "PCI-6.3.1"},
	CheckDLPAPIKey:     {"SOC2-CC6.1", "PCI-6.3.1"},
	CheckDLPVision:     {"PCI-3.4", "HIPAA-164.312"},

	// Web
	CheckWebXSS:                {"PCI-6.4.1", "SOC2-CC6.6"},
	CheckWebSQLi:               {"PCI-6.4.1", "SOC2-CC6.6"},
	CheckWebDefaultCredentials: {"PCI-8.3.9", "SOC2-CC6.2"},

	// Port
	CheckPortRedisUnauth:         {"SOC2-CC6.6", "PCI-1.3", "NIST-PR.AC"},
	CheckPortElasticsearchUnauth: {"SOC2-CC6.6", "PCI-1.3", "HIPAA-164.312"},
	CheckPortDockerUnauth:        {"SOC2-CC6.6", "PCI-1.3", "NIST-PR.AC"},
	CheckPortRDPExposed:          {"SOC2-CC6.6", "PCI-1.3", "NIST-PR.AC"},
	CheckPortSMBExposed:          {"SOC2-CC6.6", "PCI-1.3"},
	CheckPortDatabaseExposed:     {"SOC2-CC6.6", "PCI-1.3", "HIPAA-164.312"},

	// GraphQL
	CheckGraphQLIntrospection: {"SOC2-CC6.6", "NIST-PR.IP"},

	// JS / CI
	CheckJSHardcodedSecret:  {"SOC2-CC6.1", "PCI-6.3.1"},
	CheckCICDScriptInjection: {"SOC2-CC8.1", "PCI-6.4"},
}
