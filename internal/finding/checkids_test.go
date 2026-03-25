package finding_test

import (
	"testing"

	"github.com/stormbane/beacon/internal/finding"
)

// allCheckIDs lists every CheckID constant defined in the package.
// If you add a new CheckID constant, add it here too — the test will
// then enforce that you also added it to Registry.
var allCheckIDs = []finding.CheckID{
	finding.CheckEmailSPFMissing,
	finding.CheckEmailSPFSoftfail,
	finding.CheckEmailSPFLookupLimit,
	finding.CheckEmailDMARCMissing,
	finding.CheckEmailDMARCPolicyNone,
	finding.CheckEmailDMARCSubdomainNone,
	finding.CheckEmailDMARCNoReporting,
	finding.CheckEmailDKIMMissing,
	finding.CheckEmailDKIMWeakKey,
	finding.CheckEmailMTASTSMissing,
	finding.CheckEmailMTASTSNotEnforced,
	finding.CheckEmailTLSRPTMissing,
	finding.CheckEmailBIMIMissing,
	finding.CheckEmailDANEMissing,
	finding.CheckEmailSpoofable,
	finding.CheckTLSCertExpiry7d,
	finding.CheckTLSCertExpiry30d,
	finding.CheckTLSCertSelfSigned,
	finding.CheckTLSCertHostnameMismatch,
	finding.CheckTLSCertChainInvalid,
	finding.CheckTLSProtocolTLS10,
	finding.CheckTLSProtocolTLS11,
	finding.CheckTLSWeakCipher,
	finding.CheckTLSHeartbleed,
	finding.CheckTLSPOODLE,
	finding.CheckTLSROBOT,
	finding.CheckDNSAXFRAllowed,
	finding.CheckDNSWildcard,
	finding.CheckDNSDanglingCNAME,
	finding.CheckDNSMissingCAA,
	finding.CheckDNSDNSSECMissing,
	finding.CheckHeadersMissingCSP,
	finding.CheckHeadersMissingHSTS,
	finding.CheckHeadersMissingXFrameOptions,
	finding.CheckHeadersMissingXContentType,
	finding.CheckHeadersMissingReferrerPolicy,
	finding.CheckHeadersMissingPermissionsPolicy,
	finding.CheckHeadersServerInfoLeak,
	finding.CheckExposureHTTPNoRedirect,
	finding.CheckExposureStagingSubdomain,
	finding.CheckExposureAdminPath,
	finding.CheckExposureRobotsLeak,
	finding.CheckExposureEnvFile,
	finding.CheckExposureGitExposed,
	finding.CheckExposureBackupFile,
	finding.CheckExposureAPIDocs,
	finding.CheckExposureMonitoringPanel,
	finding.CheckExposureCICDPanel,
	finding.CheckExposureSpringActuator,
	finding.CheckExposureCloudStorage,
	finding.CheckNucleiS3BucketExposed,
	finding.CheckNucleiMisconfiguredCORS,
	finding.CheckSubdomainTakeover,
	finding.CheckWebTechDetected,
	finding.CheckWebOutdatedSoftware,
	finding.CheckWebDebugEndpoint,
	finding.CheckWebErrorInfoLeak,
	finding.CheckWebXSS,
	finding.CheckWebSQLi,
	finding.CheckWebOpenRedirect,
	finding.CheckWebSSRF,
	finding.CheckWebPathTraversal,
	finding.CheckWebDefaultCredentials,
	finding.CheckWebHTTPRequestSmuggling,
	finding.CheckAssetReverseIP,
	finding.CheckAssetOrgDomains,
	finding.CheckAssetASNRanges,
	finding.CheckAssetPassiveDNS,
	finding.CheckAssetHistoricalURLs,
	finding.CheckAssetCrawlEndpoints,
	finding.CheckAssetScreenshot,
	finding.CheckWHOISDomainExpiry7d,
	finding.CheckWHOISDomainExpiry30d,
	finding.CheckWHOISDomainInfo,
	finding.CheckCloudBucketPublic,
	finding.CheckCloudBucketExists,
	finding.CheckJSHardcodedSecret,
	finding.CheckJSInternalEndpoint,
	finding.CheckJSSourceMapExposed,
	finding.CheckCookieMissingSecure,
	finding.CheckCookieMissingHTTPOnly,
	finding.CheckCookieMissingSameSite,
	finding.CheckCSPUnsafeInline,
	finding.CheckCSPUnsafeEval,
	finding.CheckCSPWildcardSource,
	finding.CheckWAFNotDetected,
	finding.CheckWAFDetected,
	finding.CheckPortServiceDiscovered,
	finding.CheckWAFOriginExposed,
	finding.CheckWAFBypassHeader,
	finding.CheckWAFInsecureMode,
	finding.CheckIDSDetected,
	finding.CheckGitHubPublicRepos,
	finding.CheckGitHubTrackedEnvFile,
	finding.CheckCICDUnpinnedAction,
	finding.CheckCICDScriptInjection,
	finding.CheckCICDPwnRequest,
	finding.CheckCICDBroadPermissions,
	finding.CheckSecretsAPIKey,
	// GitHub Actions — workflow behavior gaps
	finding.CheckGHActionWorkflowRunUnsafe,
	finding.CheckGHActionGitHubEnvInjection,
	finding.CheckGHActionSecretsInherit,
	finding.CheckGHActionInsecureCommands,
	finding.CheckGHActionBotConditionSpoofable,
	finding.CheckGHActionArtiPacked,
	finding.CheckGHActionCachePoisoning,
	// GitHub Actions — OIDC vs long-lived credential checks
	finding.CheckGHActionAWSLongLivedKey,
	finding.CheckGHActionGCPServiceAccountKey,
	finding.CheckGHActionAzureCredentials,
	finding.CheckGHActionNPMTokenNotOIDC,
	finding.CheckGHActionPyPITokenNotTrusted,
	finding.CheckGHActionDockerPasswordSecret,
	finding.CheckGHActionVercelToken,
	finding.CheckGHActionTerraformCloudToken,
	finding.CheckGHActionFlyToken,
	// GitHub repository configuration
	finding.CheckGitHubNoBranchProtection,
	finding.CheckGitHubNoSecretScanning,
	finding.CheckGitHubNoDependabot,
	finding.CheckGitHubNoSAST,
	finding.CheckGitHubNoVulnAlerts,
	finding.CheckGitHubForkWorkflowApproval,
	finding.CheckGitHubDefaultTokenWrite,
	finding.CheckGitHubActionsUnrestricted,
	finding.CheckGitHubWebhookNoSecret,
	finding.CheckGitHubOrgMFANotRequired,
	// GitHub secret/key leaks in source code
	finding.CheckGitHubSecretInCode,
	finding.CheckGitHubPrivateKeyInRepo,
	finding.CheckHarvesterEmails,
	finding.CheckHarvesterSubdomains,
	finding.CheckVisionServiceID,
	// OpenAPI / Swagger
	finding.CheckSwaggerExposed,
	// EVM smart contract analysis
	finding.CheckContractReentrancy,
	finding.CheckContractSelfDestruct,
	finding.CheckContractUncheckedCall,
	finding.CheckContractIntegerOverflow,
	finding.CheckContractSourceExposed,
	finding.CheckContractProxyAdmin,
	// Blockchain node detection
	finding.CheckChainNodeRPCExposed,
	finding.CheckChainNodeUnauthorized,
	finding.CheckChainNodeValidatorExposed,
	finding.CheckChainNodeMinerExposed,
	finding.CheckChainNodePeerCountLeak,
	finding.CheckChainNodeWSExposed,
	finding.CheckChainNodeGrafanaExposed,
	// Terraform / IaC static analysis
	finding.CheckTerraformS3BucketPublic,
	finding.CheckTerraformGCSBucketPublic,
	finding.CheckTerraformGKEPublicEndpoint,
	finding.CheckTerraformGKELegacyABAC,
	finding.CheckTerraformGKENoNetworkPolicy,
	finding.CheckTerraformRDSPublic,
	finding.CheckTerraformRDSUnencrypted,
	finding.CheckTerraformSGOpenIngress,
	finding.CheckTerraformIAMWildcardPolicy,
	finding.CheckTerraformIAMAdminPolicy,
	finding.CheckTerraformSecretsInCode,
	finding.CheckTerraformUnencryptedEBS,
	finding.CheckTerraformIMDSv1Enabled,
	finding.CheckTerraformPublicECRRepo,
	finding.CheckTerraformCloudFrontHTTP,
	finding.CheckTerraformLBHTTP,
	finding.CheckTerraformTFStatePublic,
	// Web3 / SIWE + SIWS
	finding.CheckWeb3SIWEEndpoint,
	finding.CheckWeb3SIWSDEndpoint,
	finding.CheckWeb3SIWEDomainBypass,
	finding.CheckWeb3SIWENonceReuse,
	finding.CheckWeb3SIWEReplay,
	finding.CheckWeb3SIWEChainMismatch,
	finding.CheckWeb3SIWEURIMismatch,
	finding.CheckWeb3SIWEOverHTTP,
	finding.CheckWeb3HorizontalEscalation,
	// Cross-asset correlation findings
	finding.CheckCorrelationCICDToProd,
	finding.CheckCorrelationAuthBypassViaProxy,
	finding.CheckCorrelationStagingToProd,
	finding.CheckCorrelationEmailPlusLogin,
	finding.CheckCorrelationCredentialReuse,
	finding.CheckCorrelationLateralMovement,
	finding.CheckCorrelationGeneric,
}

// TestAllCheckIDsRegistered ensures every CheckID constant has a Registry entry.
// This prevents a check from silently defaulting to ModeDeep (fail-closed fallback)
// when it should be explicitly tagged.
func TestAllCheckIDsRegistered(t *testing.T) {
	for _, id := range allCheckIDs {
		if _, ok := finding.Registry[id]; !ok {
			t.Errorf("CheckID %q is defined as a constant but has no entry in finding.Registry — add it", id)
		}
	}
}

// TestDeepChecksHaveCorrectMode ensures every ModeDeep check is intentional.
// If this fails, someone added a check to the registry as ModeDeep without
// reviewing whether it actually requires --permission-confirmed.
func TestDeepChecksHaveCorrectMode(t *testing.T) {
	knownDeep := map[finding.CheckID]bool{
		finding.CheckTLSProtocolSSLv2:        true,
		finding.CheckTLSProtocolSSLv3:        true,
		finding.CheckTLSProtocolTLS10:        true,
		finding.CheckTLSProtocolTLS11:        true,
		finding.CheckTLSWeakCipher:           true,
		finding.CheckTLSHeartbleed:           true,
		finding.CheckTLSPOODLE:              true,
		finding.CheckTLSROBOT:               true,
		finding.CheckWebXSS:                 true,
		finding.CheckWebSQLi:                true,
		finding.CheckWebOpenRedirect:        true,
		finding.CheckWebSSRF:                true,
		finding.CheckWebPathTraversal:         true,
		finding.CheckWebDefaultCredentials:    true,
		finding.CheckWebHTTPRequestSmuggling:  true,
		finding.CheckDirbustFound:             true,
		finding.CheckDirbustWAFBlocked:      true,
		finding.CheckWAFBypassHeader:    true,
		// Deep-mode scanners added in current session:
		finding.CheckCORSMisconfiguration:   true,
		finding.CheckHostHeaderInjection:    true,
		finding.CheckRateLimitMissing:       true,
		finding.CheckRateLimitBypass:        true,
		finding.CheckOAuthMissingState:      true,
		finding.CheckOAuthMissingPKCE:       true,
		finding.CheckOAuthOpenRedirect:      true,
		finding.CheckOAuthTokenLeakReferer:       true,
		finding.CheckJWTNoVerification:           true,
		finding.CheckGraphQLBatchQuery:           true,
		finding.CheckGraphQLPersistedQueryBypass: true,
		finding.CheckJenkinsGroovyRCE:            true,
		// DNS zone transfer is an active AXFR probe — requires --permission-confirmed
		finding.CheckDNSAXFRAllowed: true,
		// BEAST: CBC ciphers in TLS 1.0 — testssl.sh deep probe
		finding.CheckTLSBEAST: true,
		// Rate limit Retry-After absence — observed during deep rate-limit probing
		finding.CheckRateLimitNoRetryAfter: true,
		// nmap NSE vuln scripts require --permission-confirmed (active vulnerability probing)
		finding.CheckNmapVulnScript: true,
		// JWT/OIDC/OAuth deep active probes
		finding.CheckJWTAlgorithmConfusion:  true,
		finding.CheckJWTAudienceMissing:     true,
		finding.CheckJWTIssuerNotValidated:  true,
		finding.CheckJWTReplayMissing:       true,
		finding.CheckOAuthRefreshNotRotated: true,
		finding.CheckOAuthPKCEDowngrade:     true,
		// SAML active testing — requires sending crafted assertions
		finding.CheckSAMLSignatureNotValidated: true,
		finding.CheckSAMLXMLWrapping:           true,
		finding.CheckSAMLReplayAllowed:         true,
		finding.CheckSAMLIssuerNotValidated:    true,
		finding.CheckSAMLAudienceNotValidated:  true,
		finding.CheckSAMLXXEInjection:          true,
		finding.CheckSAMLOpenRedirect:          true,
		// Web3 / SIWE + SIWS deep probes
		finding.CheckWeb3SIWEDomainBypass:     true,
		finding.CheckWeb3SIWENonceReuse:       true,
		finding.CheckWeb3SIWEReplay:           true,
		finding.CheckWeb3SIWEChainMismatch:    true,
		finding.CheckWeb3SIWEURIMismatch:      true,
		finding.CheckWeb3HorizontalEscalation: true,
		// IAM active probes
		finding.CheckLDAPInjection:       true,
		finding.CheckCloudMetadataSSRF:   true,
		// Web injection / exploitation scanners
		finding.CheckWebSSTI:                true,
		finding.CheckWebCRLFInjection:       true,
		finding.CheckWebPrototypePollution:  true,
		finding.CheckWebXXE:                 true,
		finding.CheckWebInsecureDeserialize: true,
		finding.CheckWebHPP:                 true,
		finding.CheckWebFileUpload:          true,
		finding.CheckWebAPIFuzz:             true,
		// Log4Shell — deep mode sends JNDI payload in headers
		finding.CheckCVELog4Shell: true,
		// EVM contract vulnerability analysis — active Etherscan + RPC probes
		finding.CheckContractReentrancy:      true,
		finding.CheckContractSelfDestruct:    true,
		finding.CheckContractUncheckedCall:   true,
		finding.CheckContractIntegerOverflow: true,
	}

	for id, meta := range finding.Registry {
		if meta.Mode == finding.ModeDeep && !knownDeep[id] {
			t.Errorf("CheckID %q is tagged ModeDeep but is not in the known-deep allowlist — review and add it if intentional", id)
		}
		if meta.Mode == finding.ModeSurface && knownDeep[id] {
			t.Errorf("CheckID %q is in the known-deep allowlist but is tagged ModeSurface — fix the registry entry", id)
		}
	}
}

// TestMetaFallsClosedToModeDeepForUnregisteredCheck verifies the safety backstop:
// any CheckID not in the Registry defaults to ModeDeep, preventing accidental
// surface-scan execution of an unknown check that may touch the target.
func TestMetaFallsClosedToModeDeepForUnregisteredCheck(t *testing.T) {
	unknown := finding.CheckID("unregistered.check_that_does_not_exist")
	meta := finding.Meta(unknown)

	if meta.Mode != finding.ModeDeep {
		t.Errorf("Meta(%q).Mode = %v; want ModeDeep (unregistered checks must fail closed to require permission)",
			unknown, meta.Mode)
	}
}

// TestMetaReturnsCorrectModeForRepresentativeSurfaceChecks verifies a cross-section
// of checks that must NEVER require permission — if any of these flip to ModeDeep,
// the free/unsolicited scan would break.
func TestMetaReturnsCorrectModeForRepresentativeSurfaceChecks(t *testing.T) {
	surfaceChecks := []finding.CheckID{
		// Email (DNS lookups only)
		finding.CheckEmailSPFMissing,
		finding.CheckEmailDMARCMissing,
		finding.CheckEmailDKIMMissing,
		// TLS cert observation via normal handshake
		finding.CheckTLSCertExpiry7d,
		finding.CheckTLSCertSelfSigned,
		// Exposure via well-known HTTP paths
		finding.CheckExposureEnvFile,
		finding.CheckExposureGitExposed,
		// DNS queries (passive)
		finding.CheckDNSDanglingCNAME,
		// Asset intelligence (external public APIs)
		finding.CheckAssetReverseIP,
		finding.CheckAssetPassiveDNS,
	}

	for _, id := range surfaceChecks {
		meta := finding.Meta(id)
		if meta.Mode != finding.ModeSurface {
			t.Errorf("Meta(%q).Mode = ModeDeep; want ModeSurface — this check runs without permission in free scans", id)
		}
	}
}

// TestMetaReturnsCorrectModeForRepresentativeDeepChecks verifies that checks
// requiring active probing are correctly tagged ModeDeep. These must NEVER run
// in unsolicited scans.
func TestMetaReturnsCorrectModeForRepresentativeDeepChecks(t *testing.T) {
	deepChecks := []finding.CheckID{
		// TLS: testssl.sh actively negotiates deprecated protocols / sends exploit probes
		finding.CheckTLSProtocolTLS10,
		finding.CheckTLSHeartbleed,
		finding.CheckTLSPOODLE,
		finding.CheckTLSROBOT,
		// Web: payload injection
		finding.CheckWebXSS,
		finding.CheckWebSQLi,
		finding.CheckWebSSRF,
		finding.CheckWebPathTraversal,
		finding.CheckWebDefaultCredentials,
		finding.CheckWebHTTPRequestSmuggling,
	}

	for _, id := range deepChecks {
		meta := finding.Meta(id)
		if meta.Mode != finding.ModeDeep {
			t.Errorf("Meta(%q).Mode = ModeSurface; want ModeDeep — this check requires explicit permission", id)
		}
	}
}
