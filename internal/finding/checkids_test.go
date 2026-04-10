package finding_test

import (
	"strings"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
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
	finding.CheckWebCmdInjection,
	finding.CheckWebCSRFMissing,
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
	finding.CheckGHActionPATUsedInWorkflow,
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
	// AWS — Route 53
	finding.CheckCloudAWSRoute53NoDNSSEC,
	finding.CheckCloudAWSRoute53NoQueryLogging,
	// AWS — Cognito
	finding.CheckCloudAWSCognitoNoMFA,
	finding.CheckCloudAWSCognitoWeakPassword,
	finding.CheckCloudAWSCognitoNoAdvancedSecurity,
	// AWS — CloudWatch Logs
	finding.CheckCloudAWSCloudWatchLogNoEncryption,
	finding.CheckCloudAWSCloudWatchLogShortRetention,
	// AWS — SSM Parameter Store
	finding.CheckCloudAWSSSMParamNoEncryption,
	// AWS — WAF
	finding.CheckCloudAWSWAFNoWebACL,
	finding.CheckCloudAWSWAFNoLogging,
	// AWS — Kinesis
	finding.CheckCloudAWSKinesisNoEncryption,
	// GitLab — self-hosted instance checks
	finding.CheckGitLabPublicRegistration,
	finding.CheckGitLabPublicSnippets,
	finding.CheckGitLabPublicProjects,
	finding.CheckGitLabCILintExposed,
	finding.CheckGitLabGraphQLIntrospection,
	finding.CheckGitLabOutdatedVersion,
	finding.CheckGitLabHealthExposed,
	finding.CheckGitLabPrometheusExposed,
	finding.CheckGitLabAPIUnauth,
	// TeamCity — self-hosted instance checks
	finding.CheckTeamCityGuestAccess,
	finding.CheckTeamCityAgentDetailsExposed,
	finding.CheckTeamCityBuildConfigsExposed,
	finding.CheckTeamCityUserListExposed,
	finding.CheckTeamCityProjectListExposed,
	finding.CheckTeamCityOutdatedVersion,
	finding.CheckTeamCityDebugEndpoint,
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
		finding.CheckCORSMisconfiguration:       true,
		finding.CheckCORSNullOrigin:             true,
		finding.CheckCORSPreflightMisconfig:     true,
		finding.CheckCORSCredentialedReflection: true,
		finding.CheckDNSRebindHostUnvalidated:  true,
		finding.CheckDNSRebindInternalRoutable: true,
		finding.CheckHostHeaderInjection:    true,
		finding.CheckRateLimitMissing:       true,
		finding.CheckRateLimitBypass:        true,
		finding.CheckOAuthMissingState:       true,
		finding.CheckOAuthWeakState:          true,
		finding.CheckOAuthImplicitAccepted:   true,
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
		finding.CheckJWTAlgNoneVariant:      true,
		finding.CheckJWTEmptySecret:         true,
		finding.CheckJWTKidInjection:        true,
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
		finding.CheckWebCmdInjection:        true,
		finding.CheckWebNoSQLi:              true,
		finding.CheckWebCSRFMissing:         true,
		finding.CheckWebSSTI:                true,
		finding.CheckWebCRLFInjection:       true,
		finding.CheckWebPrototypePollution:  true,
		finding.CheckWebXXE:                 true,
		finding.CheckWebInsecureDeserialize:  true,
		finding.CheckWebDotNetDeserialize:   true,
		finding.CheckWebSSRFRedirectMetadata: true,
		finding.CheckWebHPP:                 true,
		finding.CheckWebFileUpload:          true,
		finding.CheckWebAPIFuzz:             true,
		finding.CheckWebSocketCSWSH:         true,
		// Log4Shell — deep mode sends JNDI payload in headers
		finding.CheckCVELog4Shell: true,
		// CVE-2025-24813 Apache Tomcat partial PUT — writes a 1-byte temp file,
		// requires --permission-confirmed to avoid unsolicited writes to servers.
		finding.CheckCVETomcatPartialPUT: true,
		// CVE-2023-42793 TeamCity /RPC2 bypass — POST creates an admin API token,
		// a state modification that requires --permission-confirmed.
		finding.CheckCVETeamCityRPC2: true,
		// EVM contract vulnerability analysis — active Etherscan + RPC probes
		finding.CheckContractReentrancy:      true,
		finding.CheckContractSelfDestruct:    true,
		finding.CheckContractUncheckedCall:   true,
		finding.CheckContractIntegerOverflow: true,
		// CVE-2014-0224 OpenSSL CCS injection — testssl.sh sends malformed TLS handshake
		finding.CheckTLSCCSInjection: true,
		// WiFi PMKID capture via bettercap/hcxdumptool — requires --permission-confirmed
		finding.CheckWiFiPMKID: true,
		// Cloud posture checks — require authenticated API access to the cloud account
		finding.CheckCloudGCPScanError:            true,
		finding.CheckCloudGCPIAMPrimitiveRole:     true,
		finding.CheckCloudGCPServiceAccountKey:    true,
		finding.CheckCloudGCPServiceAccountKeyOld: true,
		finding.CheckCloudGCPBucketPublic:         true,
		finding.CheckCloudGCPComputeDefaultSA:     true,
		finding.CheckCloudGCPGKEPublicEndpoint:    true,
		finding.CheckCloudGCPGKENoBinaryAuth:      true,
		finding.CheckCloudAWSScanError:         true,
		finding.CheckCloudAWSIAMRootAccessKey:  true,
		finding.CheckCloudAWSIAMRootNoMFA:      true,
		finding.CheckCloudAWSIAMUserNoMFA:      true,
		finding.CheckCloudAWSIAMAccessKeyOld:   true,
		finding.CheckCloudAWSIAMPolicyWildcard: true,
		finding.CheckCloudAWSS3BucketPublic:    true,
		finding.CheckCloudAWSS3NoEncryption:    true,
		finding.CheckCloudAWSEC2PublicSG:       true,
		finding.CheckCloudAWSEKSPublicEndpoint: true,
		finding.CheckCloudAzureScanError:         true,
		finding.CheckCloudAzureBlobPublic:        true,
		finding.CheckCloudAzureStorageHTTP:       true,
		finding.CheckCloudAzureAKSPublicEndpoint: true,
		finding.CheckCloudAzureOwnerDirect:       true,
		// Additional cloud posture checks added by parallel agents
		finding.CheckCloudGCPComputeSerialPort:      true,
		finding.CheckCloudGCPComputeNoOSLogin:       true,
		finding.CheckCloudGCPGKENoWorkloadIdentity:  true,
		finding.CheckCloudGCPGKENoMasterAuthNetworks: true,
		finding.CheckCloudAWSEC2IMDSv1:              true,
		finding.CheckCloudAWSEBSUnencrypted:         true,
		finding.CheckCloudAWSEKSNoLogging:           true,
		finding.CheckCloudAzureStorageSharedKey:      true,
		finding.CheckCloudAzureAKSNoRBAC:            true,
		finding.CheckCloudAzureAKSNoNetPolicy:       true,
		// New cloud posture checks — GCP
		finding.CheckCloudGCPCloudRunUnauthenticated: true,
		finding.CheckCloudGCPCloudRunNoBinaryAuth:    true,
		finding.CheckCloudGCPCloudRunNoVPCConnector:  true,
		finding.CheckCloudGCPCloudSQLPublic:          true,
		finding.CheckCloudGCPCloudSQLNoSSL:           true,
		finding.CheckCloudGCPCloudSQLNoBackup:        true,
		finding.CheckCloudGCPArtifactRegistryPublic:  true,
		finding.CheckCloudGCPNoAuditLogging:          true,
		// New cloud posture checks — AWS
		finding.CheckCloudAWSRDSPublic:               true,
		finding.CheckCloudAWSRDSNoEncryption:          true,
		finding.CheckCloudAWSRDSNoBackup:              true,
		finding.CheckCloudAWSECRNoScanning:            true,
		finding.CheckCloudAWSECRPublic:                true,
		finding.CheckCloudAWSECRMutableTags:           true,
		finding.CheckCloudAWSNoCloudTrail:             true,
		finding.CheckCloudAWSCloudTrailNoEncryption:   true,
		finding.CheckCloudAWSCloudTrailNoValidation:   true,
		// New cloud posture checks — Azure
		finding.CheckCloudAzureSQLPublic:              true,
		finding.CheckCloudAzureSQLNoAuditing:          true,
		finding.CheckCloudAzureSQLNoTDE:               true,
		finding.CheckCloudAzureACRPublic:              true,
		finding.CheckCloudAzureACRNoContentTrust:      true,
		finding.CheckCloudAzureNoActivityLog:          true,
		// GraphQL CSRF via GET
		finding.CheckGraphQLGETEnabled: true,
		// Kubernetes posture checks — GKE
		finding.CheckCloudGKEShieldedNodesDisabled: true,
		finding.CheckCloudGKENoNetworkPolicy:       true,
		finding.CheckCloudGKELegacyMetadataEnabled: true,
		finding.CheckCloudGKENodeDefaultSA:         true,
		finding.CheckCloudGKENoAutoUpgrade:         true,
		// Kubernetes posture checks — EKS
		finding.CheckCloudEKSNoIRSA:             true,
		finding.CheckCloudEKSNoPodIdentity:      true,
		finding.CheckCloudEKSNoNetworkPolicy:    true,
		finding.CheckCloudEKSNoSecretEncryption: true,
		finding.CheckCloudEKSNoPrivateEndpoint:  true,
		// Kubernetes posture checks — AKS
		finding.CheckCloudAzureAKSNoManagedIdentity: true,
		finding.CheckCloudAzureAKSNoAADIntegration:  true,
		finding.CheckCloudAzureAKSNoAutoUpgrade:     true,
		// Additional cloud posture checks
		finding.CheckCloudGCPShieldedVMDisabled:       true,
		finding.CheckCloudGCPBigQueryPublic:            true,
		finding.CheckCloudGCPNoOrgPolicyRestrict:       true,
		finding.CheckCloudGCPNoVPCFlowLogs:             true,
		finding.CheckCloudGCPKMSNoRotation:             true,
		finding.CheckCloudGCPCloudFunctionNoAuth:       true,
		finding.CheckCloudAWSNoGuardDuty:               true,
		finding.CheckCloudAWSKMSNoRotation:             true,
		finding.CheckCloudAWSLambdaNoAuth:              true,
		finding.CheckCloudAWSLambdaOverprivileged:      true,
		finding.CheckCloudAWSNoVPCFlowLogs:             true,
		finding.CheckCloudAWSNoConfig:                  true,
		finding.CheckCloudAWSNoSecurityHub:             true,
		finding.CheckCloudAWSDefaultVPC:                true,
		finding.CheckCloudAWSSNSNoEncryption:           true,
		finding.CheckCloudAWSSQSNoEncryption:           true,
		finding.CheckCloudAWSSecretsNoRotation:         true,
		finding.CheckCloudAWSAPIGatewayNoAuth:          true,
		finding.CheckCloudAzureSQLNoATP:                true,
		finding.CheckCloudAzureKeyVaultNoPurgeProtect:  true,
		finding.CheckCloudAzureKeyVaultNoSoftDelete:    true,
		finding.CheckCloudAzureAppServiceNoManagedID:   true,
		finding.CheckCloudAzureAppServiceNoHTTPS:       true,
		finding.CheckCloudAzureNoNSGFlowLogs:           true,
		finding.CheckCloudAzureNoDefender:              true,
		finding.CheckWebNginxAliasTraversal:            true,
		// New deep-mode checks added in scanner gaps pass
		finding.CheckGraphQLAliasDos:                   true,
		finding.CheckOAuthSubdomainBypass:              true,
		// AWS — S3 extended
		finding.CheckCloudAWSS3NoVersioning:       true,
		finding.CheckCloudAWSS3NoLogging:          true,
		finding.CheckCloudAWSS3NoSSLOnly:          true,
		finding.CheckCloudAWSS3NoLifecycle:        true,
		// AWS — Lambda extended
		finding.CheckCloudAWSLambdaNoVPC:          true,
		finding.CheckCloudAWSLambdaEnvSecrets:     true,
		finding.CheckCloudAWSLambdaRuntimeEOL:     true,
		finding.CheckCloudAWSLambdaNoDLQ:          true,
		finding.CheckCloudAWSLambdaNoTracing:      true,
		// AWS — ELB/ALB
		finding.CheckCloudAWSELBNoHTTPS:              true,
		finding.CheckCloudAWSELBNoAccessLogs:          true,
		finding.CheckCloudAWSELBInsecureTLS:           true,
		finding.CheckCloudAWSELBNoDropInvalidHeaders:  true,
		finding.CheckCloudAWSELBNoDesyncMitigation:    true,
		// AWS — ECS
		finding.CheckCloudAWSECSTaskRoleOverpriv:      true,
		finding.CheckCloudAWSECSHostNetworkMode:       true,
		finding.CheckCloudAWSECSExecEnabled:           true,
		finding.CheckCloudAWSECSNoLogging:             true,
		finding.CheckCloudAWSECSPrivilegedContainer:   true,
		finding.CheckCloudAWSECSSecretsInEnv:          true,
		// AWS — DynamoDB
		finding.CheckCloudAWSDynamoDBNoEncryption:     true,
		finding.CheckCloudAWSDynamoDBNoPITR:           true,
		finding.CheckCloudAWSDynamoDBNoBackup:         true,
		// AWS — ElastiCache
		finding.CheckCloudAWSElastiCacheNoEncTransit:  true,
		finding.CheckCloudAWSElastiCacheNoEncRest:     true,
		finding.CheckCloudAWSElastiCacheNoAuth:        true,
		finding.CheckCloudAWSElastiCacheNoAutoUpgrade: true,
		// AWS — CloudFront
		finding.CheckCloudAWSCloudFrontNoHTTPS:        true,
		finding.CheckCloudAWSCloudFrontNoWAF:          true,
		finding.CheckCloudAWSCloudFrontNoOAC:          true,
		finding.CheckCloudAWSCloudFrontNoLogging:      true,
		finding.CheckCloudAWSCloudFrontInsecureTLS:    true,
		finding.CheckCloudAWSCloudFrontDefaultCert:    true,
		// AWS — OpenSearch
		finding.CheckCloudAWSOpenSearchPublic:         true,
		finding.CheckCloudAWSOpenSearchNoEncRest:      true,
		finding.CheckCloudAWSOpenSearchNoEncTransit:   true,
		finding.CheckCloudAWSOpenSearchNoVPC:          true,
		finding.CheckCloudAWSOpenSearchNoLogs:         true,
		// AWS — Redshift
		finding.CheckCloudAWSRedshiftPublic:           true,
		finding.CheckCloudAWSRedshiftNoEncryption:     true,
		finding.CheckCloudAWSRedshiftNoAuditLog:       true,
		finding.CheckCloudAWSRedshiftNoSSL:            true,
		// AWS — DocumentDB
		finding.CheckCloudAWSDocDBNoEncryption:        true,
		finding.CheckCloudAWSDocDBNoBackup:            true,
		finding.CheckCloudAWSDocDBNoAuditLog:          true,
		// AWS — SES
		finding.CheckCloudAWSSESNoDKIM:                true,
		// AWS — RDS extended
		finding.CheckCloudAWSRDSNoAutoMinorUpgrade:    true,
		finding.CheckCloudAWSRDSNoDeletionProtection:  true,
		finding.CheckCloudAWSRDSNoIAMAuth:             true,
		// AWS — Route 53
		finding.CheckCloudAWSRoute53NoDNSSEC:           true,
		finding.CheckCloudAWSRoute53NoQueryLogging:     true,
		// AWS — Cognito
		finding.CheckCloudAWSCognitoNoMFA:              true,
		finding.CheckCloudAWSCognitoWeakPassword:       true,
		finding.CheckCloudAWSCognitoNoAdvancedSecurity: true,
		// AWS — CloudWatch Logs
		finding.CheckCloudAWSCloudWatchLogNoEncryption:  true,
		finding.CheckCloudAWSCloudWatchLogShortRetention: true,
		// AWS — SSM Parameter Store
		finding.CheckCloudAWSSSMParamNoEncryption:      true,
		// AWS — WAF
		finding.CheckCloudAWSWAFNoWebACL:               true,
		finding.CheckCloudAWSWAFNoLogging:              true,
		// AWS — Kinesis
		finding.CheckCloudAWSKinesisNoEncryption:       true,
		// GCP — Secret Manager
		finding.CheckCloudGCPSecretNoRotation:          true,
		finding.CheckCloudGCPSecretNoVersionDestroy:    true,
		// GCP — Network/Firewall
		finding.CheckCloudGCPFirewallSSHOpen:           true,
		finding.CheckCloudGCPFirewallRDPOpen:           true,
		finding.CheckCloudGCPFirewallAllOpen:           true,
		// GCP — Pub/Sub
		finding.CheckCloudGCPPubSubNoEncryption:        true,
		// GCP — Memorystore
		finding.CheckCloudGCPMemorystoreNoAuth:         true,
		finding.CheckCloudGCPMemorystoreNoTransitEncryption: true,
		// GCP — Cloud DNS
		finding.CheckCloudGCPDNSNoDNSSEC:              true,
		// Azure — VM
		finding.CheckCloudAzureVMNoDiskEncryption:      true,
		finding.CheckCloudAzureVMPublicIP:              true,
		// Azure — Cosmos DB
		finding.CheckCloudAzureCosmosDBPublic:          true,
		finding.CheckCloudAzureCosmosDBNoFirewall:      true,
		// Azure — Function App
		finding.CheckCloudAzureFunctionAppNoHTTPS:      true,
		finding.CheckCloudAzureFunctionAppNoManagedID:  true,
		// Azure — Redis
		finding.CheckCloudAzureRedisNoTLS:              true,
		finding.CheckCloudAzureRedisNoFirewall:         true,
		// Azure — PostgreSQL
		finding.CheckCloudAzurePostgresPublic:          true,
		finding.CheckCloudAzurePostgresNoSSL:           true,
		// GitLab — self-hosted instance checks
		finding.CheckGitLabPublicRegistration:   true,
		finding.CheckGitLabPublicSnippets:       true,
		finding.CheckGitLabPublicProjects:       true,
		finding.CheckGitLabCILintExposed:        true,
		finding.CheckGitLabGraphQLIntrospection: true,
		finding.CheckGitLabOutdatedVersion:      true,
		finding.CheckGitLabHealthExposed:        true,
		finding.CheckGitLabPrometheusExposed:    true,
		finding.CheckGitLabAPIUnauth:            true,
		// TeamCity — self-hosted instance checks
		finding.CheckTeamCityGuestAccess:         true,
		finding.CheckTeamCityAgentDetailsExposed: true,
		finding.CheckTeamCityBuildConfigsExposed: true,
		finding.CheckTeamCityUserListExposed:     true,
		finding.CheckTeamCityProjectListExposed:  true,
		finding.CheckTeamCityOutdatedVersion:     true,
		finding.CheckTeamCityDebugEndpoint:       true,
		// AI/LLM deep probes
		finding.CheckAIPromptInjection:     true,
		finding.CheckAISystemLeak:          true,
		finding.CheckAISSRFViaPLLM:         true,
		finding.CheckAIDataExfil:           true,
		finding.CheckAIToolAbuse:           true,
		finding.CheckAIIndirectInjection:   true,
		// Auth probing — active probing
		finding.CheckAuthUsernameEnumeration:   true,
		finding.CheckAuthNoLockout:             true,
		finding.CheckAuthNoBruteforceProtect:   true,
		// Auth fuzzing — active probing
		finding.CheckAuthFuzzStateBypass:       true,
		finding.CheckAuthFuzzCodeInterception:  true,
		finding.CheckAuthFuzzRedirectAbuse:     true,
		finding.CheckAuthFuzzTokenSubstitution: true,
		finding.CheckSIWENonceReuse:            true,
		finding.CheckSIWEChainBypass:           true,
		finding.CheckSIWEReplayAttack:          true,
		// Port-level active probes
		finding.CheckPortMinIODefaultCreds:     true,
		finding.CheckPortGrafanaDefaultCreds:   true,
		finding.CheckPortSonarQubeDefaultCreds: true,
		finding.CheckPortAirflowDefaultCreds:   true,
		finding.CheckPortTomcatDefaultCreds:    true,
		finding.CheckPortPortainerDefaultCreds: true,
		finding.CheckPortPgAdminDefaultCreds:   true,
		finding.CheckPortZabbixDefaultCreds:    true,
		finding.CheckPortSupersetDefaultCreds:  true,
		// MFA enforcement — cloud API
		finding.CheckCloudGCPNo2SV:                    true,
		finding.CheckCloudAzureNoConditionalAccessMFA: true,
		finding.CheckCloudAWSIAMMFANotEnforced:        true,
		// Encryption at rest — cloud API
		finding.CheckCloudGCPBucketNoCMEK:            true,
		finding.CheckCloudAzureBlobNoCMK:              true,
		finding.CheckCloudAzureStorageNoInfraEncrypt:  true,
		// Database public reachability — TCP connect
		finding.CheckCloudAWSRDSPublicReachable:  true,
		finding.CheckCloudGCPCloudSQLReachable:   true,
		finding.CheckCloudAzureCosmosDBReachable: true,
		// LDAP injection
		finding.CheckLDAPBlindInjection: true,
		finding.CheckLDAPAuthBypass:     true,
		// Container registry
		finding.CheckContainerRegistryExposed:       true,
		finding.CheckContainerImageUnsigned:         true,
		finding.CheckContainerImageLatestTag:        true,
		finding.CheckContainerRegistryAnonymousPush: true,
		// GraphQL DoS
		finding.CheckGraphQLFragmentDos: true,
		finding.CheckGraphQLDeepNesting: true,
		// API version bypass
		finding.CheckAPIVersionAuthBypass:      true,
		finding.CheckAPIVersionRateLimitBypass: true,
		// ReDoS
		finding.CheckWebReDoS: true,
		// Expression language injection
		finding.CheckWebELInjection:   true,
		finding.CheckWebSpELInjection: true,
		finding.CheckWebOGNLInjection: true,
		// API authorization — active probe
		finding.CheckBOLAHorizontalAccess:             true,
		finding.CheckAccessControlVerticalEscalation:  true,
		finding.CheckIDORSequentialID:                 true,
		finding.CheckAccessControlMethodBypass:        true,
		finding.CheckAccessControlPathTraversalBypass: true,
		// DigitalOcean cloud
		finding.CheckCloudDOScanError:          true,
		finding.CheckCloudDOSpacesPublic:       true,
		finding.CheckCloudDOSpacesNoEncryption: true,
		finding.CheckCloudDODropletPublicIP:    true,
		finding.CheckCloudDONoFirewall:         true,
		finding.CheckCloudDOFirewallAllOpen:    true,
		finding.CheckCloudDOFirewallSSHOpen:    true,
		// OCI cloud
		finding.CheckCloudOCIScanError:           true,
		finding.CheckCloudOCIBucketPublic:        true,
		finding.CheckCloudOCIBucketNoEncryption:  true,
		finding.CheckCloudOCIVaultKeyNoRotation:  true,
		finding.CheckCloudOCISecurityListAllOpen: true,
		finding.CheckCloudOCISecurityListSSHOpen: true,
		finding.CheckCloudOCINSGAllOpen:          true,
		finding.CheckSupplyChainRegistryToCluster: true,
		// WAF bypass (authorized mode uses ModeDeep)
		finding.CheckWAFBypassPath:        true,
		finding.CheckWAFBypassMethod:      true,
		finding.CheckWAFBypassContentType: true,
		// Proxy chain
		finding.CheckProxyTraceEnabled:   true,
		finding.CheckProxyHopByHopAbuse: true,
		// Load balancer
		// H2C smuggling
		finding.CheckWebH2CSmuggling: true,
		// MCP
		finding.CheckMCPToolPoisoning:    true,
		finding.CheckMCPCommandInjection: true,
		// RPC
		finding.CheckRPCMethodDangerous: true,
		// Cache probe
		finding.CheckCachePoisonUnkeyed: true,
		finding.CheckCacheDeception:     true,
		finding.CheckCacheHostRouting:   true,
		// New scanner gaps — deep mode
		finding.CheckWebVerbTamperAuthBypass: true,
		finding.CheckWebRaceCondition:        true,
		finding.CheckWebRaceNoIdempotency:    true,
		finding.CheckWebXSDInjection:         true,
		finding.CheckWebPDFSSRF:              true,
		// Tier 2 scanner gaps — deep mode
		finding.CheckOOBCallbackReceived:    true,
		finding.CheckDirbustRecursive:      true,
		finding.CheckDirbustTechExtension:  true,
		finding.CheckWebSocketMsgInjection: true,
		finding.CheckWebSocketNoAuth:        true,
		finding.CheckHTTP2ContinuationFlood: true,
		finding.CheckAPINoRateLimit:         true,
		finding.CheckAPIBOLA:                true,
		finding.CheckAPIMassAssignment:      true,
		// Nmap deep-mode NSE scripts
		finding.CheckNmapSMTPOpenRelay:   true,
		finding.CheckNmapMySQLNoPassword: true,
		finding.CheckNmapIPMICipherZero:  true,
		// CVE-2019-9193 PostgreSQL COPY RCE — requires authenticated superuser access
		finding.CheckCVEPostgreSQLCopyRCE2019: true,
		// New scanners added this session
		finding.CheckWebReflectedXSS:            true,
		finding.CheckWebBlindSQLiTime:            true,
		finding.CheckWebHPPWAFBypass:             true,
		finding.CheckWAFBypassFound:              true,
		finding.CheckWAFBypassDoubleEncode:       true,
		finding.CheckWebSocketInjection:          true,
		finding.CheckWebSocketAuthBypass:          true,
		finding.CheckWebPHPDeserialization:        true,
		finding.CheckWebJavaDeserialization:       true,
		finding.CheckPrivescBrokenAccessControl:   true,
		finding.CheckPrivescHorizontalPrivesc:     true,
		finding.CheckPrivescMethodBypass:           true,
		finding.CheckStateSkipDetected:             true,
		finding.CheckIncompleteAuthFlow:            true,
		finding.CheckStepBypass:                    true,
		finding.CheckSecondOrderXSS:                true,
		finding.CheckSecondOrderSQLi:               true,
		finding.CheckSecondOrderReflection:          true,
		finding.CheckGraphQLNoDepthLimit:            true,
		finding.CheckGraphQLBatchNoLimit:            true,
		finding.CheckParamDiscovered:                true,
		// Chain engine findings
		finding.CheckChainSSRFToCloudCreds:          true,
		finding.CheckChainDefaultCredsToAdmin:        true,
		finding.CheckChainEnvToDatabaseAccess:        true,
		finding.CheckChainSQLiToCredentialDump:       true,
		finding.CheckChainXSSToSessionTheftPoC:       true,
		finding.CheckChainNucleiToExploit:            true,
		// Default credential probes
		finding.CheckPortPhpMyAdminDefaultCreds:     true,
		finding.CheckPortMongoExpressDefaultCreds:    true,
		finding.CheckPortKibanaDefaultCreds:          true,
		finding.CheckPortWordPressDefaultCreds:       true,
		// Smart contract deep checks
		finding.CheckContractUnprotectedWithdraw:     true,
		finding.CheckContractFlashloanCallback:       true,
		finding.CheckContractApprovalUnlimited:       true,
		// CVE-specific exploit chain checks — require active payload delivery
		finding.CheckCVEElasticsearchMVELRCE:     true,
		finding.CheckCVEJenkinsSandboxBypass:      true,
		finding.CheckCVETomcatPutRCE:              true,
		finding.CheckCVESpringCloudFunctionRCE:    true,
		finding.CheckCVERedisLuaSandboxEscape:     true,
		finding.CheckCVERedisHINCRAuthBypass:      true,
		finding.CheckCVEMongoDBBSONRCE:            true,
		finding.CheckCVEMySQLConfigManip:          true,
		finding.CheckCVEPostgreSQLExtInjection:    true,
		finding.CheckCVECouchDBErlangCookie:       true,
		finding.CheckCVECouchDBPrivEsc:            true,
		finding.CheckCVEKibanaTimelionRCE:         true,
		finding.CheckCVEKibanaSecurityInfoLeak:    true,
		finding.CheckCVEVaultPKISSRF:              true,
		finding.CheckCVEPrometheusOpenRedirect:    true,
		finding.CheckCVEGitLabAccountTakeover:     true,
		finding.CheckCVEGitLabCILintSSRF:          true,
		finding.CheckCVEAirflowExampleDAGRCE:      true,
		finding.CheckCVEAirflowConfigInfoLeak:     true,
		finding.CheckCVESonarQubeSSRF:             true,
		finding.CheckCVENginxRangeInfoLeak:        true,
		finding.CheckCVEApacheTraversal2021:       true,
		finding.CheckCVEApacheTraversalBypass2021: true,
		// etcd CVEs
		finding.CheckCVEEtcdAuthBypass:            true,
		finding.CheckCVEEtcdLeaseInfoLeak:         true,
		// RabbitMQ CVEs
		finding.CheckCVERabbitMQCredLeak:           true,
		// Jupyter CVEs
		finding.CheckCVEJupyterSSRF:               true,
		finding.CheckCVEJupyterOpenRedirect:        true,
		// Portainer CVEs
		finding.CheckCVEPortainerUnauthAPI:         true,
		// ArgoCD CVEs
		finding.CheckCVEArgoCDJWTBypass:            true,
		// NATS CVEs
		finding.CheckCVENATSAuthBypass:             true,
	}

	for id, meta := range finding.Registry {
		if meta.Mode == finding.ModeDeep && !knownDeep[id] {
			// All onprem.* checks are intentionally deep — they require
			// local network access (Proxmox API, Docker socket, etc.).
			if strings.HasPrefix(string(id), "onprem.") {
				continue
			}
			// All exploit.* and container.* checks are intentionally deep —
			// they require --authorized mode (post-exploitation).
			if strings.HasPrefix(string(id), "exploit.") || strings.HasPrefix(string(id), "container.") {
				continue
			}
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

// ---------------------------------------------------------------------------
// Edge case: ParseSeverity with unusual inputs
// ---------------------------------------------------------------------------

func TestParseUnknownSeverity(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected finding.Severity
	}{
		{"empty string", "", finding.SeverityInfo},
		{"uppercase CRITICAL", "CRITICAL", finding.SeverityCritical},
		{"mixed case High", "High", finding.SeverityHigh},
		{"unknown word", "unknown", finding.SeverityInfo},
		{"hyphenated", "high-priority", finding.SeverityInfo},
		{"trailing space", "medium ", finding.SeverityInfo},    // not trimmed — should fall through
		{"leading space", " low", finding.SeverityInfo},        // not trimmed — should fall through
		{"numeric", "5", finding.SeverityInfo},
		{"info explicit", "info", finding.SeverityInfo},
		{"medium normal", "medium", finding.SeverityMedium},
		{"low normal", "low", finding.SeverityLow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := finding.ParseSeverity(tt.input)
			if got != tt.expected {
				t.Errorf("ParseSeverity(%q) = %v; want %v", tt.input, got, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Edge case: Meta/ComplianceTags with unregistered CheckID
// ---------------------------------------------------------------------------

func TestRegistryUnknownCheckID(t *testing.T) {
	unknown := finding.CheckID("nonexistent.check")

	// Meta should return a safe default without panicking.
	meta := finding.Meta(unknown)
	if meta.CheckID != unknown {
		t.Errorf("Meta(%q).CheckID = %q; want echo-back of input", unknown, meta.CheckID)
	}
	if meta.DefaultSeverity != finding.SeverityInfo {
		t.Errorf("Meta(%q).DefaultSeverity = %v; want SeverityInfo", unknown, meta.DefaultSeverity)
	}
	if meta.Mode != finding.ModeDeep {
		t.Errorf("Meta(%q).Mode = %v; want ModeDeep (fail closed)", unknown, meta.Mode)
	}

	// ComplianceTags should return nil without panicking.
	tags := finding.ComplianceTags(unknown)
	if tags != nil {
		t.Errorf("ComplianceTags(%q) = %v; want nil for unregistered check", unknown, tags)
	}
}

// ---------------------------------------------------------------------------
// Edge case: MapNucleiTemplate with unknown template ID
// ---------------------------------------------------------------------------

func TestMapNucleiTemplateUnknown(t *testing.T) {
	tests := []struct {
		name       string
		templateID string
		expected   finding.CheckID
	}{
		{"totally unknown", "some-custom-template", "nuclei.some-custom-template"},
		{"empty string", "", "nuclei."},
		{"with spaces", "My Custom Template", "nuclei.my-custom-template"},
		{"mixed case", "FooBar-Check", "nuclei.foobar-check"},
		{"already lowercase", "already-lower", "nuclei.already-lower"},
		{"special characters preserved", "check/v2.1", "nuclei.check/v2.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := finding.MapNucleiTemplate(tt.templateID)
			if got != tt.expected {
				t.Errorf("MapNucleiTemplate(%q) = %q; want %q", tt.templateID, got, tt.expected)
			}
		})
	}

	// Known templates should return the mapped CheckID, not the fallback.
	known := finding.MapNucleiTemplate("ssl-dns-names")
	if known != finding.CheckTLSCertHostnameMismatch {
		t.Errorf("MapNucleiTemplate(\"ssl-dns-names\") = %q; want %q", known, finding.CheckTLSCertHostnameMismatch)
	}
}
