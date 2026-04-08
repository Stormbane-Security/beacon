package finding

// Evidence field name constants. All modules MUST use these instead of
// string literals to prevent field name mismatches between producers
// and consumers (scanners, tests, Forecast).
const (
	// Credential fields
	EvidenceCredentialSource = "credential_source"
	EvidenceCredentialType   = "credential_type"
	EvidenceCredentialsFound = "credentials_found"
	EvidenceGrantsAccessTo   = "grants_access_to"
	EvidenceUsername          = "username"
	EvidencePassword          = "password"

	// Pivot/lateral movement fields
	EvidencePivotTarget = "pivot_target"
	EvidencePivotHost   = "pivot_host"
	EvidencePivotPort   = "pivot_port"

	// Escalation fields
	EvidenceEscalationPath = "escalation_path"
	EvidenceSUIDBinaries   = "suid_binaries"
	EvidenceDockerSocket   = "docker_socket"

	// Network discovery fields
	EvidenceHostsFound   = "hosts_found"
	EvidenceSubnetsFound = "subnets_found"
	EvidenceDNSServers   = "dns_servers"
	EvidenceSSHTargets   = "ssh_targets"

	// Service/endpoint fields
	EvidenceService  = "service"
	EvidencePort     = "port"
	EvidenceProtocol = "protocol"
	EvidenceURL      = "url"
	EvidencePath     = "path"
	EvidenceMethod   = "method"
	EvidenceProbe    = "probe"

	// Data extraction fields
	EvidenceDataType    = "data_type"
	EvidenceSnippet     = "snippet"
	EvidenceFileCount   = "file_count"
	EvidenceRecordCount = "record_count"

	// Web/injection fields
	EvidenceInjectionPath   = "injection_path"
	EvidenceInjectionVector = "injection_vector"
	EvidenceParameter       = "parameter"
	EvidencePayload         = "payload"
	EvidenceSignal          = "signal"

	// Cloud fields
	EvidenceCloudProvider = "cloud_provider"
	EvidenceIAMRole       = "iam_role"
	EvidenceAccessKeyID   = "access_key_id"
	EvidenceRegion        = "region"

	// Version/fingerprint fields
	EvidenceVersion = "version"
	EvidenceProduct = "product"
	EvidenceOSName  = "os_name"
	EvidenceBanner  = "banner"
)
