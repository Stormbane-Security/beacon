// Package kubernetes implements a deep-mode scanner for on-premises Kubernetes
// clusters. It queries the K8s API server directly over HTTP to detect common
// security misconfigurations: anonymous auth, privileged pods, RBAC wildcards,
// missing network policies, exposed dashboards, and more.
package kubernetes

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
)

// ---------------------------------------------------------------------------
// Kubernetes API response types (lightweight — no client-go dependency)
// ---------------------------------------------------------------------------

// ObjectMeta contains standard Kubernetes object metadata.
type ObjectMeta struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// NamespaceList is the response from GET /api/v1/namespaces.
type NamespaceList struct {
	Items []Namespace `json:"items"`
}

// Namespace is a single Kubernetes namespace.
type Namespace struct {
	Metadata ObjectMeta `json:"metadata"`
}

// PodList is the response from GET /api/v1/namespaces/{ns}/pods.
type PodList struct {
	Items []Pod `json:"items"`
}

// Pod is a single Kubernetes pod.
type Pod struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     PodSpec    `json:"spec"`
}

// PodSpec describes a pod's specification.
type PodSpec struct {
	ServiceAccountName           string              `json:"serviceAccountName"`
	HostNetwork                  bool                `json:"hostNetwork"`
	HostPID                      bool                `json:"hostPID"`
	Containers                   []Container         `json:"containers"`
	SecurityContext              *PodSecurityContext `json:"securityContext"`
	AutomountServiceAccountToken *bool               `json:"automountServiceAccountToken"`
}

// PodSecurityContext holds pod-level security attributes.
type PodSecurityContext struct {
	RunAsUser    *int64 `json:"runAsUser"`
	RunAsNonRoot *bool  `json:"runAsNonRoot"`
}

// Container describes a single container in a pod.
type Container struct {
	Name            string               `json:"name"`
	Image           string               `json:"image"`
	SecurityContext *SecurityContext      `json:"securityContext"`
	Resources       ResourceRequirements `json:"resources"`
}

// SecurityContext holds container-level security attributes.
type SecurityContext struct {
	Privileged             *bool  `json:"privileged"`
	RunAsUser              *int64 `json:"runAsUser"`
	RunAsNonRoot           *bool  `json:"runAsNonRoot"`
	ReadOnlyRootFilesystem *bool  `json:"readOnlyRootFilesystem"`
}

// ResourceRequirements describes container resource constraints.
type ResourceRequirements struct {
	Limits   map[string]string `json:"limits"`
	Requests map[string]string `json:"requests"`
}

// NetworkPolicyList is the response from the networking.k8s.io/v1 API.
type NetworkPolicyList struct {
	Items []NetworkPolicy `json:"items"`
}

// NetworkPolicy is a single Kubernetes network policy.
type NetworkPolicy struct {
	Metadata ObjectMeta `json:"metadata"`
}

// ClusterRoleBindingList is the response from rbac.authorization.k8s.io/v1.
type ClusterRoleBindingList struct {
	Items []ClusterRoleBinding `json:"items"`
}

// ClusterRoleBinding binds a ClusterRole to subjects.
type ClusterRoleBinding struct {
	Metadata ObjectMeta `json:"metadata"`
	RoleRef  RoleRef    `json:"roleRef"`
	Subjects []Subject  `json:"subjects"`
}

// RoleRef identifies the role being bound.
type RoleRef struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// Subject identifies a user, group, or service account.
type Subject struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// ClusterRoleList is the response from rbac.authorization.k8s.io/v1.
type ClusterRoleList struct {
	Items []ClusterRole `json:"items"`
}

// ClusterRole defines a set of permissions.
type ClusterRole struct {
	Metadata ObjectMeta  `json:"metadata"`
	Rules    []PolicyRule `json:"rules"`
}

// PolicyRule describes a set of permissions on API resources.
type PolicyRule struct {
	Verbs     []string `json:"verbs"`
	Resources []string `json:"resources"`
	APIGroups []string `json:"apiGroups"`
}

// SecretList is the response from GET /api/v1/namespaces/{ns}/secrets.
type SecretList struct {
	Items []Secret `json:"items"`
}

// Secret is a single Kubernetes secret (we only inspect metadata, never values).
type Secret struct {
	Metadata ObjectMeta `json:"metadata"`
	Type     string     `json:"type"`
}

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

const scannerName = "onprem/kubernetes"

// Config holds the connection parameters for the Kubernetes API server.
type Config struct {
	APIServer      string // K8s API server URL (e.g. "https://192.168.1.100:6443")
	BearerToken    string // service account token
	KubeconfigPath string // path to kubeconfig file (alternative to APIServer+Token)
	SkipTLSVerify  bool
}

// Scanner checks a Kubernetes cluster for common security misconfigurations.
type Scanner struct {
	cfg Config
}

// New returns a Kubernetes scanner configured with the given parameters.
func New(cfg Config) *Scanner {
	return &Scanner{cfg: cfg}
}

// Name returns the scanner identifier.
func (s *Scanner) Name() string { return scannerName }

// Run executes the Kubernetes security scan. It requires deep or authorized
// scan mode because it actively queries the cluster API. The scan-type gate
// is enforced by the on-prem module dispatcher; this method assumes deep or
// authorized mode.
func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	apiServer := s.cfg.APIServer
	if apiServer == "" {
		return nil, fmt.Errorf("kubernetes scanner: APIServer URL is required")
	}
	apiServer = strings.TrimRight(apiServer, "/")

	client := s.httpClient()

	var findings []finding.Finding

	// --- Anonymous auth check (request WITHOUT bearer token) ---
	anonFindings := s.checkAnonymousAuth(ctx, client, apiServer, asset)
	findings = append(findings, anonFindings...)

	// --- Fetch namespaces ---
	namespaces, err := s.listNamespaces(ctx, client, apiServer)
	if err != nil {
		findings = append(findings, finding.Finding{
			CheckID:      finding.CheckOnpremK8sScanError,
			Module:       "deep",
			Scanner:      scannerName,
			Severity:     finding.SeverityInfo,
			Title:        "Kubernetes API scan failed",
			Description:  fmt.Sprintf("Failed to list namespaces: %v", err),
			Asset:        asset,
			Evidence:     map[string]any{"error": err.Error(), "api_server": apiServer},
			ProofCommand: fmt.Sprintf("kubectl --server=%s get namespaces", apiServer),
			DiscoveredAt: time.Now(),
		})
		return findings, nil
	}

	// --- Per-namespace checks ---
	systemNS := map[string]bool{
		"kube-system":     true,
		"kube-public":     true,
		"kube-node-lease": true,
	}

	for _, ns := range namespaces {
		nsName := ns.Metadata.Name

		// Network policy check (all namespaces).
		npFindings := s.checkNetworkPolicies(ctx, client, apiServer, asset, nsName)
		findings = append(findings, npFindings...)

		// Pod checks — skip system namespaces for workload checks, but
		// still check kube-system for Tiller and Dashboard.
		podFindings := s.checkPods(ctx, client, apiServer, asset, nsName, systemNS[nsName])
		findings = append(findings, podFindings...)

		// Secret existence check (non-system namespaces only).
		if !systemNS[nsName] {
			secretFindings := s.checkSecrets(ctx, client, apiServer, asset, nsName)
			findings = append(findings, secretFindings...)
		}
	}

	// --- Cluster-wide RBAC checks ---
	rbacFindings := s.checkRBAC(ctx, client, apiServer, asset)
	findings = append(findings, rbacFindings...)

	return findings, nil
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

func (s *Scanner) httpClient() *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: s.cfg.SkipTLSVerify, //nolint:gosec // user-controlled config
		},
	}
	return &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
	}
}

func (s *Scanner) doRequest(ctx context.Context, client *http.Client, url string, authenticated bool) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if authenticated && s.cfg.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.cfg.BearerToken)
	}
	return client.Do(req)
}

func (s *Scanner) getJSON(ctx context.Context, client *http.Client, url string, target any) error {
	resp, err := s.doRequest(ctx, client, url, true)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	return json.NewDecoder(resp.Body).Decode(target)
}

// ---------------------------------------------------------------------------
// Check: anonymous authentication
// ---------------------------------------------------------------------------

func (s *Scanner) checkAnonymousAuth(ctx context.Context, client *http.Client, apiServer, asset string) []finding.Finding {
	resp, err := s.doRequest(ctx, client, apiServer+"/version", false)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return []finding.Finding{{
			CheckID:     finding.CheckOnpremK8sAnonymousAuth,
			Module:      "deep",
			Scanner:     scannerName,
			Severity:    finding.SeverityCritical,
			Title:       fmt.Sprintf("K8s API server accepts anonymous requests: %s", asset),
			Description: "The Kubernetes API server returned HTTP 200 to an unauthenticated request to /version. Anonymous authentication is enabled, allowing anyone with network access to query cluster information and potentially escalate privileges.",
			Asset:       asset,
			Evidence: map[string]any{
				"api_server":  apiServer,
				"endpoint":    "/version",
				"status_code": resp.StatusCode,
				"response":    string(body),
			},
			ProofCommand: fmt.Sprintf("curl -sk %s/version", apiServer),
			DiscoveredAt: time.Now(),
		}}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Check: namespace network policies
// ---------------------------------------------------------------------------

func (s *Scanner) listNamespaces(ctx context.Context, client *http.Client, apiServer string) ([]Namespace, error) {
	var nsList NamespaceList
	if err := s.getJSON(ctx, client, apiServer+"/api/v1/namespaces", &nsList); err != nil {
		return nil, err
	}
	return nsList.Items, nil
}

func (s *Scanner) checkNetworkPolicies(ctx context.Context, client *http.Client, apiServer, asset, ns string) []finding.Finding {
	var npList NetworkPolicyList
	url := fmt.Sprintf("%s/apis/networking.k8s.io/v1/namespaces/%s/networkpolicies", apiServer, ns)
	if err := s.getJSON(ctx, client, url, &npList); err != nil {
		return nil
	}
	if len(npList.Items) == 0 {
		return []finding.Finding{{
			CheckID:     finding.CheckOnpremK8sNoNetworkPolicy,
			Module:      "deep",
			Scanner:     scannerName,
			Severity:    finding.SeverityMedium,
			Title:       fmt.Sprintf("Namespace %q has no network policies", ns),
			Description: fmt.Sprintf("Namespace %q has zero NetworkPolicy resources. All pod-to-pod traffic is allowed by default, enabling lateral movement if any pod is compromised.", ns),
			Asset:       asset,
			Evidence: map[string]any{
				"namespace":      ns,
				"policy_count":   0,
				"api_server":     apiServer,
			},
			ProofCommand: fmt.Sprintf("kubectl get networkpolicies -n %s", ns),
			DiscoveredAt: time.Now(),
		}}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Check: pod security
// ---------------------------------------------------------------------------

func (s *Scanner) checkPods(ctx context.Context, client *http.Client, apiServer, asset, ns string, isSystemNS bool) []finding.Finding {
	var podList PodList
	url := fmt.Sprintf("%s/api/v1/namespaces/%s/pods", apiServer, ns)
	if err := s.getJSON(ctx, client, url, &podList); err != nil {
		return nil
	}

	var findings []finding.Finding
	for _, pod := range podList.Items {
		podName := pod.Metadata.Name

		// Tiller check (kube-system only).
		if strings.HasPrefix(podName, "tiller-deploy") {
			findings = append(findings, finding.Finding{
				CheckID:     finding.CheckOnpremK8sTillerExposed,
				Module:      "deep",
				Scanner:     scannerName,
				Severity:    finding.SeverityCritical,
				Title:       fmt.Sprintf("Helm Tiller (v2) deployed in %s/%s", ns, podName),
				Description: "Helm Tiller v2 is running in the cluster. Tiller has full cluster-admin privileges and its unauthenticated gRPC API allows any pod with network access to deploy arbitrary workloads.",
				Asset:       asset,
				Evidence: map[string]any{
					"namespace": ns,
					"pod":       podName,
				},
				ProofCommand: fmt.Sprintf("kubectl get pods -n %s -l app=helm,name=tiller -o wide", ns),
				DiscoveredAt: time.Now(),
			})
		}

		// Dashboard check (any namespace).
		if strings.Contains(podName, "kubernetes-dashboard") {
			findings = append(findings, finding.Finding{
				CheckID:     finding.CheckOnpremK8sDashboardExposed,
				Module:      "deep",
				Scanner:     scannerName,
				Severity:    finding.SeverityCritical,
				Title:       fmt.Sprintf("Kubernetes Dashboard found: %s/%s", ns, podName),
				Description: "The Kubernetes Dashboard is deployed. If the dashboard is exposed without authentication or with skip-login enabled, it provides full cluster access to anyone who can reach it.",
				Asset:       asset,
				Evidence: map[string]any{
					"namespace": ns,
					"pod":       podName,
				},
				ProofCommand: fmt.Sprintf("kubectl get pods -n %s -l k8s-app=kubernetes-dashboard -o wide", ns),
				DiscoveredAt: time.Now(),
			})
		}

		// Skip remaining workload checks for system namespaces.
		if isSystemNS {
			continue
		}

		// Default service account with auto-mounted token.
		autoMount := pod.Spec.AutomountServiceAccountToken
		if (pod.Spec.ServiceAccountName == "" || pod.Spec.ServiceAccountName == "default") &&
			(autoMount == nil || *autoMount) {
			findings = append(findings, finding.Finding{
				CheckID:     finding.CheckOnpremK8sDefaultSA,
				Module:      "deep",
				Scanner:     scannerName,
				Severity:    finding.SeverityMedium,
				Title:       fmt.Sprintf("Pod %s/%s uses default SA with auto-mounted token", ns, podName),
				Description: fmt.Sprintf("Pod %s/%s uses the default service account with an auto-mounted API token. If compromised, the attacker can query the Kubernetes API with the default SA's permissions.", ns, podName),
				Asset:       asset,
				Evidence: map[string]any{
					"namespace":       ns,
					"pod":             podName,
					"service_account": pod.Spec.ServiceAccountName,
					"automount":       autoMount == nil || *autoMount,
				},
				ProofCommand: fmt.Sprintf("kubectl get pod %s -n %s -o json | jq '{sa: .spec.serviceAccountName, automount: .spec.automountServiceAccountToken}'", podName, ns),
				DiscoveredAt: time.Now(),
			})
		}

		// hostNetwork.
		if pod.Spec.HostNetwork {
			findings = append(findings, finding.Finding{
				CheckID:     finding.CheckOnpremK8sHostNetwork,
				Module:      "deep",
				Scanner:     scannerName,
				Severity:    finding.SeverityHigh,
				Title:       fmt.Sprintf("Pod %s/%s uses host network", ns, podName),
				Description: fmt.Sprintf("Pod %s/%s has hostNetwork: true, sharing the node's network namespace. This allows the pod to sniff traffic, access node-local services, and bypass network policies.", ns, podName),
				Asset:       asset,
				Evidence: map[string]any{
					"namespace":    ns,
					"pod":          podName,
					"host_network": true,
				},
				ProofCommand: fmt.Sprintf("kubectl get pod %s -n %s -o json | jq '.spec.hostNetwork'", podName, ns),
				DiscoveredAt: time.Now(),
			})
		}

		// hostPID.
		if pod.Spec.HostPID {
			findings = append(findings, finding.Finding{
				CheckID:     finding.CheckOnpremK8sHostPID,
				Module:      "deep",
				Scanner:     scannerName,
				Severity:    finding.SeverityHigh,
				Title:       fmt.Sprintf("Pod %s/%s shares host PID namespace", ns, podName),
				Description: fmt.Sprintf("Pod %s/%s has hostPID: true, sharing the node's PID namespace. This allows processes in the pod to see and potentially interact with all processes on the node.", ns, podName),
				Asset:       asset,
				Evidence: map[string]any{
					"namespace": ns,
					"pod":       podName,
					"host_pid":  true,
				},
				ProofCommand: fmt.Sprintf("kubectl get pod %s -n %s -o json | jq '.spec.hostPID'", podName, ns),
				DiscoveredAt: time.Now(),
			})
		}

		// Pod-level security context missing.
		if pod.Spec.SecurityContext == nil {
			hasSomeContainerSC := false
			for _, c := range pod.Spec.Containers {
				if c.SecurityContext != nil {
					hasSomeContainerSC = true
					break
				}
			}
			if !hasSomeContainerSC {
				findings = append(findings, finding.Finding{
					CheckID:     finding.CheckOnpremK8sNoSecurityContext,
					Module:      "deep",
					Scanner:     scannerName,
					Severity:    finding.SeverityMedium,
					Title:       fmt.Sprintf("Pod %s/%s has no securityContext", ns, podName),
					Description: fmt.Sprintf("Pod %s/%s has no securityContext at the pod level and none of its containers define one either. Without a security context, the container runtime uses defaults which may allow running as root, writable filesystem, and full capabilities.", ns, podName),
					Asset:       asset,
					Evidence: map[string]any{
						"namespace": ns,
						"pod":       podName,
					},
					ProofCommand: fmt.Sprintf("kubectl get pod %s -n %s -o json | jq '{podSC: .spec.securityContext, containerSC: [.spec.containers[].securityContext]}'", podName, ns),
					DiscoveredAt: time.Now(),
				})
			}
		}

		// Container-level checks.
		for _, c := range pod.Spec.Containers {
			// Privileged container.
			if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
				findings = append(findings, finding.Finding{
					CheckID:     finding.CheckOnpremK8sPrivilegedPod,
					Module:      "deep",
					Scanner:     scannerName,
					Severity:    finding.SeverityCritical,
					Title:       fmt.Sprintf("Privileged container %s in pod %s/%s", c.Name, ns, podName),
					Description: fmt.Sprintf("Container %s in pod %s/%s runs with privileged: true. Privileged containers have full access to the host's devices, can load kernel modules, and can trivially escape to the host.", c.Name, ns, podName),
					Asset:       asset,
					Evidence: map[string]any{
						"namespace":  ns,
						"pod":        podName,
						"container":  c.Name,
						"privileged": true,
					},
					ProofCommand: fmt.Sprintf("kubectl get pod %s -n %s -o json | jq '.spec.containers[] | select(.name==\"%s\") | .securityContext.privileged'", podName, ns, c.Name),
					DiscoveredAt: time.Now(),
				})
			}

			// RunAsRoot (explicit UID 0).
			if c.SecurityContext != nil && c.SecurityContext.RunAsUser != nil && *c.SecurityContext.RunAsUser == 0 {
				findings = append(findings, finding.Finding{
					CheckID:     finding.CheckOnpremK8sRunAsRoot,
					Module:      "deep",
					Scanner:     scannerName,
					Severity:    finding.SeverityMedium,
					Title:       fmt.Sprintf("Container %s in pod %s/%s runs as root (UID 0)", c.Name, ns, podName),
					Description: fmt.Sprintf("Container %s in pod %s/%s explicitly sets runAsUser: 0. Running as root increases the blast radius of container escapes and makes privilege escalation easier.", c.Name, ns, podName),
					Asset:       asset,
					Evidence: map[string]any{
						"namespace":   ns,
						"pod":         podName,
						"container":   c.Name,
						"run_as_user": 0,
					},
					ProofCommand: fmt.Sprintf("kubectl get pod %s -n %s -o json | jq '.spec.containers[] | select(.name==\"%s\") | .securityContext.runAsUser'", podName, ns, c.Name),
					DiscoveredAt: time.Now(),
				})
			}

			// Writable root filesystem.
			roFS := false
			if c.SecurityContext != nil && c.SecurityContext.ReadOnlyRootFilesystem != nil {
				roFS = *c.SecurityContext.ReadOnlyRootFilesystem
			}
			if !roFS {
				findings = append(findings, finding.Finding{
					CheckID:     finding.CheckOnpremK8sWritableRootFS,
					Module:      "deep",
					Scanner:     scannerName,
					Severity:    finding.SeverityLow,
					Title:       fmt.Sprintf("Container %s in pod %s/%s has writable root filesystem", c.Name, ns, podName),
					Description: fmt.Sprintf("Container %s in pod %s/%s does not set readOnlyRootFilesystem: true. A writable root filesystem allows attackers to modify binaries, install tools, or plant persistence mechanisms.", c.Name, ns, podName),
					Asset:       asset,
					Evidence: map[string]any{
						"namespace":                ns,
						"pod":                      podName,
						"container":                c.Name,
						"read_only_root_filesystem": false,
					},
					ProofCommand: fmt.Sprintf("kubectl get pod %s -n %s -o json | jq '.spec.containers[] | select(.name==\"%s\") | .securityContext.readOnlyRootFilesystem'", podName, ns, c.Name),
					DiscoveredAt: time.Now(),
				})
			}

			// No resource limits.
			if len(c.Resources.Limits) == 0 {
				findings = append(findings, finding.Finding{
					CheckID:     finding.CheckOnpremK8sNoResourceLimits,
					Module:      "deep",
					Scanner:     scannerName,
					Severity:    finding.SeverityLow,
					Title:       fmt.Sprintf("Container %s in pod %s/%s has no resource limits", c.Name, ns, podName),
					Description: fmt.Sprintf("Container %s in pod %s/%s has no CPU or memory limits set. Without resource limits, a compromised or misbehaving container can consume all node resources, causing denial of service for other workloads.", c.Name, ns, podName),
					Asset:       asset,
					Evidence: map[string]any{
						"namespace": ns,
						"pod":       podName,
						"container": c.Name,
					},
					ProofCommand: fmt.Sprintf("kubectl get pod %s -n %s -o json | jq '.spec.containers[] | select(.name==\"%s\") | .resources'", podName, ns, c.Name),
					DiscoveredAt: time.Now(),
				})
			}

			// Image uses :latest tag or no tag.
			if isLatestOrUntagged(c.Image) {
				findings = append(findings, finding.Finding{
					CheckID:     finding.CheckOnpremK8sLatestTag,
					Module:      "deep",
					Scanner:     scannerName,
					Severity:    finding.SeverityMedium,
					Title:       fmt.Sprintf("Container %s in pod %s/%s uses :latest or untagged image", c.Name, ns, podName),
					Description: fmt.Sprintf("Container %s in pod %s/%s uses image %q which has no explicit tag or uses :latest. This makes deployments non-reproducible and can silently introduce vulnerabilities when the upstream image changes.", c.Name, ns, podName, c.Image),
					Asset:       asset,
					Evidence: map[string]any{
						"namespace": ns,
						"pod":       podName,
						"container": c.Name,
						"image":     c.Image,
					},
					ProofCommand: fmt.Sprintf("kubectl get pod %s -n %s -o json | jq '.spec.containers[] | select(.name==\"%s\") | .image'", podName, ns, c.Name),
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	return findings
}

// isLatestOrUntagged returns true if the image reference has no tag or uses
// the :latest tag. Images with a digest (@sha256:...) are considered pinned.
func isLatestOrUntagged(image string) bool {
	// Images with a digest are always considered pinned.
	if strings.Contains(image, "@") {
		return false
	}
	// Find the last colon. If there's no colon after the last "/" (registry
	// separator), the image has no tag.
	lastSlash := strings.LastIndex(image, "/")
	tagPart := image
	if lastSlash >= 0 {
		tagPart = image[lastSlash:]
	}
	colonIdx := strings.LastIndex(tagPart, ":")
	if colonIdx < 0 {
		return true // no tag
	}
	tag := tagPart[colonIdx+1:]
	return tag == "latest"
}

// ---------------------------------------------------------------------------
// Check: secrets existence (informational)
// ---------------------------------------------------------------------------

func (s *Scanner) checkSecrets(ctx context.Context, client *http.Client, apiServer, asset, ns string) []finding.Finding {
	var secretList SecretList
	url := fmt.Sprintf("%s/api/v1/namespaces/%s/secrets", apiServer, ns)
	if err := s.getJSON(ctx, client, url, &secretList); err != nil {
		return nil
	}

	// Count non-default-token secrets.
	var userSecrets []string
	for _, sec := range secretList.Items {
		if sec.Type == "kubernetes.io/service-account-token" {
			continue
		}
		userSecrets = append(userSecrets, sec.Metadata.Name)
	}
	if len(userSecrets) == 0 {
		return nil
	}

	return []finding.Finding{{
		CheckID:     finding.CheckOnpremK8sSecretNotEncrypted,
		Module:      "deep",
		Scanner:     scannerName,
		Severity:    finding.SeverityHigh,
		Title:       fmt.Sprintf("Namespace %q has %d user-created secrets (encryption status unknown)", ns, len(userSecrets)),
		Description: fmt.Sprintf("Namespace %q contains %d user-created Secret resources. Kubernetes Secrets are stored base64-encoded by default and are not encrypted at rest unless EncryptionConfiguration is explicitly configured. Verify that etcd encryption is enabled.", ns, len(userSecrets)),
		Asset:       asset,
		Evidence: map[string]any{
			"namespace":    ns,
			"secret_count": len(userSecrets),
			"secret_names": userSecrets,
		},
		ProofCommand: fmt.Sprintf("kubectl get secrets -n %s --field-selector type!=kubernetes.io/service-account-token", ns),
		DiscoveredAt: time.Now(),
	}}
}

// ---------------------------------------------------------------------------
// Check: RBAC
// ---------------------------------------------------------------------------

func (s *Scanner) checkRBAC(ctx context.Context, client *http.Client, apiServer, asset string) []finding.Finding {
	var findings []finding.Finding

	// Check ClusterRoles for wildcard rules.
	var crList ClusterRoleList
	if err := s.getJSON(ctx, client, apiServer+"/apis/rbac.authorization.k8s.io/v1/clusterroles", &crList); err == nil {
		for _, cr := range crList.Items {
			for _, rule := range cr.Rules {
				if containsWildcard(rule.Verbs) || containsWildcard(rule.Resources) {
					findings = append(findings, finding.Finding{
						CheckID:     finding.CheckOnpremK8sRBACWildcard,
						Module:      "deep",
						Scanner:     scannerName,
						Severity:    finding.SeverityCritical,
						Title:       fmt.Sprintf("ClusterRole %q has wildcard RBAC rule", cr.Metadata.Name),
						Description: fmt.Sprintf("ClusterRole %q contains a rule with wildcard (*) verbs or resources. This grants overly broad permissions that can be leveraged for privilege escalation.", cr.Metadata.Name),
						Asset:       asset,
						Evidence: map[string]any{
							"cluster_role": cr.Metadata.Name,
							"verbs":        rule.Verbs,
							"resources":    rule.Resources,
							"api_groups":   rule.APIGroups,
						},
						ProofCommand: fmt.Sprintf("kubectl get clusterrole %s -o json | jq '.rules'", cr.Metadata.Name),
						DiscoveredAt: time.Now(),
					})
					break // one finding per ClusterRole is sufficient
				}
			}
		}
	}

	// Check ClusterRoleBindings for cluster-admin bound outside kube-system.
	var crbList ClusterRoleBindingList
	if err := s.getJSON(ctx, client, apiServer+"/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", &crbList); err == nil {
		for _, crb := range crbList.Items {
			if crb.RoleRef.Name != "cluster-admin" {
				continue
			}
			for _, subj := range crb.Subjects {
				if subj.Namespace == "kube-system" {
					continue
				}
				findings = append(findings, finding.Finding{
					CheckID:     finding.CheckOnpremK8sClusterAdminBinding,
					Module:      "deep",
					Scanner:     scannerName,
					Severity:    finding.SeverityCritical,
					Title:       fmt.Sprintf("cluster-admin bound to %s %q (namespace: %s)", subj.Kind, subj.Name, subj.Namespace),
					Description: fmt.Sprintf("ClusterRoleBinding %q binds the cluster-admin role to %s %q in namespace %q. The cluster-admin role grants unrestricted access to the entire cluster. Binding it outside kube-system increases the attack surface.", crb.Metadata.Name, subj.Kind, subj.Name, subj.Namespace),
					Asset:       asset,
					Evidence: map[string]any{
						"binding":           crb.Metadata.Name,
						"subject_kind":      subj.Kind,
						"subject_name":      subj.Name,
						"subject_namespace": subj.Namespace,
					},
					ProofCommand: fmt.Sprintf("kubectl get clusterrolebinding %s -o json | jq '.subjects'", crb.Metadata.Name),
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	return findings
}

func containsWildcard(items []string) bool {
	for _, item := range items {
		if item == "*" {
			return true
		}
	}
	return false
}
