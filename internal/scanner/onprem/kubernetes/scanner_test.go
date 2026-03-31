package kubernetes_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
	"github.com/stormbane/beacon/internal/scanner/onprem/kubernetes"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func hasCheckID(findings []finding.Finding, id finding.CheckID) bool {
	for _, f := range findings {
		if f.CheckID == id {
			return true
		}
	}
	return false
}

func countCheckID(findings []finding.Finding, id finding.CheckID) int {
	n := 0
	for _, f := range findings {
		if f.CheckID == id {
			n++
		}
	}
	return n
}

// findingWithCheckID returns the first finding matching the given CheckID, or nil.
func findingWithCheckID(findings []finding.Finding, id finding.CheckID) *finding.Finding {
	for i := range findings {
		if findings[i].CheckID == id {
			return &findings[i]
		}
	}
	return nil
}

// k8sRouter returns an http.Handler that dispatches to registered K8s API
// endpoint handlers. Unregistered paths return 404.
type k8sRouter struct {
	handlers map[string]http.HandlerFunc
}

func newRouter() *k8sRouter {
	return &k8sRouter{handlers: make(map[string]http.HandlerFunc)}
}

func (r *k8sRouter) handle(path string, fn http.HandlerFunc) {
	r.handlers[path] = fn
}

func (r *k8sRouter) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if fn, ok := r.handlers[req.URL.Path]; ok {
		fn(w, req)
		return
	}
	http.NotFound(w, req)
}

// writeJSON is a test helper that serializes v as JSON into the response.
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// defaultNamespaceHandler returns a handler that serves a namespace list with
// the given namespace names.
func defaultNamespaceHandler(names ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var items []map[string]any
		for _, n := range names {
			items = append(items, map[string]any{"metadata": map[string]any{"name": n}})
		}
		writeJSON(w, map[string]any{"items": items})
	}
}

// emptyListHandler returns a handler that serves an empty list.
func emptyListHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"items": []any{}})
	}
}

// runScanner creates a scanner pointing at the test server and runs it.
func runScanner(t *testing.T, ts *httptest.Server) ([]finding.Finding, error) {
	t.Helper()
	cfg := kubernetes.Config{
		APIServer:     ts.URL,
		BearerToken:   "test-token",
		SkipTLSVerify: true,
	}
	s := kubernetes.New(cfg)
	return s.Run(context.Background(), "test-cluster", module.ScanDeep)
}

// ---------------------------------------------------------------------------
// Surface mode — scanner must be a no-op
// ---------------------------------------------------------------------------

func TestSurfaceMode_ReturnsNil(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"major": "1", "minor": "29"})
	}))
	defer ts.Close()

	cfg := kubernetes.Config{
		APIServer:     ts.URL,
		BearerToken:   "test-token",
		SkipTLSVerify: true,
	}
	s := kubernetes.New(cfg)
	findings, err := s.Run(context.Background(), "test-cluster", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings in surface mode, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Anonymous auth
// ---------------------------------------------------------------------------

func TestAnonymousAuth_Detected(t *testing.T) {
	router := newRouter()
	router.handle("/version", func(w http.ResponseWriter, r *http.Request) {
		// Return 200 regardless of auth header → anonymous auth enabled.
		writeJSON(w, map[string]any{"major": "1", "minor": "29", "gitVersion": "v1.29.2"})
	})
	router.handle("/api/v1/namespaces", defaultNamespaceHandler("default"))
	router.handle("/api/v1/namespaces/default/pods", emptyListHandler())
	router.handle("/apis/networking.k8s.io/v1/namespaces/default/networkpolicies", emptyListHandler())
	router.handle("/api/v1/namespaces/default/secrets", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterroles", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", emptyListHandler())

	ts := httptest.NewServer(router)
	defer ts.Close()

	findings, err := runScanner(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremK8sAnonymousAuth) {
		t.Error("expected anonymous auth finding, got none")
	}
	f := findingWithCheckID(findings, finding.CheckOnpremK8sAnonymousAuth)
	if f.Severity != finding.SeverityCritical {
		t.Errorf("expected severity Critical, got %v", f.Severity)
	}
	if f.ProofCommand == "" {
		t.Error("expected ProofCommand to be set")
	}
}

func TestAnonymousAuth_NotDetected_When401(t *testing.T) {
	router := newRouter()
	router.handle("/version", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]any{"major": "1", "minor": "29"})
	})
	router.handle("/api/v1/namespaces", defaultNamespaceHandler("default"))
	router.handle("/api/v1/namespaces/default/pods", emptyListHandler())
	router.handle("/apis/networking.k8s.io/v1/namespaces/default/networkpolicies", emptyListHandler())
	router.handle("/api/v1/namespaces/default/secrets", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterroles", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", emptyListHandler())

	ts := httptest.NewServer(router)
	defer ts.Close()

	findings, err := runScanner(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(findings, finding.CheckOnpremK8sAnonymousAuth) {
		t.Error("did not expect anonymous auth finding when /version returns 401")
	}
}

// ---------------------------------------------------------------------------
// Privileged pod
// ---------------------------------------------------------------------------

func TestPrivilegedPod_Detected(t *testing.T) {
	router := newRouter()
	router.handle("/version", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]any{"major": "1", "minor": "29"})
	})
	router.handle("/api/v1/namespaces", defaultNamespaceHandler("default"))
	router.handle("/api/v1/namespaces/default/pods", func(w http.ResponseWriter, r *http.Request) {
		priv := true
		writeJSON(w, kubernetes.PodList{
			Items: []kubernetes.Pod{{
				Metadata: kubernetes.ObjectMeta{Name: "danger-pod", Namespace: "default"},
				Spec: kubernetes.PodSpec{
					ServiceAccountName: "my-sa",
					Containers: []kubernetes.Container{{
						Name:  "danger",
						Image: "nginx:1.25",
						SecurityContext: &kubernetes.SecurityContext{
							Privileged: &priv,
						},
						Resources: kubernetes.ResourceRequirements{
							Limits: map[string]string{"cpu": "100m", "memory": "128Mi"},
						},
					}},
					SecurityContext: &kubernetes.PodSecurityContext{},
				},
			}},
		})
	})
	router.handle("/apis/networking.k8s.io/v1/namespaces/default/networkpolicies", emptyListHandler())
	router.handle("/api/v1/namespaces/default/secrets", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterroles", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", emptyListHandler())

	ts := httptest.NewServer(router)
	defer ts.Close()

	findings, err := runScanner(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremK8sPrivilegedPod) {
		t.Error("expected privileged pod finding")
	}
	f := findingWithCheckID(findings, finding.CheckOnpremK8sPrivilegedPod)
	if f.Severity != finding.SeverityCritical {
		t.Errorf("expected Critical severity, got %v", f.Severity)
	}
}

func TestPrivilegedPod_NotDetected_WhenFalse(t *testing.T) {
	router := newRouter()
	router.handle("/version", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]any{"major": "1", "minor": "29"})
	})
	router.handle("/api/v1/namespaces", defaultNamespaceHandler("default"))
	router.handle("/api/v1/namespaces/default/pods", func(w http.ResponseWriter, r *http.Request) {
		priv := false
		roFS := true
		writeJSON(w, kubernetes.PodList{
			Items: []kubernetes.Pod{{
				Metadata: kubernetes.ObjectMeta{Name: "safe-pod", Namespace: "default"},
				Spec: kubernetes.PodSpec{
					ServiceAccountName: "my-sa",
					Containers: []kubernetes.Container{{
						Name:  "safe",
						Image: "nginx:1.25",
						SecurityContext: &kubernetes.SecurityContext{
							Privileged:             &priv,
							ReadOnlyRootFilesystem: &roFS,
						},
						Resources: kubernetes.ResourceRequirements{
							Limits: map[string]string{"cpu": "100m"},
						},
					}},
					SecurityContext: &kubernetes.PodSecurityContext{},
				},
			}},
		})
	})
	router.handle("/apis/networking.k8s.io/v1/namespaces/default/networkpolicies", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"items": []any{map[string]any{"metadata": map[string]any{"name": "deny-all"}}}})
	})
	router.handle("/api/v1/namespaces/default/secrets", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterroles", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", emptyListHandler())

	ts := httptest.NewServer(router)
	defer ts.Close()

	findings, err := runScanner(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(findings, finding.CheckOnpremK8sPrivilegedPod) {
		t.Error("did not expect privileged pod finding when privileged=false")
	}
}

// ---------------------------------------------------------------------------
// HostNetwork / HostPID
// ---------------------------------------------------------------------------

func TestHostNetworkAndHostPID_Detected(t *testing.T) {
	router := newRouter()
	router.handle("/version", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]any{"major": "1", "minor": "29"})
	})
	router.handle("/api/v1/namespaces", defaultNamespaceHandler("default"))
	router.handle("/api/v1/namespaces/default/pods", func(w http.ResponseWriter, r *http.Request) {
		roFS := true
		writeJSON(w, kubernetes.PodList{
			Items: []kubernetes.Pod{{
				Metadata: kubernetes.ObjectMeta{Name: "host-pod", Namespace: "default"},
				Spec: kubernetes.PodSpec{
					ServiceAccountName: "my-sa",
					HostNetwork:        true,
					HostPID:            true,
					Containers: []kubernetes.Container{{
						Name:  "app",
						Image: "myapp:v1.0",
						SecurityContext: &kubernetes.SecurityContext{
							ReadOnlyRootFilesystem: &roFS,
						},
						Resources: kubernetes.ResourceRequirements{
							Limits: map[string]string{"cpu": "100m"},
						},
					}},
					SecurityContext: &kubernetes.PodSecurityContext{},
				},
			}},
		})
	})
	router.handle("/apis/networking.k8s.io/v1/namespaces/default/networkpolicies", emptyListHandler())
	router.handle("/api/v1/namespaces/default/secrets", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterroles", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", emptyListHandler())

	ts := httptest.NewServer(router)
	defer ts.Close()

	findings, err := runScanner(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremK8sHostNetwork) {
		t.Error("expected hostNetwork finding")
	}
	if !hasCheckID(findings, finding.CheckOnpremK8sHostPID) {
		t.Error("expected hostPID finding")
	}
}

// ---------------------------------------------------------------------------
// Default service account
// ---------------------------------------------------------------------------

func TestDefaultSA_Detected(t *testing.T) {
	router := newRouter()
	router.handle("/version", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]any{"major": "1", "minor": "29"})
	})
	router.handle("/api/v1/namespaces", defaultNamespaceHandler("default"))
	router.handle("/api/v1/namespaces/default/pods", func(w http.ResponseWriter, r *http.Request) {
		roFS := true
		writeJSON(w, kubernetes.PodList{
			Items: []kubernetes.Pod{{
				Metadata: kubernetes.ObjectMeta{Name: "default-sa-pod", Namespace: "default"},
				Spec: kubernetes.PodSpec{
					ServiceAccountName: "default",
					// AutomountServiceAccountToken not set → defaults to true.
					Containers: []kubernetes.Container{{
						Name:  "app",
						Image: "myapp:v1.0",
						SecurityContext: &kubernetes.SecurityContext{
							ReadOnlyRootFilesystem: &roFS,
						},
						Resources: kubernetes.ResourceRequirements{
							Limits: map[string]string{"cpu": "100m"},
						},
					}},
					SecurityContext: &kubernetes.PodSecurityContext{},
				},
			}},
		})
	})
	router.handle("/apis/networking.k8s.io/v1/namespaces/default/networkpolicies", emptyListHandler())
	router.handle("/api/v1/namespaces/default/secrets", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterroles", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", emptyListHandler())

	ts := httptest.NewServer(router)
	defer ts.Close()

	findings, err := runScanner(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremK8sDefaultSA) {
		t.Error("expected default SA finding")
	}
}

func TestDefaultSA_NotDetected_WhenAutomountDisabled(t *testing.T) {
	router := newRouter()
	router.handle("/version", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]any{"major": "1", "minor": "29"})
	})
	router.handle("/api/v1/namespaces", defaultNamespaceHandler("default"))
	router.handle("/api/v1/namespaces/default/pods", func(w http.ResponseWriter, r *http.Request) {
		automount := false
		roFS := true
		writeJSON(w, kubernetes.PodList{
			Items: []kubernetes.Pod{{
				Metadata: kubernetes.ObjectMeta{Name: "safe-pod", Namespace: "default"},
				Spec: kubernetes.PodSpec{
					ServiceAccountName:           "default",
					AutomountServiceAccountToken: &automount,
					Containers: []kubernetes.Container{{
						Name:  "app",
						Image: "myapp:v1.0",
						SecurityContext: &kubernetes.SecurityContext{
							ReadOnlyRootFilesystem: &roFS,
						},
						Resources: kubernetes.ResourceRequirements{
							Limits: map[string]string{"cpu": "100m"},
						},
					}},
					SecurityContext: &kubernetes.PodSecurityContext{},
				},
			}},
		})
	})
	router.handle("/apis/networking.k8s.io/v1/namespaces/default/networkpolicies", emptyListHandler())
	router.handle("/api/v1/namespaces/default/secrets", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterroles", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", emptyListHandler())

	ts := httptest.NewServer(router)
	defer ts.Close()

	findings, err := runScanner(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(findings, finding.CheckOnpremK8sDefaultSA) {
		t.Error("did not expect default SA finding when automount is disabled")
	}
}

// ---------------------------------------------------------------------------
// No network policy
// ---------------------------------------------------------------------------

func TestNoNetworkPolicy_Detected(t *testing.T) {
	router := newRouter()
	router.handle("/version", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]any{"major": "1", "minor": "29"})
	})
	router.handle("/api/v1/namespaces", defaultNamespaceHandler("my-app"))
	router.handle("/api/v1/namespaces/my-app/pods", emptyListHandler())
	router.handle("/apis/networking.k8s.io/v1/namespaces/my-app/networkpolicies", emptyListHandler())
	router.handle("/api/v1/namespaces/my-app/secrets", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterroles", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", emptyListHandler())

	ts := httptest.NewServer(router)
	defer ts.Close()

	findings, err := runScanner(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremK8sNoNetworkPolicy) {
		t.Error("expected no-network-policy finding")
	}
}

func TestNoNetworkPolicy_NotDetected_WhenPolicyExists(t *testing.T) {
	router := newRouter()
	router.handle("/version", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]any{"major": "1", "minor": "29"})
	})
	router.handle("/api/v1/namespaces", defaultNamespaceHandler("my-app"))
	router.handle("/api/v1/namespaces/my-app/pods", emptyListHandler())
	router.handle("/apis/networking.k8s.io/v1/namespaces/my-app/networkpolicies", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"items": []any{map[string]any{"metadata": map[string]any{"name": "deny-all"}}}})
	})
	router.handle("/api/v1/namespaces/my-app/secrets", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterroles", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", emptyListHandler())

	ts := httptest.NewServer(router)
	defer ts.Close()

	findings, err := runScanner(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(findings, finding.CheckOnpremK8sNoNetworkPolicy) {
		t.Error("did not expect no-network-policy finding when a policy exists")
	}
}

// ---------------------------------------------------------------------------
// RBAC wildcard
// ---------------------------------------------------------------------------

func TestRBACWildcard_Detected(t *testing.T) {
	router := newRouter()
	router.handle("/version", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]any{"major": "1", "minor": "29"})
	})
	router.handle("/api/v1/namespaces", defaultNamespaceHandler("default"))
	router.handle("/api/v1/namespaces/default/pods", emptyListHandler())
	router.handle("/apis/networking.k8s.io/v1/namespaces/default/networkpolicies", emptyListHandler())
	router.handle("/api/v1/namespaces/default/secrets", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterroles", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, kubernetes.ClusterRoleList{
			Items: []kubernetes.ClusterRole{{
				Metadata: kubernetes.ObjectMeta{Name: "god-mode"},
				Rules: []kubernetes.PolicyRule{{
					Verbs:     []string{"*"},
					Resources: []string{"*"},
					APIGroups: []string{"*"},
				}},
			}},
		})
	})
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", emptyListHandler())

	ts := httptest.NewServer(router)
	defer ts.Close()

	findings, err := runScanner(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremK8sRBACWildcard) {
		t.Error("expected RBAC wildcard finding")
	}
	f := findingWithCheckID(findings, finding.CheckOnpremK8sRBACWildcard)
	if f.Severity != finding.SeverityCritical {
		t.Errorf("expected Critical severity, got %v", f.Severity)
	}
}

func TestRBACWildcard_NotDetected_WhenSpecific(t *testing.T) {
	router := newRouter()
	router.handle("/version", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]any{"major": "1", "minor": "29"})
	})
	router.handle("/api/v1/namespaces", defaultNamespaceHandler("default"))
	router.handle("/api/v1/namespaces/default/pods", emptyListHandler())
	router.handle("/apis/networking.k8s.io/v1/namespaces/default/networkpolicies", emptyListHandler())
	router.handle("/api/v1/namespaces/default/secrets", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterroles", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, kubernetes.ClusterRoleList{
			Items: []kubernetes.ClusterRole{{
				Metadata: kubernetes.ObjectMeta{Name: "reader"},
				Rules: []kubernetes.PolicyRule{{
					Verbs:     []string{"get", "list", "watch"},
					Resources: []string{"pods", "services"},
					APIGroups: []string{""},
				}},
			}},
		})
	})
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", emptyListHandler())

	ts := httptest.NewServer(router)
	defer ts.Close()

	findings, err := runScanner(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(findings, finding.CheckOnpremK8sRBACWildcard) {
		t.Error("did not expect RBAC wildcard finding with specific verbs/resources")
	}
}

// ---------------------------------------------------------------------------
// Cluster-admin binding
// ---------------------------------------------------------------------------

func TestClusterAdminBinding_Detected(t *testing.T) {
	router := newRouter()
	router.handle("/version", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]any{"major": "1", "minor": "29"})
	})
	router.handle("/api/v1/namespaces", defaultNamespaceHandler("default"))
	router.handle("/api/v1/namespaces/default/pods", emptyListHandler())
	router.handle("/apis/networking.k8s.io/v1/namespaces/default/networkpolicies", emptyListHandler())
	router.handle("/api/v1/namespaces/default/secrets", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterroles", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, kubernetes.ClusterRoleBindingList{
			Items: []kubernetes.ClusterRoleBinding{{
				Metadata: kubernetes.ObjectMeta{Name: "bad-binding"},
				RoleRef:  kubernetes.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
				Subjects: []kubernetes.Subject{{
					Kind:      "ServiceAccount",
					Name:      "dev-sa",
					Namespace: "dev",
				}},
			}},
		})
	})

	ts := httptest.NewServer(router)
	defer ts.Close()

	findings, err := runScanner(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremK8sClusterAdminBinding) {
		t.Error("expected cluster-admin binding finding for subject outside kube-system")
	}
}

func TestClusterAdminBinding_NotDetected_WhenKubeSystem(t *testing.T) {
	router := newRouter()
	router.handle("/version", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]any{"major": "1", "minor": "29"})
	})
	router.handle("/api/v1/namespaces", defaultNamespaceHandler("default"))
	router.handle("/api/v1/namespaces/default/pods", emptyListHandler())
	router.handle("/apis/networking.k8s.io/v1/namespaces/default/networkpolicies", emptyListHandler())
	router.handle("/api/v1/namespaces/default/secrets", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterroles", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, kubernetes.ClusterRoleBindingList{
			Items: []kubernetes.ClusterRoleBinding{{
				Metadata: kubernetes.ObjectMeta{Name: "system-binding"},
				RoleRef:  kubernetes.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
				Subjects: []kubernetes.Subject{{
					Kind:      "ServiceAccount",
					Name:      "system-sa",
					Namespace: "kube-system",
				}},
			}},
		})
	})

	ts := httptest.NewServer(router)
	defer ts.Close()

	findings, err := runScanner(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(findings, finding.CheckOnpremK8sClusterAdminBinding) {
		t.Error("did not expect cluster-admin binding finding for kube-system subject")
	}
}

// ---------------------------------------------------------------------------
// No security context
// ---------------------------------------------------------------------------

func TestNoSecurityContext_Detected(t *testing.T) {
	router := newRouter()
	router.handle("/version", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]any{"major": "1", "minor": "29"})
	})
	router.handle("/api/v1/namespaces", defaultNamespaceHandler("default"))
	router.handle("/api/v1/namespaces/default/pods", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, kubernetes.PodList{
			Items: []kubernetes.Pod{{
				Metadata: kubernetes.ObjectMeta{Name: "no-sc-pod", Namespace: "default"},
				Spec: kubernetes.PodSpec{
					ServiceAccountName: "my-sa",
					// No SecurityContext at pod or container level.
					Containers: []kubernetes.Container{{
						Name:  "app",
						Image: "myapp:v1.0",
						Resources: kubernetes.ResourceRequirements{
							Limits: map[string]string{"cpu": "100m"},
						},
					}},
				},
			}},
		})
	})
	router.handle("/apis/networking.k8s.io/v1/namespaces/default/networkpolicies", emptyListHandler())
	router.handle("/api/v1/namespaces/default/secrets", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterroles", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", emptyListHandler())

	ts := httptest.NewServer(router)
	defer ts.Close()

	findings, err := runScanner(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremK8sNoSecurityContext) {
		t.Error("expected no-security-context finding")
	}
}

// ---------------------------------------------------------------------------
// Writable root filesystem
// ---------------------------------------------------------------------------

func TestWritableRootFS_Detected(t *testing.T) {
	router := newRouter()
	router.handle("/version", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]any{"major": "1", "minor": "29"})
	})
	router.handle("/api/v1/namespaces", defaultNamespaceHandler("default"))
	router.handle("/api/v1/namespaces/default/pods", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, kubernetes.PodList{
			Items: []kubernetes.Pod{{
				Metadata: kubernetes.ObjectMeta{Name: "writable-pod", Namespace: "default"},
				Spec: kubernetes.PodSpec{
					ServiceAccountName: "my-sa",
					Containers: []kubernetes.Container{{
						Name:            "app",
						Image:           "myapp:v1.0",
						SecurityContext: &kubernetes.SecurityContext{},
						Resources: kubernetes.ResourceRequirements{
							Limits: map[string]string{"cpu": "100m"},
						},
					}},
					SecurityContext: &kubernetes.PodSecurityContext{},
				},
			}},
		})
	})
	router.handle("/apis/networking.k8s.io/v1/namespaces/default/networkpolicies", emptyListHandler())
	router.handle("/api/v1/namespaces/default/secrets", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterroles", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", emptyListHandler())

	ts := httptest.NewServer(router)
	defer ts.Close()

	findings, err := runScanner(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremK8sWritableRootFS) {
		t.Error("expected writable-rootfs finding when readOnlyRootFilesystem is not set")
	}
}

func TestWritableRootFS_NotDetected_WhenReadOnly(t *testing.T) {
	router := newRouter()
	router.handle("/version", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]any{"major": "1", "minor": "29"})
	})
	router.handle("/api/v1/namespaces", defaultNamespaceHandler("default"))
	router.handle("/api/v1/namespaces/default/pods", func(w http.ResponseWriter, r *http.Request) {
		roFS := true
		writeJSON(w, kubernetes.PodList{
			Items: []kubernetes.Pod{{
				Metadata: kubernetes.ObjectMeta{Name: "ro-pod", Namespace: "default"},
				Spec: kubernetes.PodSpec{
					ServiceAccountName: "my-sa",
					Containers: []kubernetes.Container{{
						Name:  "app",
						Image: "myapp:v1.0",
						SecurityContext: &kubernetes.SecurityContext{
							ReadOnlyRootFilesystem: &roFS,
						},
						Resources: kubernetes.ResourceRequirements{
							Limits: map[string]string{"cpu": "100m"},
						},
					}},
					SecurityContext: &kubernetes.PodSecurityContext{},
				},
			}},
		})
	})
	router.handle("/apis/networking.k8s.io/v1/namespaces/default/networkpolicies", emptyListHandler())
	router.handle("/api/v1/namespaces/default/secrets", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterroles", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", emptyListHandler())

	ts := httptest.NewServer(router)
	defer ts.Close()

	findings, err := runScanner(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(findings, finding.CheckOnpremK8sWritableRootFS) {
		t.Error("did not expect writable-rootfs finding when readOnlyRootFilesystem=true")
	}
}

// ---------------------------------------------------------------------------
// No resource limits
// ---------------------------------------------------------------------------

func TestNoResourceLimits_Detected(t *testing.T) {
	router := newRouter()
	router.handle("/version", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]any{"major": "1", "minor": "29"})
	})
	router.handle("/api/v1/namespaces", defaultNamespaceHandler("default"))
	router.handle("/api/v1/namespaces/default/pods", func(w http.ResponseWriter, r *http.Request) {
		roFS := true
		writeJSON(w, kubernetes.PodList{
			Items: []kubernetes.Pod{{
				Metadata: kubernetes.ObjectMeta{Name: "no-limits-pod", Namespace: "default"},
				Spec: kubernetes.PodSpec{
					ServiceAccountName: "my-sa",
					Containers: []kubernetes.Container{{
						Name:  "app",
						Image: "myapp:v1.0",
						SecurityContext: &kubernetes.SecurityContext{
							ReadOnlyRootFilesystem: &roFS,
						},
						// No Resources.Limits set.
					}},
					SecurityContext: &kubernetes.PodSecurityContext{},
				},
			}},
		})
	})
	router.handle("/apis/networking.k8s.io/v1/namespaces/default/networkpolicies", emptyListHandler())
	router.handle("/api/v1/namespaces/default/secrets", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterroles", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", emptyListHandler())

	ts := httptest.NewServer(router)
	defer ts.Close()

	findings, err := runScanner(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremK8sNoResourceLimits) {
		t.Error("expected no-resource-limits finding")
	}
}

// ---------------------------------------------------------------------------
// Latest tag / untagged image
// ---------------------------------------------------------------------------

func TestLatestTag_Detected(t *testing.T) {
	router := newRouter()
	router.handle("/version", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]any{"major": "1", "minor": "29"})
	})
	router.handle("/api/v1/namespaces", defaultNamespaceHandler("default"))
	router.handle("/api/v1/namespaces/default/pods", func(w http.ResponseWriter, r *http.Request) {
		roFS := true
		writeJSON(w, kubernetes.PodList{
			Items: []kubernetes.Pod{{
				Metadata: kubernetes.ObjectMeta{Name: "latest-pod", Namespace: "default"},
				Spec: kubernetes.PodSpec{
					ServiceAccountName: "my-sa",
					Containers: []kubernetes.Container{
						{
							Name:  "tagged-latest",
							Image: "nginx:latest",
							SecurityContext: &kubernetes.SecurityContext{
								ReadOnlyRootFilesystem: &roFS,
							},
							Resources: kubernetes.ResourceRequirements{
								Limits: map[string]string{"cpu": "100m"},
							},
						},
						{
							Name:  "untagged",
							Image: "nginx",
							SecurityContext: &kubernetes.SecurityContext{
								ReadOnlyRootFilesystem: &roFS,
							},
							Resources: kubernetes.ResourceRequirements{
								Limits: map[string]string{"cpu": "100m"},
							},
						},
					},
					SecurityContext: &kubernetes.PodSecurityContext{},
				},
			}},
		})
	})
	router.handle("/apis/networking.k8s.io/v1/namespaces/default/networkpolicies", emptyListHandler())
	router.handle("/api/v1/namespaces/default/secrets", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterroles", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", emptyListHandler())

	ts := httptest.NewServer(router)
	defer ts.Close()

	findings, err := runScanner(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	count := countCheckID(findings, finding.CheckOnpremK8sLatestTag)
	if count != 2 {
		t.Errorf("expected 2 latest-tag findings (one :latest, one untagged), got %d", count)
	}
}

func TestLatestTag_NotDetected_WhenPinned(t *testing.T) {
	router := newRouter()
	router.handle("/version", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]any{"major": "1", "minor": "29"})
	})
	router.handle("/api/v1/namespaces", defaultNamespaceHandler("default"))
	router.handle("/api/v1/namespaces/default/pods", func(w http.ResponseWriter, r *http.Request) {
		roFS := true
		writeJSON(w, kubernetes.PodList{
			Items: []kubernetes.Pod{{
				Metadata: kubernetes.ObjectMeta{Name: "pinned-pod", Namespace: "default"},
				Spec: kubernetes.PodSpec{
					ServiceAccountName: "my-sa",
					Containers: []kubernetes.Container{{
						Name:  "pinned",
						Image: "nginx:1.25.3",
						SecurityContext: &kubernetes.SecurityContext{
							ReadOnlyRootFilesystem: &roFS,
						},
						Resources: kubernetes.ResourceRequirements{
							Limits: map[string]string{"cpu": "100m"},
						},
					}},
					SecurityContext: &kubernetes.PodSecurityContext{},
				},
			}},
		})
	})
	router.handle("/apis/networking.k8s.io/v1/namespaces/default/networkpolicies", emptyListHandler())
	router.handle("/api/v1/namespaces/default/secrets", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterroles", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", emptyListHandler())

	ts := httptest.NewServer(router)
	defer ts.Close()

	findings, err := runScanner(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(findings, finding.CheckOnpremK8sLatestTag) {
		t.Error("did not expect latest-tag finding for pinned image")
	}
}

// ---------------------------------------------------------------------------
// Tiller exposed
// ---------------------------------------------------------------------------

func TestTillerExposed_Detected(t *testing.T) {
	router := newRouter()
	router.handle("/version", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]any{"major": "1", "minor": "29"})
	})
	router.handle("/api/v1/namespaces", defaultNamespaceHandler("kube-system"))
	router.handle("/api/v1/namespaces/kube-system/pods", func(w http.ResponseWriter, r *http.Request) {
		roFS := true
		writeJSON(w, kubernetes.PodList{
			Items: []kubernetes.Pod{{
				Metadata: kubernetes.ObjectMeta{Name: "tiller-deploy-abc123", Namespace: "kube-system"},
				Spec: kubernetes.PodSpec{
					ServiceAccountName: "tiller",
					Containers: []kubernetes.Container{{
						Name:  "tiller",
						Image: "gcr.io/kubernetes-helm/tiller:v2.17.0",
						SecurityContext: &kubernetes.SecurityContext{
							ReadOnlyRootFilesystem: &roFS,
						},
						Resources: kubernetes.ResourceRequirements{
							Limits: map[string]string{"cpu": "100m"},
						},
					}},
					SecurityContext: &kubernetes.PodSecurityContext{},
				},
			}},
		})
	})
	router.handle("/apis/networking.k8s.io/v1/namespaces/kube-system/networkpolicies", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterroles", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", emptyListHandler())

	ts := httptest.NewServer(router)
	defer ts.Close()

	findings, err := runScanner(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremK8sTillerExposed) {
		t.Error("expected tiller-exposed finding")
	}
	f := findingWithCheckID(findings, finding.CheckOnpremK8sTillerExposed)
	if f.Severity != finding.SeverityCritical {
		t.Errorf("expected Critical severity for Tiller, got %v", f.Severity)
	}
}

// ---------------------------------------------------------------------------
// Dashboard exposed
// ---------------------------------------------------------------------------

func TestDashboardExposed_Detected(t *testing.T) {
	router := newRouter()
	router.handle("/version", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]any{"major": "1", "minor": "29"})
	})
	router.handle("/api/v1/namespaces", defaultNamespaceHandler("kubernetes-dashboard"))
	router.handle("/api/v1/namespaces/kubernetes-dashboard/pods", func(w http.ResponseWriter, r *http.Request) {
		roFS := true
		writeJSON(w, kubernetes.PodList{
			Items: []kubernetes.Pod{{
				Metadata: kubernetes.ObjectMeta{Name: "kubernetes-dashboard-abc123", Namespace: "kubernetes-dashboard"},
				Spec: kubernetes.PodSpec{
					ServiceAccountName: "kubernetes-dashboard",
					Containers: []kubernetes.Container{{
						Name:  "dashboard",
						Image: "kubernetesui/dashboard:v2.7.0",
						SecurityContext: &kubernetes.SecurityContext{
							ReadOnlyRootFilesystem: &roFS,
						},
						Resources: kubernetes.ResourceRequirements{
							Limits: map[string]string{"cpu": "100m"},
						},
					}},
					SecurityContext: &kubernetes.PodSecurityContext{},
				},
			}},
		})
	})
	router.handle("/apis/networking.k8s.io/v1/namespaces/kubernetes-dashboard/networkpolicies", emptyListHandler())
	router.handle("/api/v1/namespaces/kubernetes-dashboard/secrets", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterroles", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", emptyListHandler())

	ts := httptest.NewServer(router)
	defer ts.Close()

	findings, err := runScanner(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremK8sDashboardExposed) {
		t.Error("expected dashboard-exposed finding")
	}
}

// ---------------------------------------------------------------------------
// RunAsRoot
// ---------------------------------------------------------------------------

func TestRunAsRoot_Detected(t *testing.T) {
	router := newRouter()
	router.handle("/version", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]any{"major": "1", "minor": "29"})
	})
	router.handle("/api/v1/namespaces", defaultNamespaceHandler("default"))
	router.handle("/api/v1/namespaces/default/pods", func(w http.ResponseWriter, r *http.Request) {
		uid := int64(0)
		roFS := true
		writeJSON(w, kubernetes.PodList{
			Items: []kubernetes.Pod{{
				Metadata: kubernetes.ObjectMeta{Name: "root-pod", Namespace: "default"},
				Spec: kubernetes.PodSpec{
					ServiceAccountName: "my-sa",
					Containers: []kubernetes.Container{{
						Name:  "root-container",
						Image: "myapp:v1.0",
						SecurityContext: &kubernetes.SecurityContext{
							RunAsUser:              &uid,
							ReadOnlyRootFilesystem: &roFS,
						},
						Resources: kubernetes.ResourceRequirements{
							Limits: map[string]string{"cpu": "100m"},
						},
					}},
					SecurityContext: &kubernetes.PodSecurityContext{},
				},
			}},
		})
	})
	router.handle("/apis/networking.k8s.io/v1/namespaces/default/networkpolicies", emptyListHandler())
	router.handle("/api/v1/namespaces/default/secrets", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterroles", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", emptyListHandler())

	ts := httptest.NewServer(router)
	defer ts.Close()

	findings, err := runScanner(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremK8sRunAsRoot) {
		t.Error("expected run-as-root finding")
	}
}

// ---------------------------------------------------------------------------
// Secrets (informational)
// ---------------------------------------------------------------------------

func TestSecretNotEncrypted_Detected(t *testing.T) {
	router := newRouter()
	router.handle("/version", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]any{"major": "1", "minor": "29"})
	})
	router.handle("/api/v1/namespaces", defaultNamespaceHandler("default"))
	router.handle("/api/v1/namespaces/default/pods", emptyListHandler())
	router.handle("/apis/networking.k8s.io/v1/namespaces/default/networkpolicies", emptyListHandler())
	router.handle("/api/v1/namespaces/default/secrets", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, kubernetes.SecretList{
			Items: []kubernetes.Secret{
				{
					Metadata: kubernetes.ObjectMeta{Name: "db-password", Namespace: "default"},
					Type:     "Opaque",
				},
				{
					Metadata: kubernetes.ObjectMeta{Name: "api-key", Namespace: "default"},
					Type:     "Opaque",
				},
				{
					Metadata: kubernetes.ObjectMeta{Name: "default-token-abc", Namespace: "default"},
					Type:     "kubernetes.io/service-account-token",
				},
			},
		})
	})
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterroles", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", emptyListHandler())

	ts := httptest.NewServer(router)
	defer ts.Close()

	findings, err := runScanner(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremK8sSecretNotEncrypted) {
		t.Error("expected secret-not-encrypted finding")
	}
	f := findingWithCheckID(findings, finding.CheckOnpremK8sSecretNotEncrypted)
	// Should count 2 user secrets (excluding the SA token).
	if count, ok := f.Evidence["secret_count"].(int); !ok || count != 2 {
		t.Errorf("expected 2 user secrets in evidence, got %v", f.Evidence["secret_count"])
	}
}

// ---------------------------------------------------------------------------
// System namespace skipping
// ---------------------------------------------------------------------------

func TestSystemNamespace_SkipsWorkloadChecks(t *testing.T) {
	router := newRouter()
	router.handle("/version", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]any{"major": "1", "minor": "29"})
	})
	router.handle("/api/v1/namespaces", defaultNamespaceHandler("kube-system"))
	router.handle("/api/v1/namespaces/kube-system/pods", func(w http.ResponseWriter, r *http.Request) {
		// Pod in kube-system with many issues — workload checks should be skipped.
		writeJSON(w, kubernetes.PodList{
			Items: []kubernetes.Pod{{
				Metadata: kubernetes.ObjectMeta{Name: "kube-proxy-abc", Namespace: "kube-system"},
				Spec: kubernetes.PodSpec{
					ServiceAccountName: "default",
					HostNetwork:        true,
					Containers: []kubernetes.Container{{
						Name:  "kube-proxy",
						Image: "k8s.gcr.io/kube-proxy",
					}},
				},
			}},
		})
	})
	router.handle("/apis/networking.k8s.io/v1/namespaces/kube-system/networkpolicies", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterroles", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", emptyListHandler())

	ts := httptest.NewServer(router)
	defer ts.Close()

	findings, err := runScanner(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Workload-level checks should not fire for kube-system pods.
	if hasCheckID(findings, finding.CheckOnpremK8sHostNetwork) {
		t.Error("did not expect hostNetwork finding for kube-system pod")
	}
	if hasCheckID(findings, finding.CheckOnpremK8sDefaultSA) {
		t.Error("did not expect default-SA finding for kube-system pod")
	}
	if hasCheckID(findings, finding.CheckOnpremK8sLatestTag) {
		t.Error("did not expect latest-tag finding for kube-system pod")
	}
}

// ---------------------------------------------------------------------------
// Scan error
// ---------------------------------------------------------------------------

func TestScanError_WhenNamespacesFail(t *testing.T) {
	router := newRouter()
	router.handle("/version", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]any{"major": "1", "minor": "29"})
	})
	router.handle("/api/v1/namespaces", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("forbidden"))
	})

	ts := httptest.NewServer(router)
	defer ts.Close()

	findings, err := runScanner(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremK8sScanError) {
		t.Error("expected scan error finding when namespace listing fails")
	}
}

// ---------------------------------------------------------------------------
// ProofCommand and Evidence on all findings
// ---------------------------------------------------------------------------

func TestAllFindings_HaveProofCommandAndEvidence(t *testing.T) {
	router := newRouter()
	router.handle("/version", func(w http.ResponseWriter, r *http.Request) {
		// Anonymous auth enabled (intentionally).
		writeJSON(w, map[string]any{"major": "1", "minor": "29"})
	})
	router.handle("/api/v1/namespaces", defaultNamespaceHandler("default"))
	router.handle("/api/v1/namespaces/default/pods", func(w http.ResponseWriter, r *http.Request) {
		priv := true
		uid := int64(0)
		writeJSON(w, kubernetes.PodList{
			Items: []kubernetes.Pod{{
				Metadata: kubernetes.ObjectMeta{Name: "bad-pod", Namespace: "default"},
				Spec: kubernetes.PodSpec{
					HostNetwork: true,
					HostPID:     true,
					Containers: []kubernetes.Container{{
						Name:  "bad",
						Image: "nginx:latest",
						SecurityContext: &kubernetes.SecurityContext{
							Privileged: &priv,
							RunAsUser:  &uid,
						},
					}},
				},
			}},
		})
	})
	router.handle("/apis/networking.k8s.io/v1/namespaces/default/networkpolicies", emptyListHandler())
	router.handle("/api/v1/namespaces/default/secrets", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, kubernetes.SecretList{
			Items: []kubernetes.Secret{{
				Metadata: kubernetes.ObjectMeta{Name: "my-secret", Namespace: "default"},
				Type:     "Opaque",
			}},
		})
	})
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterroles", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, kubernetes.ClusterRoleList{
			Items: []kubernetes.ClusterRole{{
				Metadata: kubernetes.ObjectMeta{Name: "wild"},
				Rules: []kubernetes.PolicyRule{{
					Verbs:     []string{"*"},
					Resources: []string{"*"},
				}},
			}},
		})
	})
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, kubernetes.ClusterRoleBindingList{
			Items: []kubernetes.ClusterRoleBinding{{
				Metadata: kubernetes.ObjectMeta{Name: "bad-bind"},
				RoleRef:  kubernetes.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
				Subjects: []kubernetes.Subject{{
					Kind:      "User",
					Name:      "hacker",
					Namespace: "default",
				}},
			}},
		})
	})

	ts := httptest.NewServer(router)
	defer ts.Close()

	findings, err := runScanner(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings from comprehensive bad-config cluster")
	}
	for _, f := range findings {
		if f.ProofCommand == "" {
			t.Errorf("finding %s has empty ProofCommand", f.CheckID)
		}
		if f.Evidence == nil || len(f.Evidence) == 0 {
			t.Errorf("finding %s has empty Evidence", f.CheckID)
		}
	}
}

// ---------------------------------------------------------------------------
// Image tag edge cases
// ---------------------------------------------------------------------------

func TestLatestTag_DigestImage_NotFlagged(t *testing.T) {
	router := newRouter()
	router.handle("/version", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]any{"major": "1", "minor": "29"})
	})
	router.handle("/api/v1/namespaces", defaultNamespaceHandler("default"))
	router.handle("/api/v1/namespaces/default/pods", func(w http.ResponseWriter, r *http.Request) {
		roFS := true
		writeJSON(w, kubernetes.PodList{
			Items: []kubernetes.Pod{{
				Metadata: kubernetes.ObjectMeta{Name: "digest-pod", Namespace: "default"},
				Spec: kubernetes.PodSpec{
					ServiceAccountName: "my-sa",
					Containers: []kubernetes.Container{{
						Name:  "pinned-digest",
						Image: "nginx@sha256:abc123def456",
						SecurityContext: &kubernetes.SecurityContext{
							ReadOnlyRootFilesystem: &roFS,
						},
						Resources: kubernetes.ResourceRequirements{
							Limits: map[string]string{"cpu": "100m"},
						},
					}},
					SecurityContext: &kubernetes.PodSecurityContext{},
				},
			}},
		})
	})
	router.handle("/apis/networking.k8s.io/v1/namespaces/default/networkpolicies", emptyListHandler())
	router.handle("/api/v1/namespaces/default/secrets", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterroles", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", emptyListHandler())

	ts := httptest.NewServer(router)
	defer ts.Close()

	findings, err := runScanner(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(findings, finding.CheckOnpremK8sLatestTag) {
		t.Error("did not expect latest-tag finding for digest-pinned image")
	}
}

// ---------------------------------------------------------------------------
// Registry image with port (e.g., registry.example.com:5000/nginx)
// ---------------------------------------------------------------------------

func TestLatestTag_RegistryWithPort_NoTag_Flagged(t *testing.T) {
	router := newRouter()
	router.handle("/version", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]any{"major": "1", "minor": "29"})
	})
	router.handle("/api/v1/namespaces", defaultNamespaceHandler("default"))
	router.handle("/api/v1/namespaces/default/pods", func(w http.ResponseWriter, r *http.Request) {
		roFS := true
		writeJSON(w, kubernetes.PodList{
			Items: []kubernetes.Pod{{
				Metadata: kubernetes.ObjectMeta{Name: "registry-pod", Namespace: "default"},
				Spec: kubernetes.PodSpec{
					ServiceAccountName: "my-sa",
					Containers: []kubernetes.Container{{
						Name:  "from-registry",
						Image: "registry.example.com:5000/myapp",
						SecurityContext: &kubernetes.SecurityContext{
							ReadOnlyRootFilesystem: &roFS,
						},
						Resources: kubernetes.ResourceRequirements{
							Limits: map[string]string{"cpu": "100m"},
						},
					}},
					SecurityContext: &kubernetes.PodSecurityContext{},
				},
			}},
		})
	})
	router.handle("/apis/networking.k8s.io/v1/namespaces/default/networkpolicies", emptyListHandler())
	router.handle("/api/v1/namespaces/default/secrets", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterroles", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", emptyListHandler())

	ts := httptest.NewServer(router)
	defer ts.Close()

	findings, err := runScanner(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremK8sLatestTag) {
		t.Error("expected latest-tag finding for untagged registry image")
	}
}

func TestLatestTag_RegistryWithPort_Pinned_NotFlagged(t *testing.T) {
	router := newRouter()
	router.handle("/version", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]any{"major": "1", "minor": "29"})
	})
	router.handle("/api/v1/namespaces", defaultNamespaceHandler("default"))
	router.handle("/api/v1/namespaces/default/pods", func(w http.ResponseWriter, r *http.Request) {
		roFS := true
		writeJSON(w, kubernetes.PodList{
			Items: []kubernetes.Pod{{
				Metadata: kubernetes.ObjectMeta{Name: "registry-pod", Namespace: "default"},
				Spec: kubernetes.PodSpec{
					ServiceAccountName: "my-sa",
					Containers: []kubernetes.Container{{
						Name:  "from-registry",
						Image: "registry.example.com:5000/myapp:v2.0",
						SecurityContext: &kubernetes.SecurityContext{
							ReadOnlyRootFilesystem: &roFS,
						},
						Resources: kubernetes.ResourceRequirements{
							Limits: map[string]string{"cpu": "100m"},
						},
					}},
					SecurityContext: &kubernetes.PodSecurityContext{},
				},
			}},
		})
	})
	router.handle("/apis/networking.k8s.io/v1/namespaces/default/networkpolicies", emptyListHandler())
	router.handle("/api/v1/namespaces/default/secrets", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterroles", emptyListHandler())
	router.handle("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", emptyListHandler())

	ts := httptest.NewServer(router)
	defer ts.Close()

	findings, err := runScanner(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(findings, finding.CheckOnpremK8sLatestTag) {
		t.Error("did not expect latest-tag finding for pinned registry image")
	}
}

// ---------------------------------------------------------------------------
// Scanner name
// ---------------------------------------------------------------------------

func TestScannerName(t *testing.T) {
	s := kubernetes.New(kubernetes.Config{})
	if s.Name() != "onprem/kubernetes" {
		t.Errorf("expected scanner name %q, got %q", "onprem/kubernetes", s.Name())
	}
}
