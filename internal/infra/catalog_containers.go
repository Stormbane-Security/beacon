package infra

// Container runtimes, orchestrators, registries, and service meshes.

const (
	Docker      Technology = "docker"
	Podman      Technology = "podman"
	Containerd  Technology = "containerd"
	CriO        Technology = "cri-o"
	Kubernetes  Technology = "kubernetes"
	K3s         Technology = "k3s"
	K0s         Technology = "k0s"
	MicroK8s    Technology = "microk8s"
	OpenShift   Technology = "openshift"
	Nomad       Technology = "nomad"
	DockerSwarm Technology = "docker-swarm"

	Istio       Technology = "istio"
	Linkerd     Technology = "linkerd"
	Consul      Technology = "consul"
	Cilium      Technology = "cilium"

	DockerHub   Technology = "dockerhub"
	GHCR        Technology = "ghcr"
	Harbor      Technology = "harbor"
	Quay        Technology = "quay"

	Helm        Technology = "helm"
	Kustomize   Technology = "kustomize"
)

func init() {
	// ── Container Runtimes ──
	for _, m := range []*TechMeta{
		{ID: Docker, Name: "Docker", Category: CategoryContainer, OpenSource: true, Vendor: "Docker Inc", Tags: []string{"runtime"}},
		{ID: Podman, Name: "Podman", Category: CategoryContainer, OpenSource: true, Vendor: "Red Hat", Tags: []string{"runtime", "rootless"}},
		{ID: Containerd, Name: "containerd", Category: CategoryContainer, OpenSource: true, Vendor: "CNCF", Tags: []string{"runtime"}},
		{ID: CriO, Name: "CRI-O", Category: CategoryContainer, OpenSource: true, Vendor: "CNCF/Red Hat", Tags: []string{"runtime", "k8s-native"}},
	} {
		Register(m)
	}

	// ── Orchestrators ──
	for _, m := range []*TechMeta{
		{ID: Kubernetes, Name: "Kubernetes", Category: CategoryContainer, OpenSource: true, Vendor: "CNCF", DefaultPorts: []int{6443, 10250}, Tags: []string{"orchestrator"}, Aliases: []string{"k8s"}},
		{ID: K3s, Name: "K3s", Category: CategoryContainer, OpenSource: true, Vendor: "SUSE/Rancher", DefaultPorts: []int{6443}, Tags: []string{"orchestrator", "lightweight"}},
		{ID: K0s, Name: "k0s", Category: CategoryContainer, OpenSource: true, Vendor: "Mirantis", DefaultPorts: []int{6443}, Tags: []string{"orchestrator", "lightweight"}},
		{ID: MicroK8s, Name: "MicroK8s", Category: CategoryContainer, OpenSource: true, Vendor: "Canonical", DefaultPorts: []int{16443}, Tags: []string{"orchestrator", "lightweight"}},
		{ID: OpenShift, Name: "OpenShift", Category: CategoryContainer, Vendor: "Red Hat", DefaultPorts: []int{6443, 8443}, Tags: []string{"orchestrator"}, Aliases: []string{"ocp"}},
		{ID: Nomad, Name: "HashiCorp Nomad", Category: CategoryContainer, OpenSource: true, Vendor: "HashiCorp", DefaultPorts: []int{4646, 4647, 4648}, DockerImage: "hashicorp/nomad:latest", Tags: []string{"orchestrator"}},
		{ID: DockerSwarm, Name: "Docker Swarm", Category: CategoryContainer, OpenSource: true, Vendor: "Docker Inc", DefaultPorts: []int{2377, 7946}, Tags: []string{"orchestrator"}},
	} {
		Register(m)
	}

	// ── Service Meshes ──
	for _, m := range []*TechMeta{
		{ID: Istio, Name: "Istio", Category: CategoryContainer, OpenSource: true, Vendor: "CNCF/Google", Tags: []string{"service-mesh"}},
		{ID: Linkerd, Name: "Linkerd", Category: CategoryContainer, OpenSource: true, Vendor: "CNCF/Buoyant", Tags: []string{"service-mesh"}},
		{ID: Consul, Name: "HashiCorp Consul", Category: CategoryContainer, OpenSource: true, Vendor: "HashiCorp", DefaultPorts: []int{8500, 8501, 8600}, DockerImage: "hashicorp/consul:latest", Tags: []string{"service-mesh", "service-discovery"}},
		{ID: Cilium, Name: "Cilium", Category: CategoryContainer, OpenSource: true, Vendor: "CNCF/Isovalent", Tags: []string{"service-mesh", "ebpf", "cni"}},
	} {
		Register(m)
	}

	// ── Container Registries ──
	for _, m := range []*TechMeta{
		{ID: DockerHub, Name: "Docker Hub", Category: CategoryContainer, Vendor: "Docker Inc", Tags: []string{"registry"}, Aliases: []string{"docker-registry"}},
		{ID: GHCR, Name: "GitHub Container Registry", Category: CategoryContainer, Vendor: "GitHub/Microsoft", Tags: []string{"registry"}},
		{ID: Harbor, Name: "Harbor", Category: CategoryContainer, OpenSource: true, Vendor: "CNCF/VMware", DefaultPorts: []int{80, 443}, Tags: []string{"registry"}},
		{ID: Quay, Name: "Quay", Category: CategoryContainer, OpenSource: true, Vendor: "Red Hat", Tags: []string{"registry"}, Aliases: []string{"quay-io"}},
	} {
		Register(m)
	}

	// ── Package Management ──
	for _, m := range []*TechMeta{
		{ID: Helm, Name: "Helm", Category: CategoryContainer, OpenSource: true, Vendor: "CNCF", Tags: []string{"package-manager", "k8s"}},
		{ID: Kustomize, Name: "Kustomize", Category: CategoryContainer, OpenSource: true, Vendor: "Kubernetes SIG", Tags: []string{"config-management", "k8s"}},
	} {
		Register(m)
	}
}
