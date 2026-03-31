package infra

// CI/CD platforms, build systems, and GitOps tools.

const (
	GitHubActions Technology = "github-actions"
	GitLabCI      Technology = "gitlab-ci"
	Jenkins       Technology = "jenkins"
	TeamCity      Technology = "teamcity"
	CircleCI      Technology = "circleci"
	TravisCI      Technology = "travis-ci"
	ArgoCD        Technology = "argocd"
	FluxCD        Technology = "fluxcd"
	Tekton        Technology = "tekton"
	DroneCI       Technology = "drone"
	Buildkite     Technology = "buildkite"
	AzureDevOps   Technology = "azure-devops"
	AWSCodePipeline Technology = "aws-codepipeline"
	GCPCloudBuild Technology = "gcp-cloud-build"
	Woodpecker    Technology = "woodpecker"
	Concourse     Technology = "concourse"
	Spinnaker     Technology = "spinnaker"
	Harness       Technology = "harness"
)

func init() {
	// ── CI/CD Platforms ──
	for _, m := range []*TechMeta{
		{ID: GitHubActions, Name: "GitHub Actions", Category: CategoryCICD, Vendor: "GitHub/Microsoft", Tags: []string{"ci", "cd"}},
		{ID: GitLabCI, Name: "GitLab CI/CD", Category: CategoryCICD, OpenSource: true, Vendor: "GitLab", Tags: []string{"ci", "cd"}, Aliases: []string{"gitlab-ci-cd"}},
		{ID: Jenkins, Name: "Jenkins", Category: CategoryCICD, OpenSource: true, Vendor: "Jenkins Project", DefaultPorts: []int{8080}, DockerImage: "jenkins/jenkins:lts", Tags: []string{"ci", "cd"}},
		{ID: TeamCity, Name: "TeamCity", Category: CategoryCICD, Vendor: "JetBrains", DefaultPorts: []int{8111}, Tags: []string{"ci", "cd"}},
		{ID: CircleCI, Name: "CircleCI", Category: CategoryCICD, Vendor: "CircleCI", Tags: []string{"ci", "cd"}},
		{ID: TravisCI, Name: "Travis CI", Category: CategoryCICD, OpenSource: true, Vendor: "Travis CI", Tags: []string{"ci", "cd"}, Aliases: []string{"travis"}},
		{ID: DroneCI, Name: "Drone CI", Category: CategoryCICD, OpenSource: true, Vendor: "Harness", DefaultPorts: []int{80, 443}, DockerImage: "drone/drone:latest", Tags: []string{"ci", "cd"}, Aliases: []string{"drone-ci"}},
		{ID: Buildkite, Name: "Buildkite", Category: CategoryCICD, Vendor: "Buildkite", Tags: []string{"ci", "cd"}},
		{ID: AzureDevOps, Name: "Azure DevOps", Category: CategoryCICD, CloudProvider: Azure, Vendor: "Microsoft", Tags: []string{"ci", "cd"}, Aliases: []string{"azure-pipelines", "vsts"}},
		{ID: AWSCodePipeline, Name: "AWS CodePipeline", Category: CategoryCICD, CloudProvider: AWS, Vendor: "Amazon", Tags: []string{"ci", "cd"}, Aliases: []string{"codepipeline"}},
		{ID: GCPCloudBuild, Name: "Cloud Build", Category: CategoryCICD, CloudProvider: GCP, Vendor: "Google", Tags: []string{"ci", "cd"}, Aliases: []string{"cloud-build"}},
		{ID: Woodpecker, Name: "Woodpecker CI", Category: CategoryCICD, OpenSource: true, Vendor: "Woodpecker", DockerImage: "woodpeckerci/woodpecker-server:latest", Tags: []string{"ci", "cd"}},
		{ID: Concourse, Name: "Concourse CI", Category: CategoryCICD, OpenSource: true, Vendor: "VMware", DockerImage: "concourse/concourse:latest", Tags: []string{"ci", "cd"}},
	} {
		Register(m)
	}

	// ── GitOps & Deployment ──
	for _, m := range []*TechMeta{
		{ID: ArgoCD, Name: "Argo CD", Category: CategoryCICD, OpenSource: true, Vendor: "CNCF/Intuit", DefaultPorts: []int{8080, 8443}, Tags: []string{"gitops", "cd"}, Aliases: []string{"argo-cd"}},
		{ID: FluxCD, Name: "Flux CD", Category: CategoryCICD, OpenSource: true, Vendor: "CNCF/Weaveworks", Tags: []string{"gitops", "cd"}, Aliases: []string{"flux"}},
		{ID: Tekton, Name: "Tekton Pipelines", Category: CategoryCICD, OpenSource: true, Vendor: "CNCF/Google", Tags: []string{"ci", "cd", "k8s-native"}},
		{ID: Spinnaker, Name: "Spinnaker", Category: CategoryCICD, OpenSource: true, Vendor: "Netflix/Google", Tags: []string{"cd"}},
		{ID: Harness, Name: "Harness", Category: CategoryCICD, Vendor: "Harness", Tags: []string{"ci", "cd"}},
	} {
		Register(m)
	}
}
