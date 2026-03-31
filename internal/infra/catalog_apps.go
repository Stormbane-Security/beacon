package infra

// Application frameworks, runtimes, CMS, and backend services.

const (
	// Frameworks
	NextJS    Technology = "next-js"
	Nuxt      Technology = "nuxt"
	SvelteKit Technology = "sveltekit"
	Astro     Technology = "astro"
	Rails     Technology = "rails"
	Django    Technology = "django"
	Spring    Technology = "spring"
	Laravel   Technology = "laravel"
	Express   Technology = "express"
	Flask     Technology = "flask"
	FastAPI   Technology = "fastapi"
	Gin       Technology = "gin"
	Fiber     Technology = "fiber"
	Phoenix   Technology = "phoenix"
	DotNet    Technology = "dotnet"

	// Runtimes
	NodeJS Technology = "nodejs"
	PHP    Technology = "php"
	Python Technology = "python"
	Java   Technology = "java"
	Go     Technology = "golang"
	Ruby   Technology = "ruby"
	Rust   Technology = "rust"
	Elixir Technology = "elixir"
	DotNetRuntime Technology = "dotnet-runtime"
)

func init() {
	// ── Frontend/Fullstack Frameworks ──
	for _, m := range []*TechMeta{
		{ID: NextJS, Name: "Next.js", Category: CategoryFramework, OpenSource: true, Vendor: "Vercel", Aliases: []string{"nextjs"}},
		{ID: Nuxt, Name: "Nuxt", Category: CategoryFramework, OpenSource: true, Vendor: "Nuxt Labs", Aliases: []string{"nuxtjs"}},
		{ID: SvelteKit, Name: "SvelteKit", Category: CategoryFramework, OpenSource: true, Vendor: "Svelte", Aliases: []string{"svelte"}},
		{ID: Astro, Name: "Astro", Category: CategoryFramework, OpenSource: true, Vendor: "Astro"},
	} {
		Register(m)
	}

	// ── Backend Frameworks ──
	for _, m := range []*TechMeta{
		{ID: Rails, Name: "Ruby on Rails", Category: CategoryFramework, OpenSource: true, Vendor: "Rails Core", Aliases: []string{"ruby-on-rails", "ror"}},
		{ID: Django, Name: "Django", Category: CategoryFramework, OpenSource: true, Vendor: "Django Software Foundation"},
		{ID: Spring, Name: "Spring Boot", Category: CategoryFramework, OpenSource: true, Vendor: "VMware/Pivotal", Aliases: []string{"spring-boot"}},
		{ID: Laravel, Name: "Laravel", Category: CategoryFramework, OpenSource: true, Vendor: "Laravel"},
		{ID: Express, Name: "Express.js", Category: CategoryFramework, OpenSource: true, Vendor: "OpenJS Foundation", Aliases: []string{"expressjs"}},
		{ID: Flask, Name: "Flask", Category: CategoryFramework, OpenSource: true, Vendor: "Pallets Projects"},
		{ID: FastAPI, Name: "FastAPI", Category: CategoryFramework, OpenSource: true, Vendor: "Tiangolo"},
		{ID: Gin, Name: "Gin", Category: CategoryFramework, OpenSource: true, Vendor: "Gin-Gonic"},
		{ID: Fiber, Name: "Fiber", Category: CategoryFramework, OpenSource: true, Vendor: "Fiber"},
		{ID: Phoenix, Name: "Phoenix Framework", Category: CategoryFramework, OpenSource: true, Vendor: "Phoenix"},
		{ID: DotNet, Name: "ASP.NET", Category: CategoryFramework, Vendor: "Microsoft", Aliases: []string{"aspnet", "asp-net"}},
	} {
		Register(m)
	}

	// ── Language Runtimes ──
	for _, m := range []*TechMeta{
		{ID: NodeJS, Name: "Node.js", Category: CategoryRuntime, OpenSource: true, Vendor: "OpenJS Foundation", Aliases: []string{"node"}},
		{ID: PHP, Name: "PHP", Category: CategoryRuntime, OpenSource: true, Vendor: "The PHP Group"},
		{ID: Python, Name: "Python", Category: CategoryRuntime, OpenSource: true, Vendor: "Python Software Foundation"},
		{ID: Java, Name: "Java", Category: CategoryRuntime, Vendor: "Oracle/OpenJDK", Aliases: []string{"jvm", "openjdk"}},
		{ID: Go, Name: "Go", Category: CategoryRuntime, OpenSource: true, Vendor: "Google", Aliases: []string{"go"}},
		{ID: Ruby, Name: "Ruby", Category: CategoryRuntime, OpenSource: true, Vendor: "Ruby Core"},
		{ID: Rust, Name: "Rust", Category: CategoryRuntime, OpenSource: true, Vendor: "Rust Foundation"},
		{ID: Elixir, Name: "Elixir", Category: CategoryRuntime, OpenSource: true, Vendor: "Elixir"},
		{ID: DotNetRuntime, Name: ".NET Runtime", Category: CategoryRuntime, Vendor: "Microsoft", Aliases: []string{"dotnet-core"}},
	} {
		Register(m)
	}

	// ── CMS ──
	for _, m := range []*TechMeta{
		{ID: "wordpress", Name: "WordPress", Category: CategoryFramework, OpenSource: true, Vendor: "Automattic", DockerImage: "wordpress:latest", DefaultPorts: []int{80}, Aliases: []string{"wp"}, Tags: []string{"cms"}},
		{ID: "ghost", Name: "Ghost CMS", Category: CategoryFramework, OpenSource: true, Vendor: "Ghost Foundation", DockerImage: "ghost:latest", Tags: []string{"cms"}},
		{ID: "drupal", Name: "Drupal", Category: CategoryFramework, OpenSource: true, Vendor: "Drupal Association", DockerImage: "drupal:latest", Tags: []string{"cms"}},
		{ID: "joomla", Name: "Joomla", Category: CategoryFramework, OpenSource: true, Vendor: "Open Source Matters", DockerImage: "joomla:latest", Tags: []string{"cms"}},
	} {
		Register(m)
	}
}
