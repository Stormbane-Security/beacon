package infra

// Web servers, reverse proxies, load balancers, and API gateways.

const (
	Nginx     Technology = "nginx"
	Apache    Technology = "apache"
	Caddy     Technology = "caddy"
	Traefik   Technology = "traefik"
	Envoy     Technology = "envoy"
	HAProxy   Technology = "haproxy"
	LiteSpeed Technology = "litespeed"
	IIS       Technology = "iis"
	Varnish   Technology = "varnish"
	Kong      Technology = "kong"
	Tyk       Technology = "tyk"
	F5        Technology = "f5"
	Citrix    Technology = "citrix-netscaler"
)

func init() {
	// ── Web Servers ──
	for _, m := range []*TechMeta{
		{ID: Nginx, Name: "NGINX", Category: CategoryServer, Layer: LayerReverseProxy, OpenSource: true, Vendor: "F5/NGINX", DefaultPorts: []int{80, 443}, DockerImage: "nginx:alpine"},
		{ID: Apache, Name: "Apache HTTP Server", Category: CategoryServer, Layer: LayerOrigin, OpenSource: true, Vendor: "Apache Software Foundation", DefaultPorts: []int{80, 443}, DockerImage: "httpd:alpine", Aliases: []string{"httpd", "apache2"}},
		{ID: Caddy, Name: "Caddy", Category: CategoryServer, Layer: LayerReverseProxy, OpenSource: true, Vendor: "Caddy", DefaultPorts: []int{80, 443}, DockerImage: "caddy:alpine"},
		{ID: LiteSpeed, Name: "LiteSpeed", Category: CategoryServer, Layer: LayerOrigin, Vendor: "LiteSpeed Technologies", DefaultPorts: []int{80, 443}},
		{ID: IIS, Name: "Microsoft IIS", Category: CategoryServer, Layer: LayerOrigin, Vendor: "Microsoft", DefaultPorts: []int{80, 443}},
	} {
		Register(m)
	}

	// ── Reverse Proxies & Load Balancers ──
	for _, m := range []*TechMeta{
		{ID: Traefik, Name: "Traefik", Category: CategoryServer, Layer: LayerReverseProxy, OpenSource: true, Vendor: "Traefik Labs", DefaultPorts: []int{80, 443, 8080}, DockerImage: "traefik:v3.0"},
		{ID: Envoy, Name: "Envoy Proxy", Category: CategoryServer, Layer: LayerServiceMesh, OpenSource: true, Vendor: "CNCF/Lyft", DefaultPorts: []int{80, 443, 9901}, DockerImage: "envoyproxy/envoy:v1.31-latest"},
		{ID: HAProxy, Name: "HAProxy", Category: CategoryServer, Layer: LayerLoadBalancer, OpenSource: true, Vendor: "HAProxy Technologies", DefaultPorts: []int{80, 443}, DockerImage: "haproxy:alpine"},
		{ID: Varnish, Name: "Varnish Cache", Category: CategoryServer, Layer: LayerCDNEdge, OpenSource: true, Vendor: "Varnish Software", DefaultPorts: []int{80, 6081}, DockerImage: "varnish:stable"},
		{ID: F5, Name: "F5 BIG-IP", Category: CategoryServer, Layer: LayerLoadBalancer, Vendor: "F5 Networks", DefaultPorts: []int{443, 8443}},
		{ID: Citrix, Name: "Citrix NetScaler", Category: CategoryServer, Layer: LayerLoadBalancer, Vendor: "Citrix", DefaultPorts: []int{443, 9443}, Aliases: []string{"netscaler"}},
	} {
		Register(m)
	}

	// ── API Gateways ──
	for _, m := range []*TechMeta{
		{ID: Kong, Name: "Kong Gateway", Category: CategoryGateway, Layer: LayerAPIGateway, OpenSource: true, Vendor: "Kong Inc", DefaultPorts: []int{8000, 8443, 8001}, DockerImage: "kong:latest"},
		{ID: Tyk, Name: "Tyk Gateway", Category: CategoryGateway, Layer: LayerAPIGateway, OpenSource: true, Vendor: "Tyk Technologies", DefaultPorts: []int{8080}, DockerImage: "tykio/tyk-gateway:latest"},
		{ID: "apigee", Name: "Apigee", Category: CategoryGateway, Layer: LayerAPIGateway, CloudProvider: GCP, Vendor: "Google"},
		{ID: "azure-apim", Name: "Azure API Management", Category: CategoryGateway, Layer: LayerAPIGateway, CloudProvider: Azure, Vendor: "Microsoft"},
	} {
		Register(m)
	}

	// ── CDN Providers ──
	for _, m := range []*TechMeta{
		{ID: "akamai", Name: "Akamai", Category: CategoryCDN, Layer: LayerCDNEdge, Vendor: "Akamai Technologies"},
		{ID: "fastly", Name: "Fastly", Category: CategoryCDN, Layer: LayerCDNEdge, Vendor: "Fastly"},
		{ID: "keycdn", Name: "KeyCDN", Category: CategoryCDN, Layer: LayerCDNEdge, Vendor: "proinity"},
		{ID: "bunnycdn", Name: "BunnyCDN", Category: CategoryCDN, Layer: LayerCDNEdge, Vendor: "BunnyCDN"},
		{ID: "sucuri", Name: "Sucuri", Category: CategoryCDN, Layer: LayerCDNEdge, Vendor: "Sucuri/GoDaddy", Tags: []string{"waf"}},
	} {
		Register(m)
	}
}
