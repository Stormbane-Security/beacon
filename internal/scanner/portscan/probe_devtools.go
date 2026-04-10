package portscan

import (
	"context"
	"fmt"
	"strings"

	"github.com/stormbane-security/beacon/internal/finding"
)

func init() {
	registerProbe(ServiceProbe{
		Name:         "grpc-reflection",
		Category:     ProbeCatProtocol,
		DefaultPorts: []int{50051},
		Detect:       detectGRPCReflection,
	})
	registerProbe(ServiceProbe{
		Name:         "gradio",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{7860},
		Detect:       detectGradio,
	})
	registerProbe(ServiceProbe{
		Name:         "automatic1111",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{7860},
		Detect:       detectAutomatic1111,
	})
	registerProbe(ServiceProbe{
		Name:         "comfyui",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{8188},
		Detect:       detectComfyUI,
	})
	registerProbe(ServiceProbe{
		Name:         "sglang",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{30000},
		Detect:       detectSGLang,
	})
	registerProbe(ServiceProbe{
		Name:         "ray-dashboard",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{8265},
		Detect:       detectRayDashboard,
	})
	registerProbe(ServiceProbe{
		Name:         "ollama",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{11434},
		Detect:       detectOllama,
	})
	registerProbe(ServiceProbe{
		Name:         "tekton-dashboard",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{9097},
		Detect:       detectTektonDashboard,
	})
}

func detectGRPCReflection(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	if !probeGRPCReflection(ctx, host, port) {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortGRPCReflectionEnabled,
		finding.SeverityHigh,
		fmt.Sprintf("gRPC server reflection enabled on port %d (unauthenticated)", port),
		"A gRPC server with reflection enabled is publicly accessible on port 50051. "+
			"gRPC reflection lists all available service definitions, method names, and protobuf schemas "+
			"without authentication, acting as an unauthenticated API documentation endpoint. "+
			"Attackers use reflection to enumerate all gRPC endpoints and craft targeted requests "+
			"for further exploitation. Disable reflection in production "+
			"(grpc.EnableReflection = false) and restrict port 50051 to internal services only.",
		map[string]any{"port": port, "service": "grpc", "reflection": true},
	)}
}

func detectGradio(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	// Probe multiple Gradio endpoints for a comprehensive detection.
	// Detection strategy: /info is the primary fingerprint (contains "gradio"
	// and "api":true). The predict endpoints alone are NOT enough because
	// services like InfluxDB return generic JSON error bodies that match
	// loose keyword checks.
	var findings []finding.Finding
	gradioDetected := false
	version := ""
	noAuth := false
	gradioServer := false // true if Server header contains gradio or uvicorn

	// Probe /info — primary Gradio identification endpoint.
	// Real Gradio returns {"version":"X.Y.Z","mode":"blocks","api":true,...}.
	// Require both "gradio" in the body AND the "api":true field to avoid
	// matching generic JSON APIs.
	if body, server, ok := probeHTTPBodyAndServer(ctx, host, port, false, "/info"); ok {
		serverLow := strings.ToLower(server)
		if strings.Contains(serverLow, "gradio") || strings.Contains(serverLow, "uvicorn") {
			gradioServer = true
		}
		bodyLow := strings.ToLower(body)
		if strings.Contains(bodyLow, "gradio") || (strings.Contains(body, `"api"`) && gradioServer) {
			gradioDetected = true
			// Extract version from the /info response (typically {"version":"4.x.x",...}).
			if idx := strings.Index(body, `"version"`); idx >= 0 {
				rest := body[idx:]
				if start := strings.Index(rest, `"`+``); start >= 0 {
					// Skip "version":" to get value
					if colon := strings.Index(rest, ":"); colon >= 0 {
						valPart := strings.TrimSpace(rest[colon+1:])
						if len(valPart) > 0 && valPart[0] == '"' {
							if end := strings.Index(valPart[1:], `"`); end >= 0 {
								version = valPart[1 : end+1]
							}
						}
					}
				}
			}
		}
	}

	// Probe /api/predict — inference endpoint that accepts arbitrary inputs.
	// Only count as Gradio if we already confirmed via /info OR the Server
	// header is Gradio/uvicorn. Matching on generic JSON keywords like
	// "data" or "error" alone causes false positives (e.g. InfluxDB).
	predictNoAuth := false
	if body, server, ok := probeHTTPBodyAndServer(ctx, host, port, false, "/api/predict"); ok {
		serverLow := strings.ToLower(server)
		if strings.Contains(serverLow, "gradio") || strings.Contains(serverLow, "uvicorn") {
			gradioServer = true
		}
		bodyLow := strings.ToLower(body)
		isGradioResponse := strings.Contains(bodyLow, "gradio") ||
			strings.Contains(bodyLow, "duration") ||
			(strings.Contains(bodyLow, `"data"`) && !strings.Contains(bodyLow, `"error"`))
		// Only mark as detected if we have a Gradio-specific signal.
		if (gradioDetected || gradioServer) && isGradioResponse {
			predictNoAuth = true
		} else if isGradioResponse && strings.Contains(bodyLow, "gradio") {
			gradioDetected = true
			predictNoAuth = true
		}
	}

	// Probe /run/predict — alternative inference path.
	if body, server, ok := probeHTTPBodyAndServer(ctx, host, port, false, "/run/predict"); ok {
		serverLow := strings.ToLower(server)
		if strings.Contains(serverLow, "gradio") || strings.Contains(serverLow, "uvicorn") {
			gradioServer = true
		}
		bodyLow := strings.ToLower(body)
		isGradioResponse := strings.Contains(bodyLow, "gradio") ||
			strings.Contains(bodyLow, "duration") ||
			(strings.Contains(bodyLow, `"data"`) && !strings.Contains(bodyLow, `"error"`))
		if (gradioDetected || gradioServer) && isGradioResponse {
			noAuth = true
		} else if isGradioResponse && strings.Contains(bodyLow, "gradio") {
			gradioDetected = true
			noAuth = true
		}
	}

	if !gradioDetected && !gradioServer {
		return nil
	}

	ev := map[string]any{"port": port, "service": "gradio", "banner": banner}
	if version != "" {
		ev["gradio_version"] = version
	}
	if predictNoAuth || noAuth {
		ev["unauthenticated_predict"] = true
	}

	findings = append(findings, makeF(
		finding.CheckPortGradioExposed,
		finding.SeverityHigh,
		fmt.Sprintf("Gradio ML demo server exposed on port %d", port),
		"A Gradio machine learning demo server is publicly accessible. Gradio deployments often "+
			"run ML models with no authentication, accept arbitrary inputs, and can be exploited for "+
			"SSRF, prompt injection, or unauthorized model access.",
		ev,
	))

	// If predict endpoints are accessible without auth, emit the stronger finding.
	if predictNoAuth || noAuth {
		findings = append(findings, makeF(
			finding.CheckAIInfraGradio,
			finding.SeverityHigh,
			fmt.Sprintf("Gradio inference endpoint unauthenticated on port %d", port),
			fmt.Sprintf("The Gradio ML server on port %d accepts inference requests at /api/predict or "+
				"/run/predict without authentication. Anyone can submit arbitrary inputs to the model, "+
				"potentially extracting training data, performing prompt injection, or consuming "+
				"GPU resources at the operator's expense.", port),
			ev,
		))
	}

	return findings
}

func detectAutomatic1111(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	body, ok := probeHTTPBody(ctx, host, port, false, "/sdapi/v1/options")
	if !ok {
		return nil
	}
	bodyLow := strings.ToLower(body)
	if !strings.Contains(bodyLow, "sd_model_checkpoint") && !strings.Contains(bodyLow, "stable_diffusion") &&
		!strings.Contains(bodyLow, "sdapi") && !strings.Contains(bodyLow, "samples_format") {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortAutomatic1111Exposed,
		finding.SeverityHigh,
		fmt.Sprintf("Automatic1111 Stable Diffusion WebUI exposed unauthenticated on port %d", port),
		"An Automatic1111 Stable Diffusion WebUI instance is publicly accessible without authentication. "+
			"The /sdapi/v1/options endpoint discloses model paths, output directories, and all SD configuration. "+
			"Unauthenticated access allows arbitrary image generation at the operator's compute cost, "+
			"model file path disclosure (aiding local file read attacks), and SSRF via "+
			"the extensions system. Enable authentication (--gradio-auth) and restrict to trusted networks.",
		map[string]any{"port": port, "service": "automatic1111",
			"url": fmt.Sprintf("http://%s:%d/sdapi/v1/options", host, port)},
	)}
}

func detectComfyUI(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	body, ok := probeHTTPBody(ctx, host, port, false, "/system_stats")
	if !ok {
		return nil
	}
	bodyLow := strings.ToLower(body)
	if !strings.Contains(bodyLow, "vram") && !strings.Contains(bodyLow, "ram_total") &&
		!strings.Contains(bodyLow, "comfyui") {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortComfyUIExposed,
		finding.SeverityHigh,
		fmt.Sprintf("ComfyUI Stable Diffusion server exposed unauthenticated on port %d", port),
		"A ComfyUI image generation server is publicly accessible without authentication. "+
			"ComfyUI is a node-based Stable Diffusion UI with full filesystem access for "+
			"model loading. Unauthenticated access allows arbitrary image generation, "+
			"reading model files via the /view endpoint (arbitrary file read traversal), "+
			"and potentially executing custom nodes with OS-level access. "+
			"Add authentication (--auth user:pass) and restrict to trusted networks.",
		map[string]any{"port": port, "service": "comfyui",
			"url": fmt.Sprintf("http://%s:%d/system_stats", host, port)},
	)}
}

func detectSGLang(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	body, ok := probeHTTPBody(ctx, host, port, false, "/v1/models")
	if !ok {
		return nil
	}
	// SGLang /v1/models returns JSON like {"object":"list","data":[{"id":"model-name","object":"model",...}]}.
	// Reject HTML responses and require JSON structure.
	trimmedBody := strings.TrimSpace(body)
	if strings.HasPrefix(trimmedBody, "<") || !strings.HasPrefix(trimmedBody, "{") {
		return nil
	}
	bodyLow := strings.ToLower(body)
	if !strings.Contains(bodyLow, `"data"`) || !strings.Contains(bodyLow, `"model"`) {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortSGLangExposed,
		finding.SeverityHigh,
		fmt.Sprintf("SGLang LLM inference server exposed unauthenticated on port %d", port),
		"An SGLang LLM inference server is publicly accessible without authentication. "+
			"SGLang is a high-throughput serving framework for large language models. "+
			"Unauthenticated access allows unlimited inference at the operator's infrastructure cost, "+
			"potential prompt injection attacks, and exposure of fine-tuned model capabilities "+
			"or system prompts. If fine-tuned on proprietary data, model inversion may be possible. "+
			"Add an API key requirement (--api-key) and place the inference server behind "+
			"an authenticated reverse proxy or VPN.",
		map[string]any{"port": port, "service": "sglang",
			"url": fmt.Sprintf("http://%s:%d/v1/models", host, port)},
	)}
}

func detectRayDashboard(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	body, ok := probeHTTPBody(ctx, host, port, false, "/api/version")
	if !ok {
		return nil
	}
	// Reject HTML responses (SPAs/web apps return 200 with HTML for any path).
	trimmedBody := strings.TrimSpace(body)
	if strings.HasPrefix(trimmedBody, "<") || strings.HasPrefix(trimmedBody, "<!") {
		return nil
	}
	ev := map[string]any{"port": port, "service": "ray"}
	if ver := parseJSONStringField(body, "version"); ver != "" {
		ev["ray_version"] = ver
	}
	// Ray /api/version returns JSON like {"version":"2.10.0","ray_version":"2.10.0"}.
	// Require "ray" in the response to avoid matching other services with /api/version.
	if !strings.Contains(strings.ToLower(body), "ray") {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortRayDashboardExposed,
		finding.SeverityCritical,
		fmt.Sprintf("Ray distributed ML dashboard exposed on port %d", port),
		"The Ray distributed computing dashboard is publicly accessible without authentication. "+
			"Ray Dashboard exposes cluster state, running jobs, actor information, and "+
			"file system paths. CVE-2026-32981 allows path traversal for arbitrary file reads. "+
			"The jobs API (/api/jobs/) allows submitting and canceling cluster jobs without auth. "+
			"Restrict to trusted networks immediately.",
		ev,
	)}
}

func detectOllama(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	ev := map[string]any{"port": port, "service": "ollama", "banner": banner}
	// Probe /api/tags — returns model list without authentication on default installs.
	if body, ok := probeHTTPBody(ctx, host, port, false, "/api/tags"); ok && strings.Contains(body, "models") {
		snippet := body
		if len(snippet) > 200 {
			snippet = snippet[:200] + "…"
		}
		ev["api_tags_snippet"] = snippet
		return []finding.Finding{makeF(
			finding.CheckPortOllamaExposed,
			finding.SeverityHigh,
			fmt.Sprintf("Ollama LLM inference server exposed on port %d (unauthenticated)", port),
			"An Ollama local LLM inference server is publicly accessible on port 11434 without authentication. "+
				"The /api/tags endpoint lists all installed AI models. The /api/generate and /api/chat endpoints "+
				"allow arbitrary model inference. Approximately 12,000 Ollama instances are exposed on the internet. "+
				"Ollama is designed for localhost use only — restrict access with a firewall or bind to 127.0.0.1.",
			ev,
		)}
	}
	// GHSA-q3jj-7xxq-6mgr: Ollama < 0.1.47 directory traversal via model blob endpoint.
	if vbody, ok := probeHTTPBody(ctx, host, port, false, "/api/version"); ok {
		if strings.Contains(vbody, "version") {
			ev["api_version_response"] = vbody
			var findings []finding.Finding
			if isVulnerableOllamaVersion(vbody) {
				findings = append(findings, makeF(
					finding.CheckCVEOllamaPathTraversal,
					finding.SeverityHigh,
					fmt.Sprintf("Ollama < 0.1.47 path traversal (GHSA-q3jj-7xxq-6mgr) on port %d", port),
					"GHSA-q3jj-7xxq-6mgr: Ollama versions before 0.1.47 allow directory traversal via the "+
						"model blob endpoint (/api/blobs/:digest). An unauthenticated attacker can read "+
						"arbitrary files from the server by crafting a path traversal in the digest parameter. "+
						"Upgrade Ollama to 0.1.47 or later.",
					ev,
				))
			}
			return findings
		}
	}
	return nil
}

func detectTektonDashboard(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	body, ok := probeHTTPBody(ctx, host, port, false, "/")
	if !ok {
		return nil
	}
	bodyLow := strings.ToLower(body)
	if !strings.Contains(bodyLow, "tekton") {
		return nil
	}
	ev := map[string]any{"port": port, "service": "tekton"}
	return []finding.Finding{makeF(
		finding.CheckPortTektonDashboardExposed,
		finding.SeverityHigh,
		fmt.Sprintf("Tekton Pipelines dashboard exposed on port %d", port),
		"The Tekton CI/CD Pipelines dashboard is publicly accessible without authentication. "+
			"Tekton Dashboard exposes pipeline runs, task runs, and cluster configuration. "+
			"CVE-2026-33211 allows path traversal in the git resolver to read arbitrary files "+
			"from the resolver pod. Restrict to trusted networks and configure auth.",
		ev,
	)}
}
