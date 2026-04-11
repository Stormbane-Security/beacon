package portscan

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/stormbane-security/beacon/internal/exploit"
	"github.com/stormbane-security/beacon/internal/finding"
)

func init() {
	// Register engine-driven probes for services with YAML playbooks.
	for _, pb := range exploit.Playbooks() {
		pb := pb // capture loop variable
		registerProbe(ServiceProbe{
			Name:         pb.Service + "-exploit",
			Category:     ProbeCatHTTP,
			DefaultPorts: pb.DefaultPorts,
			Detect: func(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
				return exploit.Run(ctx, pb, host, port, exploit.FindingFunc(makeF), false)
			},
		})
	}

	// Go-only probes for services without YAML playbooks.
	registerProbe(ServiceProbe{
		Name:         "tomcat-creds",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{8080},
		Detect:       detectTomcatDefaultCreds,
	})
	registerProbe(ServiceProbe{
		Name:         "portainer-creds",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{9000, 9443},
		Detect:       detectPortainerSetup,
	})
	registerProbe(ServiceProbe{
		Name:         "pgadmin-creds",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{5050, 80},
		Detect:       detectPgAdminDefaultCreds,
	})
	registerProbe(ServiceProbe{
		Name:         "zabbix-creds",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{80, 8080},
		Detect:       detectZabbixDefaultCreds,
	})
	registerProbe(ServiceProbe{
		Name:         "gitea-noauth",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{3000},
		Detect:       detectGiteaNoAuth,
	})
	registerProbe(ServiceProbe{
		Name:         "superset-creds",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{8088},
		Detect:       detectSupersetDefaultCreds,
	})
	registerProbe(ServiceProbe{
		Name:         "wordpress-creds",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{80, 443, 8080},
		Detect:       detectWordPressDefaultCreds,
	})
	registerProbe(ServiceProbe{
		Name:         "mongo-express-creds",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{8081},
		Detect:       detectMongoExpressDefaultCreds,
	})
	registerProbe(ServiceProbe{
		Name:         "phpmyadmin-creds",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{80, 8080},
		Detect:       detectPhpMyAdminDefaultCreds,
	})
	registerProbe(ServiceProbe{
		Name:         "kibana-creds",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{5601},
		Detect:       detectKibanaDefaultCreds,
	})
	registerProbe(ServiceProbe{
		Name:         "rabbitmq-creds",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{15672},
		Detect:       detectRabbitMQDefaultCreds,
	})
	registerProbe(ServiceProbe{
		Name:         "minio-console-creds",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{9001},
		Detect:       detectMinIOConsoleDefaultCreds,
	})
}

// detectTomcatDefaultCreds attempts Tomcat Manager login with common default credentials.
func detectTomcatDefaultCreds(ctx context.Context, host string, port int, _ string, makeF findingMaker) []finding.Finding {
	defaultPairs := [][2]string{
		{"tomcat", "tomcat"},
		{"admin", "admin"},
		{"manager", "manager"},
		{"tomcat", "s3cret"},
	}

	for _, creds := range defaultPairs {
		body, ok := probeHTTPBodyWithAuth(ctx, host, port, false, "/manager/html", creds[0], creds[1])
		if !ok {
			continue
		}
		if strings.Contains(strings.ToLower(body), "tomcat") && strings.Contains(strings.ToLower(body), "manager") {
			tcEv := map[string]any{"port": port, "service": "tomcat", "default_creds": true,
				"username": creds[0],
				"proof":    fmt.Sprintf("curl -s -u %s:%s http://%s:%d/manager/html", creds[0], creds[1], host, port)}
			if ver := extractTomcatVersion(body); ver != "" {
				tcEv["version"] = ver
				tcEv["product"] = "Apache Tomcat " + ver
			}
			return []finding.Finding{makeF(
				finding.CheckPortTomcatDefaultCreds,
				finding.SeverityCritical,
				fmt.Sprintf("Apache Tomcat Manager accepts default %s:%s credentials on port %d", creds[0], creds[1], port),
				fmt.Sprintf("The Apache Tomcat Manager application is accessible with credentials %s/%s. "+
					"An attacker can deploy arbitrary WAR files to achieve remote code execution on the server.", creds[0], creds[1]),
				tcEv,
			)}
		}
	}
	return nil
}

// detectPortainerSetup checks if Portainer's initial admin setup is still available.
func detectPortainerSetup(ctx context.Context, host string, port int, _ string, makeF findingMaker) []finding.Finding {
	// Portainer serves on HTTPS by default on 9443, HTTP on 9000.
	useTLS := port == 9443

	// Check admin/check endpoint directly — probeHTTPBody only returns true for
	// 200, but uninitialized Portainer returns 404 which we need to detect.
	url := fmt.Sprintf("http://%s:%d/api/users/admin/check", host, port)
	if useTLS {
		url = fmt.Sprintf("https://%s:%d/api/users/admin/check", host, port)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: httpTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     transport}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()

	// Portainer returns 404 with a JSON error body like {"message":"...","details":"..."}.
	// A bare 404 from nginx/apache/tomcat is NOT Portainer. Verify by checking
	// the response body and Portainer-specific headers.
	bodyStr := string(respBody)
	isPortainer := resp.Header.Get("X-Portainer-Version") != "" ||
		(strings.Contains(bodyStr, "\"message\"") && strings.Contains(bodyStr, "\"details\""))

	if resp.StatusCode == http.StatusNotFound && isPortainer {
		setupEv := map[string]any{"port": port, "service": "portainer", "setup_available": true,
			"proof": fmt.Sprintf("curl -s %s", url)}
		if pv := resp.Header.Get("X-Portainer-Version"); pv != "" {
			setupEv["version"] = pv
			setupEv["product"] = "Portainer " + pv
		}
		return []finding.Finding{makeF(
			finding.CheckPortPortainerDefaultCreds,
			finding.SeverityCritical,
			fmt.Sprintf("Portainer initial admin setup available on port %d", port),
			"Portainer's initial admin account has not been created yet. "+
				"Anyone who accesses this Portainer instance can create the admin account "+
				"and gain full control over all managed Docker/Kubernetes environments.",
			setupEv,
		)}
	}

	// Also check if the status API reveals it's Portainer without auth.
	statusBody, ok := probeHTTPBody(ctx, host, port, useTLS, "/api/status")
	if ok && strings.Contains(statusBody, "Version") {
		// Portainer is accessible, but admin is set up. Check if we can list endpoints.
		endpointsBody, ok := probeHTTPBody(ctx, host, port, useTLS, "/api/endpoints")
		if ok && strings.Contains(endpointsBody, "Name") {
			noAuthEv := map[string]any{"port": port, "service": "portainer", "authenticated": false}
			if ver := parseJSONStringField(statusBody, "Version"); ver != "" {
				noAuthEv["version"] = ver
				noAuthEv["product"] = "Portainer " + ver
			}
			return []finding.Finding{makeF(
				finding.CheckPortPortainerDefaultCreds,
				finding.SeverityCritical,
				fmt.Sprintf("Portainer API accessible without authentication on port %d", port),
				"Portainer API endpoints are accessible without authentication. "+
					"An attacker can manage all connected Docker and Kubernetes environments.",
				noAuthEv,
			)}
		}
	}
	return nil
}

// detectPgAdminDefaultCreds attempts pgAdmin login with default credentials.
func detectPgAdminDefaultCreds(ctx context.Context, host string, port int, _ string, makeF findingMaker) []finding.Finding {
	// Verify it's pgAdmin by checking the login page.
	body, ok := probeHTTPBody(ctx, host, port, false, "/login")
	if !ok || !strings.Contains(strings.ToLower(body), "pgadmin") {
		return nil
	}

	// pgAdmin uses form-based login. Try default credentials.
	url := fmt.Sprintf("http://%s:%d/api/auth/login", host, port)
	payload := strings.NewReader(`{"email":"admin@admin.com","password":"admin","language":"en"}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, payload)
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: httpTimeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))

	if resp.StatusCode == http.StatusOK && strings.Contains(string(b), "Authentication") {
		return []finding.Finding{makeF(
			finding.CheckPortPgAdminDefaultCreds,
			finding.SeverityCritical,
			fmt.Sprintf("pgAdmin accepts default credentials on port %d", port),
			"pgAdmin database management tool accepts default credentials (admin@admin.com / admin). "+
				"An attacker can view, modify, and delete data in all configured PostgreSQL databases.",
			map[string]any{"port": port, "service": "pgadmin", "default_creds": true,
				"proof": fmt.Sprintf("curl -s -X POST http://%s:%d/api/auth/login -H 'Content-Type: application/json' -d '{\"email\":\"admin@admin.com\",\"password\":\"admin\"}'", host, port)},
		)}
	}
	return nil
}

// detectZabbixDefaultCreds attempts Zabbix login with Admin:zabbix.
func detectZabbixDefaultCreds(ctx context.Context, host string, port int, _ string, makeF findingMaker) []finding.Finding {
	// Verify it's Zabbix by checking the login page.
	body, ok := probeHTTPBody(ctx, host, port, false, "/zabbix/")
	if !ok || !strings.Contains(strings.ToLower(body), "zabbix") {
		// Try without /zabbix/ prefix.
		body, ok = probeHTTPBody(ctx, host, port, false, "/")
		if !ok || !strings.Contains(strings.ToLower(body), "zabbix") {
			return nil
		}
	}

	// Zabbix uses JSON-RPC API for authentication.
	url := fmt.Sprintf("http://%s:%d/api_jsonrpc.php", host, port)
	payload := strings.NewReader(`{"jsonrpc":"2.0","method":"user.login","params":{"username":"Admin","password":"zabbix"},"id":1}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, payload)
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json-rpc")
	client := &http.Client{Timeout: httpTimeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))

	var rpcResp struct {
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(b, &rpcResp); err != nil {
		return nil
	}
	// Successful login returns a session ID string in "result", error returns an object in "error".
	if len(rpcResp.Result) > 2 && len(rpcResp.Error) == 0 {
		return []finding.Finding{makeF(
			finding.CheckPortZabbixDefaultCreds,
			finding.SeverityCritical,
			fmt.Sprintf("Zabbix accepts default Admin:zabbix credentials on port %d", port),
			"Zabbix monitoring server accepts the factory-default super-admin credentials Admin/zabbix. "+
				"An attacker can view all monitored infrastructure, execute remote commands on agents, "+
				"and pivot through the monitoring network.",
			map[string]any{"port": port, "service": "zabbix", "default_creds": true,
				"proof": fmt.Sprintf("curl -s -X POST http://%s:%d/api_jsonrpc.php -H 'Content-Type: application/json-rpc' -d '{\"jsonrpc\":\"2.0\",\"method\":\"user.login\",\"params\":{\"username\":\"Admin\",\"password\":\"zabbix\"},\"id\":1}'", host, port)},
		)}
	}
	return nil
}

// detectGiteaNoAuth checks if Gitea/Forgejo exposes repositories without authentication.
func detectGiteaNoAuth(ctx context.Context, host string, port int, _ string, makeF findingMaker) []finding.Finding {
	// Verify it's Gitea/Forgejo by checking the API version endpoint.
	body, ok := probeHTTPBody(ctx, host, port, false, "/api/v1/version")
	if !ok || !strings.Contains(body, "version") {
		return nil
	}

	// Extract Gitea/Forgejo version from X-Gitea-Version header or /api/v1/version JSON.
	giteaVersion := ""
	if ver := parseJSONStringField(body, "version"); ver != "" {
		giteaVersion = ver
	}

	// Check if the repos search API is accessible without auth.
	// A successful response (contains "ok" or "data" or "full_name") means
	// the API is open. Even an empty repo list is a finding — the API itself
	// should require authentication.
	repoBody, ok := probeHTTPBody(ctx, host, port, false, "/api/v1/repos/search?limit=5")
	if !ok {
		return nil
	}
	if strings.Contains(repoBody, "full_name") || strings.Contains(repoBody, `"ok":true`) || strings.Contains(repoBody, `"data":`) {
		sev := finding.SeverityHigh
		desc := "Gitea or Forgejo is accessible without authentication and exposes repository contents. " +
			"An attacker can browse source code, issues, and potentially clone private repositories."
		if !strings.Contains(repoBody, "full_name") {
			sev = finding.SeverityMedium
			desc = "Gitea or Forgejo API is accessible without authentication. " +
				"No repositories are currently exposed, but the unauthenticated API allows enumeration " +
				"and may expose repos if they are created later."
		}
		return []finding.Finding{makeF(
			finding.CheckPortGiteaNoAuth,
			sev,
			fmt.Sprintf("Gitea/Forgejo exposes API without authentication on port %d", port),
			desc,
			func() map[string]any {
					ev := map[string]any{"port": port, "service": "gitea", "authenticated": false,
						"proof": fmt.Sprintf("curl -s http://%s:%d/api/v1/repos/search?limit=5", host, port)}
					if giteaVersion != "" {
						ev["version"] = giteaVersion
						ev["product"] = "Gitea " + giteaVersion
					}
					return ev
				}(),
		)}
	}
	return nil
}

// detectWordPressDefaultCreds attempts WordPress login with common default credentials.
func detectWordPressDefaultCreds(ctx context.Context, host string, port int, _ string, makeF findingMaker) []finding.Finding {
	// Verify it's WordPress by checking the login page.
	body, ok := probeHTTPBody(ctx, host, port, false, "/wp-login.php")
	if !ok || !strings.Contains(strings.ToLower(body), "wordpress") {
		return nil
	}

	defaultPairs := [][2]string{
		{"admin", "admin"},
		{"admin", "password"},
	}

	for _, creds := range defaultPairs {
		url := fmt.Sprintf("http://%s:%d/wp-login.php", host, port)
		payload := strings.NewReader(fmt.Sprintf("log=%s&pwd=%s&wp-submit=Log+In", creds[0], creds[1]))
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, payload)
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		client := &http.Client{Timeout: httpTimeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		_, _ = io.ReadAll(io.LimitReader(resp.Body, 512))
		_ = resp.Body.Close()

		// WordPress redirects to /wp-admin/ on successful login (302 with Location header).
		if resp.StatusCode == http.StatusFound {
			loc := resp.Header.Get("Location")
			if strings.Contains(loc, "wp-admin") {
				return []finding.Finding{makeF(
					finding.CheckPortWordPressDefaultCreds,
					finding.SeverityCritical,
					fmt.Sprintf("WordPress accepts default %s:%s credentials on port %d", creds[0], creds[1], port),
					fmt.Sprintf("WordPress admin panel accepts default credentials %s/%s. "+
						"An attacker can install plugins, edit themes, and achieve remote code execution on the server.", creds[0], creds[1]),
					map[string]any{"port": port, "service": "wordpress", "default_creds": true,
						"username": creds[0],
						"proof":    fmt.Sprintf("curl -s -o /dev/null -w '%%{redirect_url}' -X POST http://%s:%d/wp-login.php -d 'log=%s&pwd=%s&wp-submit=Log+In'", host, port, creds[0], creds[1])},
				)}
			}
		}
	}
	return nil
}

// detectMongoExpressDefaultCreds attempts mongo-express login with admin:pass.
func detectMongoExpressDefaultCreds(ctx context.Context, host string, port int, _ string, makeF findingMaker) []finding.Finding {
	// mongo-express uses HTTP basic auth by default.
	body, ok := probeHTTPBodyWithAuth(ctx, host, port, false, "/", "admin", "pass")
	if !ok {
		return nil
	}
	if strings.Contains(strings.ToLower(body), "mongo express") || strings.Contains(strings.ToLower(body), "mongo-express") {
		return []finding.Finding{makeF(
			finding.CheckPortMongoExpressDefaultCreds,
			finding.SeverityCritical,
			fmt.Sprintf("mongo-express accepts default admin:pass credentials on port %d", port),
			"mongo-express web interface accepts factory-default credentials admin/pass. "+
				"An attacker can browse, modify, and delete all MongoDB databases and collections.",
			map[string]any{"port": port, "service": "mongo-express", "default_creds": true,
				"username": "admin",
				"proof":    fmt.Sprintf("curl -s -u admin:pass http://%s:%d/", host, port)},
		)}
	}
	return nil
}

// detectPhpMyAdminDefaultCreds attempts phpMyAdmin login with root and empty/default password.
func detectPhpMyAdminDefaultCreds(ctx context.Context, host string, port int, _ string, makeF findingMaker) []finding.Finding {
	// Verify it's phpMyAdmin by checking the login page.
	body, ok := probeHTTPBody(ctx, host, port, false, "/index.php")
	if !ok || !strings.Contains(strings.ToLower(body), "phpmyadmin") {
		return nil
	}

	defaultPairs := [][2]string{
		{"root", ""},
		{"root", "root"},
	}

	for _, creds := range defaultPairs {
		url := fmt.Sprintf("http://%s:%d/index.php", host, port)
		payload := strings.NewReader(fmt.Sprintf("pma_username=%s&pma_password=%s&server=1", creds[0], creds[1]))
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, payload)
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		client := &http.Client{Timeout: httpTimeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()

		// Successful login: redirect to main page or response contains navigation elements.
		if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusOK {
			bodyStr := strings.ToLower(string(b))
			loc := strings.ToLower(resp.Header.Get("Location"))
			if strings.Contains(loc, "index.php") && !strings.Contains(loc, "login") ||
				strings.Contains(bodyStr, "server_databases") || strings.Contains(bodyStr, "navigation") {
				passDesc := creds[1]
				if passDesc == "" {
					passDesc = "(empty)"
				}
				return []finding.Finding{makeF(
					finding.CheckPortPhpMyAdminDefaultCreds,
					finding.SeverityCritical,
					fmt.Sprintf("phpMyAdmin accepts root:%s credentials on port %d", passDesc, port),
					fmt.Sprintf("phpMyAdmin database management tool accepts credentials root/%s. "+
						"An attacker can read, modify, and delete all MySQL/MariaDB databases.", passDesc),
					map[string]any{"port": port, "service": "phpmyadmin", "default_creds": true,
						"username": creds[0],
						"proof":    fmt.Sprintf("curl -s -X POST http://%s:%d/index.php -d 'pma_username=%s&pma_password=%s&server=1'", host, port, creds[0], creds[1])},
				)}
			}
		}
	}
	return nil
}

// detectKibanaDefaultCreds attempts Kibana login with elastic:changeme.
func detectKibanaDefaultCreds(ctx context.Context, host string, port int, _ string, makeF findingMaker) []finding.Finding {
	// Kibana uses Elasticsearch credentials. Try the security API.
	body, ok := probeHTTPBodyWithAuth(ctx, host, port, false, "/api/security/v1/me", "elastic", "changeme")
	if !ok {
		return nil
	}
	if strings.Contains(body, "username") && strings.Contains(body, "elastic") {
		return []finding.Finding{makeF(
			finding.CheckPortKibanaDefaultCreds,
			finding.SeverityCritical,
			fmt.Sprintf("Kibana accepts default elastic:changeme credentials on port %d", port),
			"Kibana accepts the Elasticsearch default credentials elastic/changeme. "+
				"An attacker can view all indices, execute queries, and access sensitive data "+
				"stored in Elasticsearch via the Kibana dashboard.",
			map[string]any{"port": port, "service": "kibana", "default_creds": true,
				"username": "elastic",
				"proof":    fmt.Sprintf("curl -s -u elastic:changeme http://%s:%d/api/security/v1/me", host, port)},
		)}
	}
	return nil
}

// detectRabbitMQDefaultCreds attempts RabbitMQ Management login with guest:guest.
func detectRabbitMQDefaultCreds(ctx context.Context, host string, port int, _ string, makeF findingMaker) []finding.Finding {
	body, ok := probeHTTPBodyWithAuth(ctx, host, port, false, "/api/whoami", "guest", "guest")
	if !ok {
		return nil
	}
	if strings.Contains(body, "name") && strings.Contains(body, "guest") {
		return []finding.Finding{makeF(
			finding.CheckPortRabbitMQDefaultCreds,
			finding.SeverityCritical,
			fmt.Sprintf("RabbitMQ Management accepts default guest:guest credentials on port %d", port),
			"RabbitMQ Management API accepts factory-default credentials guest/guest. "+
				"An attacker can view all queues, exchanges, and messages, publish malicious messages, "+
				"and disrupt message-driven services.",
			map[string]any{"port": port, "service": "rabbitmq", "default_creds": true,
				"username": "guest",
				"proof":    fmt.Sprintf("curl -s -u guest:guest http://%s:%d/api/whoami", host, port)},
		)}
	}
	return nil
}

// detectMinIOConsoleDefaultCreds attempts MinIO Console login with minioadmin:minioadmin.
func detectMinIOConsoleDefaultCreds(ctx context.Context, host string, port int, _ string, makeF findingMaker) []finding.Finding {
	url := fmt.Sprintf("http://%s:%d/api/v1/login", host, port)
	payload := strings.NewReader(`{"accessKey":"minioadmin","secretKey":"minioadmin"}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, payload)
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: httpTimeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))

	if resp.StatusCode == http.StatusNoContent || (resp.StatusCode == http.StatusOK && strings.Contains(string(b), "sessionId")) {
		return []finding.Finding{makeF(
			finding.CheckPortMinIODefaultCreds,
			finding.SeverityCritical,
			fmt.Sprintf("MinIO Console accepts default minioadmin:minioadmin credentials on port %d", port),
			"MinIO Console accepts factory-default credentials minioadmin/minioadmin. "+
				"An attacker can access all S3-compatible object storage buckets, download sensitive files, "+
				"and modify or delete stored data.",
			map[string]any{"port": port, "service": "minio", "default_creds": true,
				"username": "minioadmin",
				"proof":    fmt.Sprintf("curl -s -X POST http://%s:%d/api/v1/login -H 'Content-Type: application/json' -d '{\"accessKey\":\"minioadmin\",\"secretKey\":\"minioadmin\"}'", host, port)},
		)}
	}
	return nil
}

// detectSupersetDefaultCreds attempts Apache Superset login with admin:admin.
func detectSupersetDefaultCreds(ctx context.Context, host string, port int, _ string, makeF findingMaker) []finding.Finding {
	// Superset is already detected by probe_cloud.go's detectSuperset.
	// This probe focuses specifically on default credentials.
	_, ok := probeHTTPBody(ctx, host, port, false, "/api/v1/security/login")
	if !ok {
		// Check if it's Superset by looking at the login page.
		body, ok := probeHTTPBody(ctx, host, port, false, "/login/")
		if !ok || !strings.Contains(strings.ToLower(body), "superset") {
			return nil
		}
	}

	// Try the API login endpoint.
	url := fmt.Sprintf("http://%s:%d/api/v1/security/login", host, port)
	payload := strings.NewReader(`{"username":"admin","password":"admin","provider":"db","refresh":true}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, payload)
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: httpTimeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))

	if resp.StatusCode == http.StatusOK && strings.Contains(string(b), "access_token") {
		return []finding.Finding{makeF(
			finding.CheckPortSupersetDefaultCreds,
			finding.SeverityCritical,
			fmt.Sprintf("Apache Superset accepts default admin:admin credentials on port %d", port),
			"Apache Superset BI platform accepts factory-default credentials admin/admin. "+
				"An attacker can view all dashboards, query connected databases, "+
				"and potentially execute arbitrary SQL on all configured data sources.",
			map[string]any{"port": port, "service": "superset", "default_creds": true,
				"proof": fmt.Sprintf("curl -s -X POST http://%s:%d/api/v1/security/login -H 'Content-Type: application/json' -d '{\"username\":\"admin\",\"password\":\"admin\",\"provider\":\"db\"}'", host, port)},
		)}
	}
	return nil
}
