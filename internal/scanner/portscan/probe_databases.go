package portscan

import (
	"context"
	"fmt"
	"strings"

	"github.com/stormbane-security/beacon/internal/finding"
)

func init() {
	registerProbe(ServiceProbe{
		Name:         "elasticsearch",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{9200},
		Detect:       detectElasticsearch,
	})
	registerProbe(ServiceProbe{
		Name:         "mongodb",
		Category:     ProbeCatProtocol,
		DefaultPorts: []int{27017},
		Detect:       detectMongoDB,
	})
	registerProbe(ServiceProbe{
		Name:         "mysql-postgres-mssql-oracle",
		Category:     ProbeCatProtocol,
		DefaultPorts: []int{3306, 5432, 1433, 1521},
		Detect:       detectRelationalDB,
	})
	registerProbe(ServiceProbe{
		Name:         "memcached",
		Category:     ProbeCatProtocol,
		DefaultPorts: []int{11211},
		Detect:       detectMemcached,
	})
	registerProbe(ServiceProbe{
		Name:         "couchdb",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{5984},
		Detect:       detectCouchDB,
	})
	registerProbe(ServiceProbe{
		Name:         "influxdb",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{8086},
		Detect:       detectInfluxDB,
	})
	registerProbe(ServiceProbe{
		Name:         "cassandra",
		Category:     ProbeCatProtocol,
		DefaultPorts: []int{9042},
		Detect:       detectCassandra,
	})
	registerProbe(ServiceProbe{
		Name:         "neo4j",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{7474},
		Detect:       detectNeo4j,
	})
	registerProbe(ServiceProbe{
		Name:         "splunk-mgmt",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{8089},
		Detect:       detectSplunkMgmt,
	})
}

func detectElasticsearch(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	body, ok := probeHTTPBody(ctx, host, port, false, "/")
	if !ok {
		return nil
	}
	// Require ES/OpenSearch-specific JSON fields in root response.
	// ES returns: {"name":"...","cluster_name":"...","cluster_uuid":"...","version":{"number":"..."},...}
	// Require cluster_name AND (cluster_uuid OR "version"+"number") to avoid false positives
	// on other HTTP services that might have one of these fields (e.g. RabbitMQ management).
	bodyLower := strings.ToLower(body)
	if !strings.Contains(bodyLower, "cluster_name") {
		return nil
	}
	if !strings.Contains(bodyLower, "cluster_uuid") && (!strings.Contains(bodyLower, `"version"`) || !strings.Contains(bodyLower, `"number"`)) {
		return nil
	}
	// Distinguish OpenSearch from Elasticsearch via the root response.
	serviceName := "Elasticsearch"
	serviceLabel := "Unauthenticated Elasticsearch"
	description := "An Elasticsearch cluster is accessible without credentials. " +
		"All indexed data can be read, modified, or deleted by anyone with network access."
	if strings.Contains(strings.ToLower(body), "opensearch") {
		serviceName = "OpenSearch"
		serviceLabel = "Unauthenticated OpenSearch"
		description = "An OpenSearch cluster is accessible without credentials. " +
			"All indexed data can be read, modified, or deleted by anyone with network access."
	}
	esVer := parseJSONStringField(body, "number")
	esEv := map[string]any{
		"port": port, "service": serviceName,
		"authenticated": false, "auth_status": "no_auth",
		"banner": banner,
	}
	if esVer != "" {
		esEv["version"] = esVer
		esEv["product"] = serviceName + " " + esVer
	}
	var esFindings []finding.Finding
	esFindings = append(esFindings, makeF(
		finding.CheckPortElasticsearchUnauth,
		finding.SeverityCritical,
		fmt.Sprintf("%s exposed on port %d", serviceLabel, port),
		description,
		esEv,
	))
	// CVE-2015-1427: Elasticsearch ≤ 1.5.x Groovy sandbox escape → unauthenticated RCE.
	if serviceName == "Elasticsearch" && isElasticsearchGroovyVulnerable(esVer) {
		esFindings = append(esFindings, makeF(
			finding.CheckCVEElasticsearchGroovyRCE,
			finding.SeverityCritical,
			fmt.Sprintf("CVE-2015-1427: Elasticsearch %s Groovy sandbox escape → unauthenticated RCE on port %d", esVer, port),
			fmt.Sprintf("Elasticsearch %s has dynamic Groovy scripting enabled by default. "+
				"CVE-2015-1427 (CVSS 10.0) — the Groovy sandbox in Elasticsearch < 1.6.0 is bypassable, "+
				"allowing an unauthenticated attacker to execute arbitrary OS commands by sending "+
				"crafted Groovy scripts via the _search or _msearch API. "+
				"Upgrade to Elasticsearch ≥ 1.6.0 and disable dynamic scripting "+
				"(`script.disable_dynamic: true` in elasticsearch.yml).", esVer),
			map[string]any{"port": port, "service": serviceName, "es_version": esVer, "cve": "CVE-2015-1427"},
		))
	}
	return esFindings
}

func detectMongoDB(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	unauth := probeMongoDB(ctx, host, port)
	if !unauth {
		return nil
	}
	ev := map[string]any{
		"port": port, "service": "mongodb",
		"authenticated": false, "auth_status": "no_auth",
		"banner": banner,
	}
	return []finding.Finding{makeF(
		finding.CheckPortDatabaseExposed,
		finding.SeverityCritical,
		fmt.Sprintf("Unauthenticated MongoDB exposed on port %d", port),
		"A MongoDB instance is accepting connections without authentication. "+
			"All collections and documents are readable and writable by any network client.",
		ev,
	)}
}

func detectRelationalDB(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	// Try each database protocol probe — detect by wire protocol, not port number.
	// MySQL: greeting packet starts with protocol version 0x0a/0x09
	if probeMySQL(ctx, host, port) {
		dbName := "MySQL"
		// Enhanced probe: parse full greeting for version, capabilities, auth plugin.
		greetingInfo := probeMySQLGreeting(ctx, host, port)
		mysqlVer := ""
		if greetingInfo != nil {
			mysqlVer = greetingInfo.Version
		} else {
			mysqlVer = probeMySQLVersion(ctx, host, port)
		}
		dbEv := map[string]any{
			"port": port, "service": dbName,
			"banner": banner,
		}
		noAuthEv := map[string]any{
			"port": port, "service": dbName,
			"user": "root", "password": "(empty)",
			"auth_status": "no_auth",
		}
		if mysqlVer != "" {
			dbEv["version"] = mysqlVer
			dbEv["product"] = "MySQL " + mysqlVer
			noAuthEv["version"] = mysqlVer
			noAuthEv["product"] = "MySQL " + mysqlVer
		}
		if greetingInfo != nil {
			if greetingInfo.AuthPlugin != "" {
				dbEv["auth_plugin"] = greetingInfo.AuthPlugin
			}
			dbEv["connection_id"] = greetingInfo.ConnectionID
			dbEv["character_set"] = fmt.Sprintf("0x%02x", greetingInfo.CharacterSet)
			dbEv["capabilities"] = fmt.Sprintf("0x%08x", greetingInfo.Capabilities)
		}
		return []finding.Finding{
			makeF(
				finding.CheckPortDatabaseExposed,
				finding.SeverityHigh,
				fmt.Sprintf("%s database exposed on port %d", dbName, port),
				fmt.Sprintf("A %s database is directly accessible from the internet. "+
					"Databases should never be exposed publicly; this enables brute-force attacks and "+
					"exploitation of database-engine vulnerabilities.", dbName),
				dbEv,
			),
			makeF(
				finding.CheckPortMySQLNoAuth,
				finding.SeverityCritical,
				fmt.Sprintf("MySQL/MariaDB accepts root login with empty password on port %d", port),
				"The MySQL or MariaDB server accepts the root user with an empty password. "+
					"An attacker gains full database administrator access without any credentials: "+
					"SELECT * FROM all tables, read local files via LOAD DATA INFILE, and potentially "+
					"achieve RCE via SELECT INTO OUTFILE or UDF injection. "+
					"Set a strong root password immediately: ALTER USER 'root'@'%' IDENTIFIED BY '...'",
				noAuthEv,
			),
		}
	}
	// PostgreSQL: responds to SSLRequest or StartupMessage
	if probePostgreSQL(ctx, host, port) {
		dbName := "PostgreSQL"
		pgEv := map[string]any{
			"port": port, "service": dbName,
			"banner": banner,
		}
		trustEv := map[string]any{
			"port": port, "service": dbName,
			"user": "postgres", "auth_method": "trust",
			"auth_status": "no_auth",
		}
		return []finding.Finding{
			makeF(
				finding.CheckPortDatabaseExposed,
				finding.SeverityHigh,
				fmt.Sprintf("%s database exposed on port %d", dbName, port),
				fmt.Sprintf("A %s database is directly accessible from the internet. "+
					"Databases should never be exposed publicly; this enables brute-force attacks and "+
					"exploitation of database-engine vulnerabilities.", dbName),
				pgEv,
			),
			makeF(
				finding.CheckPortPostgreSQLTrust,
				finding.SeverityCritical,
				fmt.Sprintf("PostgreSQL trust authentication — connects as postgres without password on port %d", port),
				"PostgreSQL is configured with trust authentication for the postgres superuser from external addresses. "+
					"Any client can connect as postgres without a password, gaining superuser access to all databases. "+
					"Trust authentication exposes COPY TO/FROM PROGRAM (RCE), pg_read_file(), and all data. "+
					"Set pg_hba.conf to require 'scram-sha-256' or 'md5' for all remote connections.",
				trustEv,
			),
		}
	}
	// MSSQL: responds to TDS prelogin — enhanced with version/encryption extraction.
	if mssqlInfo := probeMSSQLPrelogin(ctx, host, port); mssqlInfo != nil {
		dbName := "Microsoft SQL Server"
		mssqlVersion := fmt.Sprintf("%d.%d.%d", mssqlInfo.MajorVersion, mssqlInfo.MinorVersion, mssqlInfo.BuildNumber)
		encryptionStr := "unknown"
		switch mssqlInfo.Encryption {
		case 0:
			encryptionStr = "off"
		case 1:
			encryptionStr = "on"
		case 2:
			encryptionStr = "not_supported"
		case 3:
			encryptionStr = "required"
		}
		mssqlEv := map[string]any{
			"port": port, "service": dbName, "banner": banner,
			"version": mssqlVersion, "encryption": encryptionStr,
		}
		if mssqlInfo.InstanceName != "" {
			mssqlEv["instance_name"] = mssqlInfo.InstanceName
		}
		var mssqlFindings []finding.Finding
		mssqlFindings = append(mssqlFindings, makeF(
			finding.CheckPortMSSQLExposed,
			finding.SeverityHigh,
			fmt.Sprintf("%s %s exposed on port %d (encryption: %s)", dbName, mssqlVersion, port, encryptionStr),
			fmt.Sprintf("A %s instance (version %s) is directly accessible from the internet. "+
				"TDS prelogin handshake succeeded, revealing server version and encryption setting (%s). "+
				"Databases should never be exposed publicly; this enables brute-force attacks and "+
				"exploitation of database-engine vulnerabilities.", dbName, mssqlVersion, encryptionStr),
			mssqlEv,
		))
		mssqlFindings = append(mssqlFindings, makeF(
			finding.CheckPortDatabaseExposed,
			finding.SeverityHigh,
			fmt.Sprintf("%s database exposed on port %d", dbName, port),
			fmt.Sprintf("A %s database is directly accessible from the internet. "+
				"Databases should never be exposed publicly; this enables brute-force attacks and "+
				"exploitation of database-engine vulnerabilities.", dbName),
			mssqlEv,
		))
		// Also try sa with empty password.
		if probeMSSQL(ctx, host, port) {
			mssqlFindings = append(mssqlFindings, makeF(
				finding.CheckPortMSSQLDefaultCreds,
				finding.SeverityCritical,
				fmt.Sprintf("MSSQL accepts sa login with empty password on port %d", port),
				"Microsoft SQL Server accepts the 'sa' (system administrator) login with a blank password. "+
					"The sa account has sysadmin privileges — an attacker can read/write all databases, "+
					"enable xp_cmdshell for OS command execution, and read Windows registry hives. "+
					"Disable the sa account or set a strong password: ALTER LOGIN sa WITH PASSWORD='...', ENABLE.",
				map[string]any{"port": port, "service": dbName, "user": "sa", "password": "(empty)",
					"version": mssqlVersion},
			))
		}
		return mssqlFindings
	} else if probeMSSQL(ctx, host, port) {
		// Fallback: prelogin parse failed but LOGIN7 succeeded.
		dbName := "Microsoft SQL Server"
		return []finding.Finding{
			makeF(
				finding.CheckPortDatabaseExposed,
				finding.SeverityHigh,
				fmt.Sprintf("%s database exposed on port %d", dbName, port),
				fmt.Sprintf("A %s database is directly accessible from the internet. "+
					"Databases should never be exposed publicly; this enables brute-force attacks and "+
					"exploitation of database-engine vulnerabilities.", dbName),
				map[string]any{"port": port, "service": dbName, "banner": banner},
			),
			makeF(
				finding.CheckPortMSSQLDefaultCreds,
				finding.SeverityCritical,
				fmt.Sprintf("MSSQL accepts sa login with empty password on port %d", port),
				"Microsoft SQL Server accepts the 'sa' (system administrator) login with a blank password. "+
					"The sa account has sysadmin privileges — an attacker can read/write all databases, "+
					"enable xp_cmdshell for OS command execution, and read Windows registry hives. "+
					"Disable the sa account or set a strong password: ALTER LOGIN sa WITH PASSWORD='...', ENABLE.",
				map[string]any{"port": port, "service": dbName, "user": "sa", "password": "(empty)"},
			),
		}
	}
	// Oracle TNS protocol probe.
	if probeOracleTNS(ctx, host, port) {
		dbName := "Oracle Database"
		return []finding.Finding{makeF(
			finding.CheckPortDatabaseExposed,
			finding.SeverityHigh,
			fmt.Sprintf("%s exposed on port %d", dbName, port),
			fmt.Sprintf("A %s listener is directly accessible from the internet. "+
				"Databases should never be exposed publicly; this enables brute-force attacks and "+
				"exploitation of database-engine vulnerabilities.", dbName),
			map[string]any{"port": port, "service": dbName, "banner": banner},
		)}
	}
	return nil
}

func detectMemcached(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	unauth := probeMemcached(ctx, host, port)
	if !unauth {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortMemcachedUnauth,
		finding.SeverityCritical,
		fmt.Sprintf("Unauthenticated Memcached exposed on port %d", port),
		"A Memcached instance is accessible without authentication. "+
			"Cache contents (which may include session tokens or PII) can be read or poisoned.",
		map[string]any{"port": port, "service": "memcached", "authenticated": false, "banner": banner},
	)}
}

func detectCouchDB(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	// Check unauthenticated access: /_all_dbs returns JSON array without credentials.
	body, ok := probeHTTPBody(ctx, host, port, false, "/_all_dbs")
	if ok && strings.HasPrefix(strings.TrimSpace(body), "[") {
		ev := map[string]any{"port": port, "service": "couchdb", "authenticated": false, "banner": banner}
		// Extract CouchDB version from root / JSON response ({"couchdb":"Welcome","version":"3.3.2"}).
		if rootBody, rootOk := probeHTTPBody(ctx, host, port, false, "/"); rootOk {
			if ver := parseJSONStringField(rootBody, "version"); ver != "" {
				ev["version"] = ver
			}
		}
		return []finding.Finding{makeF(
			finding.CheckPortCouchDBUnauth,
			finding.SeverityCritical,
			fmt.Sprintf("Unauthenticated CouchDB exposed on port %d", port),
			"A CouchDB instance is accessible without authentication. "+
				"All databases and their documents can be read, modified, or deleted.",
			ev,
		)}
	}
	// Fallback: CouchDB root / returns {"couchdb":"Welcome",...} even with auth enabled.
	rootBody, rootOk := probeHTTPBody(ctx, host, port, false, "/")
	if !rootOk {
		return nil
	}
	if !strings.Contains(rootBody, `"couchdb"`) {
		return nil
	}
	ev := map[string]any{"port": port, "service": "couchdb", "banner": banner}
	if ver := parseJSONStringField(rootBody, "version"); ver != "" {
		ev["version"] = ver
	}
	return []finding.Finding{makeF(
		finding.CheckPortDatabaseExposed,
		finding.SeverityHigh,
		fmt.Sprintf("CouchDB exposed on port %d", port),
		"A CouchDB database is publicly accessible. Although authentication may be configured, "+
			"the CouchDB service is reachable from the network and may be subject to brute-force or "+
			"exploitation of known CouchDB vulnerabilities. Restrict to trusted networks.",
		ev,
	)}
}

func detectInfluxDB(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	// InfluxDB /ping returns 204 No Content. If the response has HTML body content,
	// it's a SPA returning its shell, not InfluxDB.
	body, hdrs, ok := probeHTTPBodyAndHeaders(ctx, host, port, false, "/ping")
	if !ok {
		return nil
	}
	trimmed := strings.TrimSpace(body)
	if strings.HasPrefix(trimmed, "<") || strings.HasPrefix(trimmed, "<!") {
		return nil // HTML response — not InfluxDB
	}
	ev := map[string]any{"port": port, "service": "influxdb", "authenticated": false, "banner": banner}
	// Extract InfluxDB version from X-Influxdb-Version header (returned on /ping).
	if ver := hdrs.Get("X-Influxdb-Version"); ver != "" {
		ev["version"] = ver
	} else if ver := hdrs.Get("X-Influxdb-Build"); ver != "" {
		ev["version"] = ver
	}
	return []finding.Finding{makeF(
		finding.CheckPortInfluxDBExposed,
		finding.SeverityHigh,
		fmt.Sprintf("InfluxDB exposed on port %d", port),
		"An InfluxDB time-series database is publicly accessible. Without authentication, "+
			"all stored metrics data can be read, modified, or deleted.",
		ev,
	)}
}

func detectCassandra(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	// Enhanced CQL probe: parse OPTIONS response for versions, compression, and auth status.
	cqlInfo := probeCassandraCQLInfo(ctx, host, port)
	if cqlInfo == nil {
		// Fallback to basic probe.
		if !probeCassandraCQL(ctx, host, port) {
			return nil
		}
		return []finding.Finding{makeF(
			finding.CheckPortDatabaseExposed,
			finding.SeverityHigh,
			fmt.Sprintf("Apache Cassandra exposed on port %d", port),
			"An Apache Cassandra database is publicly accessible on its native CQL port. "+
				"Cassandra without authentication allows full read/write access to all keyspaces and tables.",
			map[string]any{"port": port, "service": "cassandra", "banner": banner},
		)}
	}

	ev := map[string]any{
		"port": port, "service": "cassandra", "banner": banner,
	}
	if len(cqlInfo.CQLVersions) > 0 {
		ev["cql_versions"] = strings.Join(cqlInfo.CQLVersions, ", ")
	}
	if len(cqlInfo.Compression) > 0 {
		ev["compression"] = strings.Join(cqlInfo.Compression, ", ")
	}

	var findings []finding.Finding
	if cqlInfo.NoAuth {
		ev["auth_status"] = "no_auth"
		ev["authenticator"] = "AllowAllAuthenticator"
		findings = append(findings, makeF(
			finding.CheckPortCassandraNoAuth,
			finding.SeverityCritical,
			fmt.Sprintf("Apache Cassandra on port %d accepts connections without authentication (AllowAllAuthenticator)", port),
			"The Cassandra cluster uses AllowAllAuthenticator — any client can connect without credentials and "+
				"read, write, or delete all data in every keyspace. An attacker has full DBA access. "+
				"Configure PasswordAuthenticator in cassandra.yaml and require credentials for all clients.",
			ev,
		))
	}
	findings = append(findings, makeF(
		finding.CheckPortCassandraExposed,
		finding.SeverityCritical,
		fmt.Sprintf("Apache Cassandra CQL exposed on port %d", port),
		"An Apache Cassandra database is publicly accessible on its native CQL port. "+
			"Cassandra without authentication allows full read/write access to all keyspaces and tables.",
		ev,
	))
	return findings
}

func detectNeo4j(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	body, ok := probeHTTPBody(ctx, host, port, false, "/")
	if !ok {
		return nil
	}
	lb := strings.ToLower(body)
	if !strings.Contains(lb, "neo4j") && (!strings.Contains(lb, "bolt") || !strings.Contains(lb, "transaction")) {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortNeo4jExposed,
		finding.SeverityHigh,
		fmt.Sprintf("Neo4j graph database HTTP API exposed without authentication on port %d", port),
		"A Neo4j graph database REST API is accessible without authentication on port 7474. "+
			"Unauthenticated access allows full read/write of all graph data. "+
			"Enable authentication in neo4j.conf (dbms.security.auth_enabled=true) and "+
			"restrict port 7474 to application server subnets only.",
		map[string]any{"port": port, "service": "neo4j"},
	)}
}

func detectSplunkMgmt(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	// Splunk /services/server/info returns XML with <entry> elements and "server-info".
	body, ok := probeHTTPBody(ctx, host, port, true, "/services/server/info")
	if !ok {
		return nil
	}
	bodyLow := strings.ToLower(body)
	if !strings.Contains(bodyLow, "server-info") && !strings.Contains(bodyLow, "splunk") {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortSplunkMgmtExposed,
		finding.SeverityHigh,
		fmt.Sprintf("Splunk management API exposed on port %d", port),
		"The Splunk management REST API is publicly accessible. This port provides administrative "+
			"access to all Splunk configuration, search capabilities, and log data.",
		map[string]any{"port": port, "service": "splunk", "authenticated": false, "banner": banner},
	)}
}
