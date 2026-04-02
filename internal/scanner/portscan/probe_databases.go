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
	var esFindings []finding.Finding
	esFindings = append(esFindings, makeF(
		finding.CheckPortElasticsearchUnauth,
		finding.SeverityCritical,
		fmt.Sprintf("%s exposed on port %d", serviceLabel, port),
		description,
		map[string]any{"port": port, "service": serviceName, "authenticated": false, "banner": banner},
	))
	// CVE-2015-1427: Elasticsearch ≤ 1.5.x Groovy sandbox escape → unauthenticated RCE.
	if esVer := parseJSONStringField(body, "number"); serviceName == "Elasticsearch" && isElasticsearchGroovyVulnerable(esVer) {
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
	return []finding.Finding{makeF(
		finding.CheckPortDatabaseExposed,
		finding.SeverityCritical,
		fmt.Sprintf("Unauthenticated MongoDB exposed on port %d", port),
		"A MongoDB instance is accepting connections without authentication. "+
			"All collections and documents are readable and writable by any network client.",
		map[string]any{"port": port, "service": "mongodb", "authenticated": false, "banner": banner},
	)}
}

func detectRelationalDB(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	// Try each database protocol probe — detect by wire protocol, not port number.
	// MySQL: greeting packet starts with protocol version 0x0a/0x09
	if probeMySQL(ctx, host, port) {
		dbName := "MySQL"
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
				finding.CheckPortMySQLNoAuth,
				finding.SeverityCritical,
				fmt.Sprintf("MySQL/MariaDB accepts root login with empty password on port %d", port),
				"The MySQL or MariaDB server accepts the root user with an empty password. "+
					"An attacker gains full database administrator access without any credentials: "+
					"SELECT * FROM all tables, read local files via LOAD DATA INFILE, and potentially "+
					"achieve RCE via SELECT INTO OUTFILE or UDF injection. "+
					"Set a strong root password immediately: ALTER USER 'root'@'%' IDENTIFIED BY '...'",
				map[string]any{"port": port, "service": dbName, "user": "root", "password": "(empty)"},
			),
		}
	}
	// PostgreSQL: responds to SSLRequest or StartupMessage
	if probePostgreSQL(ctx, host, port) {
		dbName := "PostgreSQL"
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
				finding.CheckPortPostgreSQLTrust,
				finding.SeverityCritical,
				fmt.Sprintf("PostgreSQL trust authentication — connects as postgres without password on port %d", port),
				"PostgreSQL is configured with trust authentication for the postgres superuser from external addresses. "+
					"Any client can connect as postgres without a password, gaining superuser access to all databases. "+
					"Trust authentication exposes COPY TO/FROM PROGRAM (RCE), pg_read_file(), and all data. "+
					"Set pg_hba.conf to require 'scram-sha-256' or 'md5' for all remote connections.",
				map[string]any{"port": port, "service": dbName, "user": "postgres", "auth_method": "trust"},
			),
		}
	}
	// MSSQL: responds to TDS prelogin
	if probeMSSQL(ctx, host, port) {
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
	unauth := probeHTTP(ctx, host, port, false, "/_all_dbs")
	if !unauth {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortCouchDBUnauth,
		finding.SeverityCritical,
		fmt.Sprintf("Unauthenticated CouchDB exposed on port %d", port),
		"A CouchDB instance is accessible without authentication. "+
			"All databases and their documents can be read, modified, or deleted.",
		map[string]any{"port": port, "service": "couchdb", "authenticated": false, "banner": banner},
	)}
}

func detectInfluxDB(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	unauth := probeHTTP(ctx, host, port, false, "/ping")
	if !unauth {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortInfluxDBExposed,
		finding.SeverityHigh,
		fmt.Sprintf("InfluxDB exposed on port %d", port),
		"An InfluxDB time-series database is publicly accessible. Without authentication, "+
			"all stored metrics data can be read, modified, or deleted.",
		map[string]any{"port": port, "service": "influxdb", "authenticated": false, "banner": banner},
	)}
}

func detectCassandra(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
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

func detectNeo4j(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	body, ok := probeHTTPBody(ctx, host, port, false, "/")
	if !ok {
		return nil
	}
	lb := strings.ToLower(body)
	if !strings.Contains(lb, "neo4j") && !(strings.Contains(lb, "bolt") && strings.Contains(lb, "transaction")) {
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
	unauth := probeHTTP(ctx, host, port, true, "/services/server/info")
	if !unauth {
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
