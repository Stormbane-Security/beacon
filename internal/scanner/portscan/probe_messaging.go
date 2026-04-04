package portscan

import (
	"context"
	"fmt"
	"strings"

	"github.com/stormbane-security/beacon/internal/finding"
)

func init() {
	registerProbe(ServiceProbe{
		Name:         "rabbitmq-amqp",
		Category:     ProbeCatProtocol,
		DefaultPorts: []int{5672},
		Detect:       detectRabbitMQAMQP,
	})
	registerProbe(ServiceProbe{
		Name:         "rabbitmq-mgmt",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{15672},
		Detect:       detectRabbitMQMgmt,
	})
	registerProbe(ServiceProbe{
		Name:         "kafka",
		Category:     ProbeCatProtocol,
		DefaultPorts: []int{9092},
		Detect:       detectKafka,
	})
	registerProbe(ServiceProbe{
		Name:         "nats-monitoring",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{8222},
		Detect:       detectNATSMonitoring,
	})
	registerProbe(ServiceProbe{
		Name:         "activemq",
		Category:     ProbeCatBanner,
		DefaultPorts: []int{61616},
		Detect:       detectActiveMQ,
	})
	registerProbe(ServiceProbe{
		Name:         "mqtt",
		Category:     ProbeCatProtocol,
		DefaultPorts: []int{1883, 8883},
		Detect:       detectMQTT,
	})
	registerProbe(ServiceProbe{
		Name:         "zookeeper",
		Category:     ProbeCatProtocol,
		DefaultPorts: []int{2181},
		Detect:       detectZooKeeper,
	})
	registerProbe(ServiceProbe{
		Name:         "pulsar-admin",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{8080},
		Detect:       detectPulsarAdmin,
	})
	registerProbe(ServiceProbe{
		Name:         "nifi",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{8080},
		Detect:       detectNiFi,
	})
	registerProbe(ServiceProbe{
		Name:         "asterisk-ami",
		Category:     ProbeCatBanner,
		DefaultPorts: []int{5038},
		Detect:       detectAsteriskAMI,
	})
}

func detectRabbitMQAMQP(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	if !probeAMQP(ctx, host, port) {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortAMQPExposed,
		finding.SeverityHigh,
		fmt.Sprintf("AMQP (RabbitMQ) exposed on port %d", port),
		"An AMQP message broker (commonly RabbitMQ) is publicly accessible. "+
			"AMQP brokers often have no authentication by default and may expose "+
			"application messages, task queues, and internal service communication.",
		map[string]any{"port": port, "service": "rabbitmq", "banner": banner},
	)}
}

func detectRabbitMQMgmt(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	if body, ok := probeHTTPBody(ctx, host, port, false, "/"); ok {
		bodyLow := strings.ToLower(body)
		if strings.Contains(bodyLow, "rabbitmq") {
			ev := map[string]any{"port": port, "service": "rabbitmq-mgmt"}
			return []finding.Finding{makeF(
				finding.CheckPortRabbitMQMgmtExposed,
				finding.SeverityHigh,
				fmt.Sprintf("RabbitMQ management API exposed on port %d", port),
				"The RabbitMQ management UI and REST API are publicly accessible. "+
					"The management API provides full control over virtual hosts, exchanges, "+
					"queues, bindings, and user accounts. Default credentials (guest:guest) "+
					"are disabled on non-localhost connections in recent versions but older "+
					"deployments may still accept them. Restrict to trusted networks.",
				ev,
			)}
		}
	}
	// Test for default guest:guest credentials on the RabbitMQ management API.
	if body, ok := probeHTTPBodyWithAuth(ctx, host, port, false, "/api/overview", "guest", "guest"); ok {
		bodyLow := strings.ToLower(body)
		if strings.Contains(bodyLow, "rabbitmq_version") || strings.Contains(bodyLow, "cluster_name") {
			return []finding.Finding{makeF(
				finding.CheckPortRabbitMQDefaultCreds,
				finding.SeverityCritical,
				fmt.Sprintf("RabbitMQ accepts default guest:guest credentials on port %d", port),
				"The RabbitMQ management API accepts the factory-default credentials guest:guest. "+
					"An attacker can read all messages in transit, publish arbitrary messages, delete queues, "+
					"reconfigure exchanges and virtual hosts, and manage user accounts. "+
					"Delete the guest account and create named service accounts with minimal permissions.",
				map[string]any{"port": port, "service": "rabbitmq-mgmt", "creds": "guest:guest", "authenticated": true},
			)}
		}
	}
	return nil
}

func detectKafka(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	if !probeKafka(ctx, host, port) {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortKafkaExposed,
		finding.SeverityHigh,
		fmt.Sprintf("Apache Kafka broker exposed on port %d", port),
		"An Apache Kafka broker is publicly accessible. Kafka without authentication "+
			"allows anyone to read, write, or delete messages from any topic — potentially "+
			"exposing event streams containing sensitive application data.",
		map[string]any{"port": port, "service": "kafka", "banner": banner},
	)}
}

func detectNATSMonitoring(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	body, ok := probeHTTPBody(ctx, host, port, false, "/varz")
	if !ok {
		return nil
	}
	ev := map[string]any{"port": port, "service": "nats"}
	if ver := parseJSONStringField(body, "version"); ver != "" {
		ev["nats_version"] = ver
	}
	if !strings.Contains(body, "server_id") && !strings.Contains(body, "nats") {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortNATSMonitoringExposed,
		finding.SeverityHigh,
		fmt.Sprintf("NATS message broker monitoring API exposed on port %d", port),
		"The NATS server monitoring endpoint (/varz) is publicly accessible. "+
			"This exposes server configuration, connection counts, subscription counts, "+
			"and routing topology. Multiple NATS CVEs involve authentication bypass: "+
			"CVE-2023-47090 (system account bypass), CVE-2022-24450 (authorization bypass), "+
			"CVE-2026-27889 (pre-auth crash via WebSocket). "+
			"Restrict the monitoring port to trusted networks.",
		ev,
	)}
}

func detectActiveMQ(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	if !strings.Contains(banner, "ActiveMQ") && !strings.Contains(banner, "activemq") {
		return nil
	}
	vuln, verStr := isActiveMQRCE2023Vulnerable(banner)
	if vuln {
		return []finding.Finding{makeF(
			finding.CheckCVEActiveMQRCE,
			finding.SeverityCritical,
			fmt.Sprintf("CVE-2023-46604: Apache ActiveMQ %s vulnerable to pre-auth RCE on port %d", verStr, port),
			fmt.Sprintf("Apache ActiveMQ %s is internet-accessible and vulnerable to CVE-2023-46604 "+
				"(CVSS 10.0, KEV). The ClassInfo deserialization vulnerability in the OpenWire "+
				"protocol allows an unauthenticated remote attacker to execute arbitrary code. "+
				"Exploited by HelloKitty ransomware and multiple APT groups. "+
				"Upgrade to ActiveMQ 5.15.16+, 5.16.7+, 5.17.6+, or 5.18.3+ immediately. "+
				"Restrict port 61616 to internal broker networks only.", verStr),
			map[string]any{"port": port, "service": "activemq", "banner": banner, "version": verStr},
		)}
	}
	// ActiveMQ detected but version not determined or not vulnerable — still report exposure.
	return []finding.Finding{makeF(
		finding.CheckPortActiveMQExposed,
		finding.SeverityHigh,
		fmt.Sprintf("Apache ActiveMQ broker exposed on port %d", port),
		"An Apache ActiveMQ message broker is publicly accessible. The OpenWire protocol "+
			"(port 61616) is the primary broker protocol and should be restricted to "+
			"trusted application networks. Multiple critical CVEs affect ActiveMQ brokers "+
			"including CVE-2023-46604 (CVSS 10.0, RCE). Verify the version and patch level, "+
			"and restrict port 61616 to internal networks immediately.",
		map[string]any{"port": port, "service": "activemq", "banner": banner},
	)}
}

func detectMQTT(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	tlsFlag := port == 8883
	if isMQTT := probeMQTT(ctx, host, port, tlsFlag); !isMQTT {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortMQTTExposed,
		finding.SeverityHigh,
		fmt.Sprintf("MQTT broker exposed on port %d", port),
		"An MQTT message broker is publicly accessible. MQTT brokers used in IoT deployments "+
			"often lack authentication (no username/password required). "+
			"An unauthenticated MQTT broker allows anyone to subscribe to all topics, "+
			"intercept device telemetry, and publish commands to connected devices. "+
			"Restrict access with IP allowlisting and enforce TLS + username/password authentication.",
		map[string]any{"port": port, "service": "mqtt", "banner": banner},
	)}
}

func detectZooKeeper(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	if !probeZooKeeper(ctx, host, port) {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortZooKeeperExposed,
		finding.SeverityHigh,
		fmt.Sprintf("Apache ZooKeeper exposed on port %d", port),
		"Apache ZooKeeper is publicly accessible. ZooKeeper stores distributed configuration "+
			"and coordination data for services like Kafka, HBase, and Hadoop. Unauthenticated access "+
			"allows reading and modifying cluster configuration, enabling service disruption or data extraction.",
		map[string]any{"port": port, "service": "zookeeper", "banner": banner},
	)}
}

func detectPulsarAdmin(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	body, ok := probeHTTPBody(ctx, host, port, false, "/admin/v2/clusters")
	if !ok {
		return nil
	}
	bodyLow := strings.ToLower(body)
	if !strings.Contains(bodyLow, "standalone") && !strings.Contains(bodyLow, "pulsar") &&
		!(strings.HasPrefix(strings.TrimSpace(body), "[") && strings.Contains(body, `"`)) {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortPulsarAdminExposed,
		finding.SeverityHigh,
		fmt.Sprintf("Apache Pulsar admin API exposed unauthenticated on port %d", port),
		"The Apache Pulsar broker admin REST API at /admin/v2/clusters is accessible without "+
			"authentication. The Pulsar admin API provides full control over the messaging cluster: "+
			"creating and deleting topics and namespaces, managing subscriptions, offloading data, "+
			"and reading broker configuration. Unauthenticated access can expose all topic data "+
			"and allow a attacker to drain, corrupt, or delete message queues. "+
			"Enable Pulsar authentication (JWT or TLS mutual auth) and restrict the admin port "+
			"to trusted management networks.",
		map[string]any{"port": port, "service": "pulsar",
			"url": fmt.Sprintf("http://%s:%d/admin/v2/clusters", host, port)},
	)}
}

func detectNiFi(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	body, ok := probeHTTPBody(ctx, host, port, false, "/nifi/")
	if !ok {
		return nil
	}
	bodyLow := strings.ToLower(body)
	if !strings.Contains(bodyLow, "nifi") && !strings.Contains(bodyLow, "apache nifi") {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortNiFiExposed,
		finding.SeverityHigh,
		fmt.Sprintf("Apache NiFi data pipeline UI accessible on port %d", port),
		"An Apache NiFi data pipeline instance is publicly accessible. "+
			"NiFi provides a web-based interface for designing, controlling, and monitoring data flows. "+
			"Unauthenticated access (or default credentials) allows full control over data routing, "+
			"reading all data in transit, modifying processor configurations, and connecting "+
			"to internal data sources. Enable NiFi authentication and restrict to trusted networks.",
		map[string]any{"port": port, "service": "nifi",
			"url": fmt.Sprintf("http://%s:%d/nifi/", host, port)},
	)}
}

func detectAsteriskAMI(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	ev := map[string]any{"port": port, "service": "asterisk-ami"}
	if !strings.Contains(banner, "Asterisk") && !strings.Contains(banner, "Call Manager") {
		return nil
	}
	ev["banner"] = banner
	return []finding.Finding{makeF(
		finding.CheckPortAsteriskAMIExposed,
		finding.SeverityHigh,
		"Asterisk Manager Interface (AMI) exposed",
		"The Asterisk PBX Manager Interface is internet-accessible. AMI is a plaintext "+
			"administrative API that provides control over calls, channels, queues, and the Asterisk "+
			"dialplan. Without authentication or with weak credentials it enables eavesdropping, "+
			"call hijacking, and toll fraud. AMI should never be internet-facing.",
		ev,
	)}
}
