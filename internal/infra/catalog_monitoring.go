package infra

// Observability: metrics, logging, tracing, and APM.

const (
	Prometheus    Technology = "prometheus"
	Grafana       Technology = "grafana"
	Datadog       Technology = "datadog"
	Splunk        Technology = "splunk"
	NewRelic      Technology = "newrelic"
	PagerDuty     Technology = "pagerduty"
	OpsGenie      Technology = "opsgenie"
	Jaeger        Technology = "jaeger"
	Zipkin        Technology = "zipkin"
	OpenTelemetry Technology = "opentelemetry"
	Loki          Technology = "loki"
	Tempo         Technology = "tempo"
	Mimir         Technology = "mimir"
	Thanos        Technology = "thanos"
	VictoriaMetrics Technology = "victoriametrics"
	Sentry        Technology = "sentry"
	ELKStack      Technology = "elk"
	Fluentd       Technology = "fluentd"
	FluentBit     Technology = "fluent-bit"
	Logstash      Technology = "logstash"
	Kibana        Technology = "kibana"
	Nagios        Technology = "nagios"
	Zabbix        Technology = "zabbix"
)

func init() {
	// ── Metrics & Monitoring ──
	for _, m := range []*TechMeta{
		{ID: Prometheus, Name: "Prometheus", Category: CategoryMonitoring, OpenSource: true, Vendor: "CNCF", DefaultPorts: []int{9090}, DockerImage: "prom/prometheus:latest", Tags: []string{"metrics"}},
		{ID: Grafana, Name: "Grafana", Category: CategoryMonitoring, OpenSource: true, Vendor: "Grafana Labs", DefaultPorts: []int{3000}, DockerImage: "grafana/grafana:latest", Tags: []string{"dashboards"}},
		{ID: Datadog, Name: "Datadog", Category: CategoryMonitoring, Vendor: "Datadog", Tags: []string{"apm", "metrics", "logs"}},
		{ID: Splunk, Name: "Splunk", Category: CategoryMonitoring, Vendor: "Cisco/Splunk", DefaultPorts: []int{8000, 8089, 9997}, Tags: []string{"siem", "logs"}},
		{ID: NewRelic, Name: "New Relic", Category: CategoryMonitoring, Vendor: "New Relic", Tags: []string{"apm"}},
		{ID: VictoriaMetrics, Name: "VictoriaMetrics", Category: CategoryMonitoring, OpenSource: true, Vendor: "VictoriaMetrics", DefaultPorts: []int{8428}, DockerImage: "victoriametrics/victoria-metrics:latest", Tags: []string{"metrics", "tsdb"}},
		{ID: Thanos, Name: "Thanos", Category: CategoryMonitoring, OpenSource: true, Vendor: "CNCF", Tags: []string{"metrics"}},
		{ID: Mimir, Name: "Grafana Mimir", Category: CategoryMonitoring, OpenSource: true, Vendor: "Grafana Labs", Tags: []string{"metrics"}},
		{ID: Nagios, Name: "Nagios", Category: CategoryMonitoring, OpenSource: true, Vendor: "Nagios Enterprises", DefaultPorts: []int{5666}, Tags: []string{"infra-monitoring"}},
		{ID: Zabbix, Name: "Zabbix", Category: CategoryMonitoring, OpenSource: true, Vendor: "Zabbix", DefaultPorts: []int{10050, 10051}, DockerImage: "zabbix/zabbix-server-pgsql:latest", Tags: []string{"infra-monitoring"}},
	} {
		Register(m)
	}

	// ── Tracing & APM ──
	for _, m := range []*TechMeta{
		{ID: Jaeger, Name: "Jaeger", Category: CategoryMonitoring, OpenSource: true, Vendor: "CNCF/Uber", DefaultPorts: []int{16686, 14268}, DockerImage: "jaegertracing/all-in-one:latest", Tags: []string{"tracing"}},
		{ID: Zipkin, Name: "Zipkin", Category: CategoryMonitoring, OpenSource: true, Vendor: "OpenZipkin", DefaultPorts: []int{9411}, DockerImage: "openzipkin/zipkin:latest", Tags: []string{"tracing"}},
		{ID: OpenTelemetry, Name: "OpenTelemetry", Category: CategoryMonitoring, OpenSource: true, Vendor: "CNCF", Tags: []string{"tracing", "metrics", "logs"}, Aliases: []string{"otel"}},
		{ID: Sentry, Name: "Sentry", Category: CategoryMonitoring, OpenSource: true, Vendor: "Sentry", Tags: []string{"errors", "apm"}},
	} {
		Register(m)
	}

	// ── Logging ──
	for _, m := range []*TechMeta{
		{ID: Loki, Name: "Grafana Loki", Category: CategoryMonitoring, OpenSource: true, Vendor: "Grafana Labs", DefaultPorts: []int{3100}, DockerImage: "grafana/loki:latest", Tags: []string{"logs"}},
		{ID: ELKStack, Name: "ELK Stack", Category: CategoryMonitoring, OpenSource: true, Vendor: "Elastic", Tags: []string{"logs", "search"}, Aliases: []string{"elastic-stack"}},
		{ID: Fluentd, Name: "Fluentd", Category: CategoryMonitoring, OpenSource: true, Vendor: "CNCF/Treasure Data", Tags: []string{"logs"}, Aliases: []string{"td-agent"}},
		{ID: FluentBit, Name: "Fluent Bit", Category: CategoryMonitoring, OpenSource: true, Vendor: "CNCF/Calyptia", Tags: []string{"logs"}},
		{ID: Logstash, Name: "Logstash", Category: CategoryMonitoring, OpenSource: true, Vendor: "Elastic", DefaultPorts: []int{5044, 9600}, Tags: []string{"logs"}},
		{ID: Kibana, Name: "Kibana", Category: CategoryMonitoring, OpenSource: true, Vendor: "Elastic", DefaultPorts: []int{5601}, Tags: []string{"dashboards", "logs"}},
	} {
		Register(m)
	}

	// ── Incident Management ──
	for _, m := range []*TechMeta{
		{ID: PagerDuty, Name: "PagerDuty", Category: CategoryMonitoring, Vendor: "PagerDuty", Tags: []string{"incident"}},
		{ID: OpsGenie, Name: "OpsGenie", Category: CategoryMonitoring, Vendor: "Atlassian", Tags: []string{"incident"}},
	} {
		Register(m)
	}

	// ── Tracing Backend ──
	for _, m := range []*TechMeta{
		{ID: Tempo, Name: "Grafana Tempo", Category: CategoryMonitoring, OpenSource: true, Vendor: "Grafana Labs", Tags: []string{"tracing"}},
	} {
		Register(m)
	}
}
