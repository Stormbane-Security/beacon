package infra

// Databases, caches, search engines, and message brokers.

const (
	PostgreSQL    Technology = "postgresql"
	MySQL         Technology = "mysql"
	MariaDB       Technology = "mariadb"
	SQLServer     Technology = "mssql"
	Oracle        Technology = "oracle-db"
	SQLite        Technology = "sqlite"
	MongoDB       Technology = "mongodb"
	CouchDB       Technology = "couchdb"
	Redis         Technology = "redis"
	Memcached     Technology = "memcached"
	Elasticsearch Technology = "elasticsearch"
	OpenSearch    Technology = "opensearch"
	Cassandra     Technology = "cassandra"
	CockroachDB   Technology = "cockroachdb"
	InfluxDB      Technology = "influxdb"
	Neo4j         Technology = "neo4j"
	Kafka         Technology = "kafka"
	RabbitMQ      Technology = "rabbitmq"
	NATS          Technology = "nats"
	ZooKeeper     Technology = "zookeeper"
)

func init() {
	// ── Relational Databases ──
	for _, m := range []*TechMeta{
		{ID: PostgreSQL, Name: "PostgreSQL", Category: CategoryDatabase, OpenSource: true, Vendor: "PostgreSQL Global Development Group", DefaultPorts: []int{5432}, DockerImage: "postgres:16-alpine", Aliases: []string{"postgres", "pg"}},
		{ID: MySQL, Name: "MySQL", Category: CategoryDatabase, OpenSource: true, Vendor: "Oracle", DefaultPorts: []int{3306}, DockerImage: "mysql:8"},
		{ID: MariaDB, Name: "MariaDB", Category: CategoryDatabase, OpenSource: true, Vendor: "MariaDB Foundation", DefaultPorts: []int{3306}, DockerImage: "mariadb:11"},
		{ID: SQLServer, Name: "Microsoft SQL Server", Category: CategoryDatabase, Vendor: "Microsoft", DefaultPorts: []int{1433}, Aliases: []string{"sqlserver"}},
		{ID: Oracle, Name: "Oracle Database", Category: CategoryDatabase, Vendor: "Oracle", DefaultPorts: []int{1521}},
		{ID: CockroachDB, Name: "CockroachDB", Category: CategoryDatabase, OpenSource: true, Vendor: "Cockroach Labs", DefaultPorts: []int{26257, 8080}, DockerImage: "cockroachdb/cockroach:latest"},
	} {
		Register(m)
	}

	// ── NoSQL / Document Databases ──
	for _, m := range []*TechMeta{
		{ID: MongoDB, Name: "MongoDB", Category: CategoryDatabase, OpenSource: true, Vendor: "MongoDB Inc", DefaultPorts: []int{27017}, DockerImage: "mongo:7", Tags: []string{"nosql"}},
		{ID: CouchDB, Name: "CouchDB", Category: CategoryDatabase, OpenSource: true, Vendor: "Apache Software Foundation", DefaultPorts: []int{5984}, DockerImage: "couchdb:latest", Tags: []string{"nosql"}},
		{ID: Cassandra, Name: "Apache Cassandra", Category: CategoryDatabase, OpenSource: true, Vendor: "Apache Software Foundation", DefaultPorts: []int{9042}, DockerImage: "cassandra:latest", Tags: []string{"nosql"}},
	} {
		Register(m)
	}

	// ── Cache / In-Memory ──
	for _, m := range []*TechMeta{
		{ID: Redis, Name: "Redis", Category: CategoryDatabase, OpenSource: true, Vendor: "Redis Ltd", DefaultPorts: []int{6379}, DockerImage: "redis:7-alpine", Tags: []string{"cache"}},
		{ID: Memcached, Name: "Memcached", Category: CategoryDatabase, OpenSource: true, Vendor: "Memcached", DefaultPorts: []int{11211}, DockerImage: "memcached:alpine", Tags: []string{"cache"}},
	} {
		Register(m)
	}

	// ── Search Engines ──
	for _, m := range []*TechMeta{
		{ID: Elasticsearch, Name: "Elasticsearch", Category: CategoryDatabase, OpenSource: true, Vendor: "Elastic", DefaultPorts: []int{9200, 9300}, DockerImage: "elasticsearch:8.14.0", Tags: []string{"search"}, Aliases: []string{"elastic"}},
		{ID: OpenSearch, Name: "OpenSearch", Category: CategoryDatabase, OpenSource: true, Vendor: "Amazon/OpenSearch", DefaultPorts: []int{9200}, DockerImage: "opensearchproject/opensearch:latest", Tags: []string{"search"}},
	} {
		Register(m)
	}

	// ── Time Series ──
	for _, m := range []*TechMeta{
		{ID: InfluxDB, Name: "InfluxDB", Category: CategoryDatabase, OpenSource: true, Vendor: "InfluxData", DefaultPorts: []int{8086}, DockerImage: "influxdb:latest", Tags: []string{"timeseries"}},
	} {
		Register(m)
	}

	// ── Graph Databases ──
	for _, m := range []*TechMeta{
		{ID: Neo4j, Name: "Neo4j", Category: CategoryDatabase, OpenSource: true, Vendor: "Neo4j Inc", DefaultPorts: []int{7474, 7687}, DockerImage: "neo4j:latest", Tags: []string{"graph"}},
	} {
		Register(m)
	}

	// ── Message Brokers & Streaming ──
	for _, m := range []*TechMeta{
		{ID: Kafka, Name: "Apache Kafka", Category: CategoryMessaging, OpenSource: true, Vendor: "Apache Software Foundation", DefaultPorts: []int{9092}, DockerImage: "confluentinc/cp-kafka:latest", Tags: []string{"streaming"}},
		{ID: RabbitMQ, Name: "RabbitMQ", Category: CategoryMessaging, OpenSource: true, Vendor: "VMware/Broadcom", DefaultPorts: []int{5672, 15672}, DockerImage: "rabbitmq:3-management-alpine", Tags: []string{"queue"}, Aliases: []string{"amqp"}},
		{ID: NATS, Name: "NATS", Category: CategoryMessaging, OpenSource: true, Vendor: "Synadia", DefaultPorts: []int{4222}, DockerImage: "nats:alpine", Tags: []string{"pubsub"}},
		{ID: ZooKeeper, Name: "Apache ZooKeeper", Category: CategoryMessaging, OpenSource: true, Vendor: "Apache Software Foundation", DefaultPorts: []int{2181}, DockerImage: "zookeeper:latest"},
	} {
		Register(m)
	}
}
