// Package infra provides a shared taxonomy of infrastructure technologies,
// platforms, services, and frameworks. It is imported by both Beacon
// (for fingerprinting and classification) and Drydock (for scenario
// definitions and test infrastructure provisioning).
//
// This package contains NO business logic — only type definitions, constants,
// and metadata. It is intentionally lightweight with zero dependencies.
//
// Categories:
//
//   - Platform:   where workloads run (GKE, EKS, EC2, Cloud Run, Docker, bare-metal)
//   - Server:     HTTP servers and reverse proxies (nginx, Apache, Caddy, Envoy)
//   - Framework:  application frameworks (Next.js, Rails, Django, Spring)
//   - Database:   data stores (PostgreSQL, MySQL, Redis, Elasticsearch, DynamoDB)
//   - Auth:       authentication systems (Okta, Auth0, Keycloak, Cognito, SAML)
//   - Cloud:      cloud providers and their managed services
//   - CICD:       CI/CD platforms and their components
//   - Messaging:  message brokers and event systems (Kafka, RabbitMQ, SQS, Pub/Sub)
//   - Monitoring: observability tools (Prometheus, Grafana, Datadog, Splunk)
//   - CDN:        content delivery networks (Cloudflare, Fastly, Akamai, CloudFront)
package infra
