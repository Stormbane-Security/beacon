package aws

import (
	"context"
	"fmt"
	"strings"
	"time"

	awscfg "github.com/aws/aws-sdk-go-v2/aws"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"

	"github.com/stormbane/beacon/internal/finding"
)

func scanELB(ctx context.Context, cfg awscfg.Config, accountID, region, asset string) ([]finding.Finding, error) {
	svc := elbv2.NewFromConfig(cfg)
	var findings []finding.Finding

	// Paginate through all load balancers.
	var marker *string
	for {
		input := &elbv2.DescribeLoadBalancersInput{Marker: marker}
		resp, err := svc.DescribeLoadBalancers(ctx, input)
		if err != nil {
			if len(findings) == 0 {
				return nil, fmt.Errorf("describe load balancers: %w", err)
			}
			break
		}

		for _, lb := range resp.LoadBalancers {
			lbName := awscfg.ToString(lb.LoadBalancerName)
			lbArn := awscfg.ToString(lb.LoadBalancerArn)
			lbType := string(lb.Type)

			evidence := map[string]any{
				"account_id":    accountID,
				"lb_name":       lbName,
				"lb_arn":        lbArn,
				"region":        region,
				"resource_type": "load_balancer",
				"lb_type":       lbType,
			}

			// Fetch listeners for this load balancer.
			listeners, listErr := svc.DescribeListeners(ctx, &elbv2.DescribeListenersInput{
				LoadBalancerArn: lb.LoadBalancerArn,
			})
			if listErr == nil {
				hasHTTP := false
				hasHTTPS := false
				for _, l := range listeners.Listeners {
					port := awscfg.ToInt32(l.Port)
					if port == 80 {
						hasHTTP = true
					}
					if port == 443 {
						hasHTTPS = true
					}
				}

				// Check 1: HTTP listener without corresponding HTTPS listener.
				if hasHTTP && !hasHTTPS {
					ev := copyEvidence(evidence)
					findings = append(findings, finding.Finding{
						CheckID: finding.CheckCloudAWSELBNoHTTPS,
						Title:   fmt.Sprintf("Load balancer has HTTP listener without HTTPS: %s", lbName),
						Description: fmt.Sprintf(
							"Load balancer %s in %s has a listener on port 80 (HTTP) but no corresponding "+
								"listener on port 443 (HTTPS). Traffic is transmitted in plaintext, exposing "+
								"sensitive data to interception. Add an HTTPS listener with a valid TLS certificate.",
							lbName, region,
						),
						Severity:     finding.SeverityHigh,
						Asset:        asset,
						Scanner:      "cloud/aws",
						ProofCommand: fmt.Sprintf("aws elbv2 describe-listeners --load-balancer-arn %s --region %s", lbArn, region),
						Evidence:     ev,
						DiscoveredAt: time.Now(),
					})
				}

				// Check 3: HTTPS listener using outdated TLS policy.
				for _, l := range listeners.Listeners {
					port := awscfg.ToInt32(l.Port)
					if port == 443 || string(l.Protocol) == "HTTPS" || string(l.Protocol) == "TLS" {
						sslPolicy := awscfg.ToString(l.SslPolicy)
						if sslPolicy != "" && isInsecureTLSPolicy(sslPolicy) {
							ev := copyEvidence(evidence)
							ev["ssl_policy"] = sslPolicy
							ev["listener_port"] = port
							findings = append(findings, finding.Finding{
								CheckID: finding.CheckCloudAWSELBInsecureTLS,
								Title:   fmt.Sprintf("Load balancer uses outdated TLS policy: %s (%s)", lbName, sslPolicy),
								Description: fmt.Sprintf(
									"Load balancer %s in %s uses TLS policy %s which supports outdated "+
										"protocol versions (TLS 1.0/1.1) or weak cipher suites. Upgrade to a "+
										"modern policy that enforces TLS 1.2+ (e.g., ELBSecurityPolicy-TLS13-1-2-2021-06).",
									lbName, region, sslPolicy,
								),
								Severity:     finding.SeverityHigh,
								Asset:        asset,
								Scanner:      "cloud/aws",
								ProofCommand: fmt.Sprintf("aws elbv2 describe-listeners --load-balancer-arn %s --region %s", lbArn, region),
								Evidence:     ev,
								DiscoveredAt: time.Now(),
							})
						}
					}
				}
			}

			// Fetch load balancer attributes.
			attrs, attrErr := svc.DescribeLoadBalancerAttributes(ctx, &elbv2.DescribeLoadBalancerAttributesInput{
				LoadBalancerArn: lb.LoadBalancerArn,
			})
			if attrErr == nil {
				attrMap := make(map[string]string)
				for _, a := range attrs.Attributes {
					attrMap[awscfg.ToString(a.Key)] = awscfg.ToString(a.Value)
				}

				// Check 2: Access logs not enabled.
				if attrMap["access_logs.s3.enabled"] != "true" {
					ev := copyEvidence(evidence)
					ev["access_logs_enabled"] = attrMap["access_logs.s3.enabled"]
					findings = append(findings, finding.Finding{
						CheckID: finding.CheckCloudAWSELBNoAccessLogs,
						Title:   fmt.Sprintf("Load balancer access logging is not enabled: %s", lbName),
						Description: fmt.Sprintf(
							"Load balancer %s in %s does not have access logging enabled. "+
								"Access logs record all requests processed by the load balancer, which are "+
								"critical for security auditing, forensics, and compliance. Enable access "+
								"logging to an S3 bucket.",
							lbName, region,
						),
						Severity:     finding.SeverityMedium,
						Asset:        asset,
						Scanner:      "cloud/aws",
						ProofCommand: fmt.Sprintf("aws elbv2 describe-load-balancer-attributes --load-balancer-arn %s --region %s", lbArn, region),
						Evidence:     ev,
						DiscoveredAt: time.Now(),
					})
				}

				// ALB-only checks.
				if lbType == "application" {
					// Check 4: ALB not dropping invalid HTTP headers.
					if attrMap["routing.http.drop_invalid_header_fields.enabled"] != "true" {
						ev := copyEvidence(evidence)
						ev["drop_invalid_headers"] = attrMap["routing.http.drop_invalid_header_fields.enabled"]
						findings = append(findings, finding.Finding{
							CheckID: finding.CheckCloudAWSELBNoDropInvalidHeaders,
							Title:   fmt.Sprintf("ALB does not drop invalid HTTP headers: %s", lbName),
							Description: fmt.Sprintf(
								"Application Load Balancer %s in %s does not drop invalid HTTP headers. "+
									"Invalid headers can be used for request smuggling and header injection "+
									"attacks. Enable routing.http.drop_invalid_header_fields.enabled to "+
									"strip non-compliant headers before forwarding to targets.",
								lbName, region,
							),
							Severity:     finding.SeverityMedium,
							Asset:        asset,
							Scanner:      "cloud/aws",
							ProofCommand: fmt.Sprintf("aws elbv2 describe-load-balancer-attributes --load-balancer-arn %s --region %s", lbArn, region),
							Evidence:     ev,
							DiscoveredAt: time.Now(),
						})
					}

					// Check 5: ALB desync mitigation mode not strictest.
					if attrMap["routing.http.desync_mitigation_mode"] != "strictest" {
						ev := copyEvidence(evidence)
						ev["desync_mitigation_mode"] = attrMap["routing.http.desync_mitigation_mode"]
						findings = append(findings, finding.Finding{
							CheckID: finding.CheckCloudAWSELBNoDesyncMitigation,
							Title:   fmt.Sprintf("ALB HTTP desync mitigation is not set to strictest: %s", lbName),
							Description: fmt.Sprintf(
								"Application Load Balancer %s in %s has HTTP desync mitigation mode set to "+
									"'%s' instead of 'strictest'. HTTP desync attacks exploit differences in "+
									"how front-end and back-end servers parse HTTP requests, enabling request "+
									"smuggling. Set routing.http.desync_mitigation_mode to 'strictest'.",
								lbName, region, attrMap["routing.http.desync_mitigation_mode"],
							),
							Severity:     finding.SeverityMedium,
							Asset:        asset,
							Scanner:      "cloud/aws",
							ProofCommand: fmt.Sprintf("aws elbv2 describe-load-balancer-attributes --load-balancer-arn %s --region %s", lbArn, region),
							Evidence:     ev,
							DiscoveredAt: time.Now(),
						})
					}
				}
			}
		}

		if resp.NextMarker == nil {
			break
		}
		marker = resp.NextMarker
	}

	return findings, nil
}

// isInsecureTLSPolicy returns true if the SSL policy name indicates support for
// outdated TLS versions (1.0, 1.1) or old cipher suites (2016-era policies).
func isInsecureTLSPolicy(policy string) bool {
	p := strings.ToUpper(policy)
	return strings.Contains(p, "TLS-1-0") ||
		strings.Contains(p, "TLS-1-1") ||
		strings.Contains(p, "2016")
}

// copyEvidence returns a shallow copy of the evidence map so per-finding
// entries do not mutate the shared base map.
func copyEvidence(src map[string]any) map[string]any {
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
