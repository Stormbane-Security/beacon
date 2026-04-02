package portscan

import (
	"context"
	"fmt"
	"strings"

	"github.com/stormbane-security/beacon/internal/finding"
)

func init() {
	registerProbe(ServiceProbe{
		Name:         "unifi-8443",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{8443},
		Detect:       detectUniFi8443,
	})
	registerProbe(ServiceProbe{
		Name:         "unifi-8880",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{8880},
		Detect:       detectUniFi8880,
	})
	registerProbe(ServiceProbe{
		Name:         "unifi-8843",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{8843},
		Detect:       detectUniFi8843,
	})
	registerProbe(ServiceProbe{
		Name:         "aruba-instant-4343",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{4343},
		Detect:       detectArubaInstant4343,
	})
	registerProbe(ServiceProbe{
		Name:         "aruba-instant-8443",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{8443},
		Detect:       detectArubaInstant8443,
	})
	registerProbe(ServiceProbe{
		Name:         "tplink-omada",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{8043},
		Detect:       detectTPLinkOmada,
	})
}

func detectUniFi8443(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	return probeUniFi(ctx, host, port, true)
}

func detectUniFi8880(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	return probeUniFi(ctx, host, port, false)
}

func detectUniFi8843(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	return probeUniFi(ctx, host, port, true)
}

func detectArubaInstant4343(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	body, ok := probeHTTPBody(ctx, host, port, true, "/")
	if !ok {
		return nil
	}
	lb := strings.ToLower(body)
	if !strings.Contains(lb, "aruba") && !strings.Contains(lb, "instant ap") {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckNetDeviceArubaInstant,
		finding.SeverityHigh,
		fmt.Sprintf("Aruba Instant access point management UI exposed on port %d", port),
		"An Aruba Instant access point web management interface is accessible from the internet. "+
			"Exposed AP management allows attackers to reconfigure WiFi SSIDs, capture credentials, "+
			"inject rogue access points into the network, and potentially exploit firmware CVEs. "+
			"Restrict management access to trusted management VLANs.",
		map[string]any{"port": port, "service": "aruba-instant"},
	)}
}

func detectArubaInstant8443(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	body, ok := probeHTTPBody(ctx, host, port, true, "/")
	if !ok {
		return nil
	}
	lb := strings.ToLower(body)
	if !strings.Contains(lb, "aruba instant") && !strings.Contains(lb, "aruba networks") &&
		!strings.Contains(lb, "arubainstant") {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckNetDeviceArubaInstant,
		finding.SeverityHigh,
		fmt.Sprintf("Aruba Instant access point management UI exposed on port %d", port),
		"An Aruba Instant access point web management interface is accessible from the internet. "+
			"Exposed AP management allows attackers to reconfigure WiFi SSIDs, capture credentials, "+
			"inject rogue access points into the network, and potentially exploit firmware CVEs. "+
			"Restrict management access to trusted management VLANs.",
		map[string]any{"port": port, "service": "aruba-instant"},
	)}
}

func detectTPLinkOmada(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	return probeTPLinkOmada(ctx, host, port, true)
}
