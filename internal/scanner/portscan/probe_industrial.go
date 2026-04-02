package portscan

import (
	"context"
	"fmt"

	"github.com/stormbane-security/beacon/internal/finding"
)

func init() {
	registerProbe(ServiceProbe{
		Name:         "modbus",
		Category:     ProbeCatProtocol,
		DefaultPorts: []int{502},
		Detect:       detectModbus,
	})
	registerProbe(ServiceProbe{
		Name:         "s7comm",
		Category:     ProbeCatProtocol,
		DefaultPorts: []int{102},
		Detect:       detectS7Comm,
	})
	registerProbe(ServiceProbe{
		Name:         "ethernetip",
		Category:     ProbeCatProtocol,
		DefaultPorts: []int{44818},
		Detect:       detectEtherNetIP,
	})
	registerProbe(ServiceProbe{
		Name:         "dnp3",
		Category:     ProbeCatProtocol,
		DefaultPorts: []int{20000},
		Detect:       detectDNP3,
	})
	registerProbe(ServiceProbe{
		Name:         "bacnet",
		Category:     ProbeCatProtocol,
		DefaultPorts: []int{47808},
		Detect:       detectBACnet,
	})
}

func detectModbus(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	if isModbus := probeModbus(ctx, host, port); !isModbus {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortModbusExposed,
		finding.SeverityCritical,
		fmt.Sprintf("Modbus TCP SCADA/ICS device exposed on port %d", port),
		"A Modbus TCP industrial control system device is publicly accessible. "+
			"Modbus has no built-in authentication or encryption. "+
			"An attacker can read sensor values, write control registers, and issue commands "+
			"to industrial equipment (PLCs, RTUs, HMIs) without any credentials. "+
			"This is a critical OT/SCADA exposure that can cause physical damage or safety incidents. "+
			"Isolate industrial devices from internet access immediately.",
		map[string]any{"port": port, "service": "modbus", "banner": banner},
	)}
}

func detectS7Comm(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	if !probeS7comm(ctx, host, port) {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortS7CommExposed,
		finding.SeverityCritical,
		fmt.Sprintf("Siemens S7 PLC accessible on port %d (COTP/S7comm)", port),
		"TCP port 102 (Siemens S7comm over COTP/ISO-on-TCP) is internet-accessible. "+
			"This is a direct connection to a Siemens S7-300/400/1200/1500 Programmable Logic Controller. "+
			"S7comm has no built-in authentication in older PLC series — an attacker can read all process "+
			"data, write control values, and modify PLC logic. Stuxnet targeted Siemens S7 PLCs via this "+
			"protocol. Any internet-exposed S7 PLC should be treated as a critical infrastructure emergency. "+
			"Air-gap or firewall this port immediately.",
		map[string]any{"port": port, "service": "s7comm", "banner": banner},
	)}
}

func detectEtherNetIP(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	if !probeEtherNetIP(ctx, host, port) {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortEtherNetIPExposed,
		finding.SeverityCritical,
		fmt.Sprintf("Rockwell EtherNet/IP PLC accessible on port %d", port),
		"TCP port 44818 (EtherNet/IP — Allen-Bradley/Rockwell Automation industrial protocol) is "+
			"internet-accessible. EtherNet/IP provides direct access to Rockwell CompactLogix, ControlLogix, "+
			"MicroLogix, and other PLCs. An attacker can enumerate device identity, read/write process tags, "+
			"and halt production operations. No authentication is required for `List Identity` queries. "+
			"This port must never be internet-facing — apply firewall rules immediately.",
		map[string]any{"port": port, "service": "ethernetip", "banner": banner},
	)}
}

func detectDNP3(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	if !probeDNP3(ctx, host, port) {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortDNP3Exposed,
		finding.SeverityCritical,
		fmt.Sprintf("DNP3 electric utility SCADA accessible on port %d", port),
		"TCP port 20000 (DNP3 — Distributed Network Protocol 3) is internet-accessible. "+
			"DNP3 is used in electric power distribution, water treatment, and oil/gas SCADA systems. "+
			"An attacker with network access can send unsolicited control commands to RTUs and substations. "+
			"ICS-CERT has issued multiple advisories on internet-exposed DNP3. "+
			"This is a critical infrastructure exposure — air-gap immediately.",
		map[string]any{"port": port, "service": "dnp3", "banner": banner},
	)}
}

func detectBACnet(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	if !probeBACnet(ctx, host, port) {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortBACnetExposed,
		finding.SeverityHigh,
		fmt.Sprintf("BACnet building automation protocol accessible on port %d", port),
		"TCP/UDP port 47808 (BACnet/IP) is internet-accessible. BACnet controls building automation "+
			"systems including HVAC, lighting, access control, and fire systems. An attacker can discover "+
			"devices, read sensor values, and potentially control building systems. BACnet/IP has no "+
			"authentication in the base protocol. Restrict to internal building management networks.",
		map[string]any{"port": port, "service": "bacnet", "banner": banner},
	)}
}
