package grpcreflect

import (
	"context"
	"testing"

	"github.com/stormbane-security/beacon/internal/module"
)

func TestExtractServiceNames(t *testing.T) {
	// Simulate a gRPC reflection response containing service names.
	// Service names are length-prefixed strings with dot separators.
	data := make([]byte, 0, 200)
	// Add some random bytes before the service name.
	data = append(data, 0x0a, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f)
	// Add a service name: "com.example.UserService" (23 bytes)
	name := "com.example.UserService"
	data = append(data, byte(len(name)))
	data = append(data, []byte(name)...)
	// Add another: "com.example.OrderService" (24 bytes)
	name2 := "com.example.OrderService"
	data = append(data, byte(len(name2)))
	data = append(data, []byte(name2)...)

	services := extractServiceNames(data)
	if len(services) < 2 {
		t.Fatalf("expected at least 2 services, got %d: %v", len(services), services)
	}

	found := map[string]bool{}
	for _, s := range services {
		found[s] = true
	}
	if !found["com.example.UserService"] {
		t.Error("expected com.example.UserService in extracted services")
	}
	if !found["com.example.OrderService"] {
		t.Error("expected com.example.OrderService in extracted services")
	}
}

func TestSurfaceModeRuns(t *testing.T) {
	// Surface mode should attempt to run (not skip) — gRPC reflection is
	// a safe read-only probe.
	s := New()
	// This will fail to connect to example.com:50051 etc. but should not
	// return an error — just empty findings.
	findings, err := s.Run(context.Background(), "192.0.2.1", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings on unreachable host, got %d", len(findings))
	}
}
