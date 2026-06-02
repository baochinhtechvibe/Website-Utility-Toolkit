package dns

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDoTrace(t *testing.T) {
	if os.Getenv("RUN_DNS_INTEGRATION_TESTS") != "1" {
		t.Skip("bỏ qua integration test DNS trace; đặt RUN_DNS_INTEGRATION_TESTS=1 để chạy")
	}

	tr := NewTraceResolver(20 * time.Second)

	// Test with a domain that has CNAME chain
	domain := "www.github.com"
	records, logs, err := tr.DoTrace(domain, dns.TypeA)
	if err != nil {
		t.Fatalf("DoTrace failed for %s: %v", domain, err)
	}

	fmt.Printf("\n--- Trace Logs for %s ---\n", domain)
	for _, step := range logs {
		fmt.Println(step.Message)
	}

	fmt.Printf("\n--- Records found for %s ---\n", domain)
	for _, rec := range records {
		fmt.Printf("Type: %s, Value/Address: %s/%s\n", rec.Type, rec.Value, rec.Address)
	}

	if len(records) == 0 {
		t.Errorf("No records found for %s", domain)
	}
}

func TestDoTraceParallel(t *testing.T) {
	if os.Getenv("RUN_DNS_INTEGRATION_TESTS") != "1" {
		t.Skip("bỏ qua integration test DNS trace; đặt RUN_DNS_INTEGRATION_TESTS=1 để chạy")
	}

	tr := NewTraceResolver(30 * time.Second)
	domain := "google.com"

	// Test parallel execution mock
	go func() {
		tr.DoTrace(domain, dns.TypeA)
	}()
	go func() {
		tr.DoTrace(domain, dns.TypeAAAA)
	}()

	time.Sleep(2 * time.Second)
}
