package dns

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestIsTimeoutError(t *testing.T) {
	if !isTimeoutError(context.DeadlineExceeded) {
		t.Fatal("isTimeoutError() = false for context deadline")
	}
	if isTimeoutError(errors.New("SERVFAIL")) {
		t.Fatal("isTimeoutError() = true for non-timeout DNS error")
	}
	if isTimeoutError(nil) {
		t.Fatal("isTimeoutError() = true for nil error")
	}
}

func TestRBLProvidersIntegration(t *testing.T) {
	if os.Getenv("RUN_DNS_INTEGRATION_TESTS") != "1" {
		t.Skip("bỏ qua integration test RBL; đặt RUN_DNS_INTEGRATION_TESTS=1 để chạy")
	}

	t.Setenv("SPAMHAUS_DQS_KEY", "")
	t.Setenv("ABUSIX_API_KEY", "")
	for _, provider := range buildRBLProviders() {
		provider := provider
		t.Run(provider.Host, func(t *testing.T) {
			queryHost := rblQueryHost(provider)
			records, err := queryRBL(context.Background(), "2.0.0.127."+queryHost)
			if err != nil {
				t.Fatalf("queryRBL() positive probe error = %v", err)
			}
			if status := classifyRBLRecords(records); status != "LISTED" {
				t.Fatalf("classifyRBLRecords() positive probe = %q, want LISTED", status)
			}

			records, err = queryRBL(context.Background(), "1.0.0.127."+queryHost)
			if err != nil {
				t.Fatalf("queryRBL() negative probe error = %v", err)
			}
			if status := classifyRBLRecords(records); status != "OK" {
				t.Fatalf("classifyRBLRecords() negative probe = %q, want OK", status)
			}
		})
	}
}

func TestClassifyRBLRecords(t *testing.T) {
	tests := []struct {
		name    string
		records []dns.RR
		want    string
	}{
		{name: "not listed", want: "OK"},
		{name: "listed", records: []dns.RR{testARecord(t, "127.0.0.2")}, want: "LISTED"},
		{name: "spamhaus resolver error", records: []dns.RR{testARecord(t, "127.255.255.254")}, want: "ERROR"},
		{name: "unexpected public address", records: []dns.RR{testARecord(t, "104.21.5.194")}, want: "ERROR"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := classifyRBLRecords(test.records); got != test.want {
				t.Fatalf("classifyRBLRecords() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestBuildRBLProviders(t *testing.T) {
	t.Setenv("SPAMHAUS_DQS_KEY", "spamhaus-key")
	t.Setenv("ABUSIX_API_KEY", "abusix-key")

	providers := buildRBLProviders()
	queryHosts := make(map[string]bool, len(providers))
	for _, provider := range providers {
		queryHosts[rblQueryHost(provider)] = true
		if strings.Contains(provider.Host, "sorbs.net") {
			t.Fatalf("buildRBLProviders() contains retired SORBS provider %q", provider.Host)
		}
	}

	for _, host := range []string{
		"spamhaus-key.zen.dq.spamhaus.net",
		"abusix-key.combined.mail.abusix.zone",
		"bl.0spam.org",
		"bl.blocklist.de",
	} {
		if !queryHosts[host] {
			t.Fatalf("buildRBLProviders() missing %q", host)
		}
	}

	payload, err := json.Marshal(providers)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if strings.Contains(string(payload), "spamhaus-key") || strings.Contains(string(payload), "abusix-key") {
		t.Fatal("buildRBLProviders() exposes provider API keys in JSON")
	}
}

func testARecord(t *testing.T, address string) dns.RR {
	t.Helper()
	record, err := dns.NewRR("test.example. 60 IN A " + address)
	if err != nil {
		t.Fatalf("dns.NewRR() error = %v", err)
	}
	return record
}
