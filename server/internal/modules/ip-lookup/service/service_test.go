package service

import (
	"net"
	"testing"
)

func TestParseUserAgent(t *testing.T) {
	tests := []struct {
		name        string
		ua          string
		wantBrowser string
		wantOS      string
	}{
		{
			name:        "Windows Chrome",
			ua:          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			wantBrowser: "Chrome",
			wantOS:      "Windows",
		},
		{
			name:        "Mac Safari",
			ua:          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
			wantBrowser: "Safari",
			wantOS:      "macOS",
		},
		{
			name:        "iOS Safari",
			ua:          "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
			wantBrowser: "Safari",
			wantOS:      "iOS",
		},
		{
			name:        "Linux Firefox",
			ua:          "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
			wantBrowser: "Firefox",
			wantOS:      "Linux",
		},
		{
			name:        "Windows Edge",
			ua:          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
			wantBrowser: "Edge",
			wantOS:      "Windows",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotBrowser, gotOS := ParseUserAgent(tt.ua)
			if gotBrowser != tt.wantBrowser {
				t.Errorf("ParseUserAgent() gotBrowser = %v, want %v", gotBrowser, tt.wantBrowser)
			}
			if gotOS != tt.wantOS {
				t.Errorf("ParseUserAgent() gotOS = %v, want %v", gotOS, tt.wantOS)
			}
		})
	}
}

func TestIpToDecimal(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want string
	}{
		{
			name: "IPv4 localhost",
			ip:   "127.0.0.1",
			want: "2130706433",
		},
		{
			name: "IPv4 max",
			ip:   "255.255.255.255",
			want: "4294967295",
		},
		{
			name: "IPv6 localhost",
			ip:   "::1",
			want: "1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if got := ipToDecimal(ip); got != tt.want {
				t.Errorf("ipToDecimal() = %v, want %v", got, tt.want)
			}
		})
	}
}
