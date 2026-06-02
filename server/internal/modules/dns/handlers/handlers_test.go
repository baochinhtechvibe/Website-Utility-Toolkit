package handlers

import "testing"

func TestIsSafeHostnameForRequest(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		want     bool
	}{
		{
			name:     "public domain is allowed without pre-resolving",
			hostname: "trungtamdaotaoxenangthienvu.com",
			want:     true,
		},
		{
			name:     "public IPv4 is allowed",
			hostname: "8.8.8.8",
			want:     true,
		},
		{
			name:     "private IPv4 is blocked",
			hostname: "192.168.1.1",
			want:     false,
		},
		{
			name:     "localhost is blocked",
			hostname: "localhost",
			want:     false,
		},
		{
			name:     "local suffix is blocked",
			hostname: "printer.local",
			want:     false,
		},
		{
			name:     "internal suffix with trailing dot is blocked",
			hostname: "service.internal.",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isSafeHostnameForRequest(tt.hostname); got != tt.want {
				t.Fatalf("isSafeHostnameForRequest(%q) = %v, want %v", tt.hostname, got, tt.want)
			}
		})
	}
}
