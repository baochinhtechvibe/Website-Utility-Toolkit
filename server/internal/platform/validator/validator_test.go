package validator

import (
	"context"
	"net"
	"testing"
)

func TestAreAllResolvedIPsSafe(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ips  []net.IP
		want bool
	}{
		{
			name: "public IPv4 only",
			ips: []net.IP{
				net.ParseIP("8.8.8.8"),
				net.ParseIP("1.1.1.1"),
			},
			want: true,
		},
		{
			name: "mixed public and private IPv4",
			ips: []net.IP{
				net.ParseIP("8.8.8.8"),
				net.ParseIP("10.0.0.5"),
			},
			want: false,
		},
		{
			name: "loopback IPv4",
			ips: []net.IP{
				net.ParseIP("127.0.0.1"),
			},
			want: false,
		},
		{
			name: "mixed public and unique local IPv6",
			ips: []net.IP{
				net.ParseIP("2606:4700:4700::1111"),
				net.ParseIP("fd00::1"),
			},
			want: false,
		},
		{
			name: "empty resolution result",
			ips:  nil,
			want: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := areAllResolvedIPsSafe(tt.ips)
			if got != tt.want {
				t.Fatalf("areAllResolvedIPsSafe() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsSafeHostnameWithContextCanceled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if IsSafeHostnameWithContext(ctx, "example.com") {
		t.Fatal("IsSafeHostnameWithContext() = true for canceled context, want false")
	}
}
