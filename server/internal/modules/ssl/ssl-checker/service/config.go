// ============================================
// FILE: ssl-checker/service/config.go
//
// Constants và cấu hình cho SSL Checker
// ============================================

package service

import "time"

// Timeouts
const (
	TLSDialTimeout    = 5 * time.Second // Giảm xuống 5s cho mỗi lần thử IP
	HTTPProbeTimeout  = 3 * time.Second
	ProbeTimeout      = 4 * time.Second
	DNSResolveTimeout = 4 * time.Second
)

// TLS version labels
const (
	TLSVersion13 = "TLS 1.3"
	TLSVersion12 = "TLS 1.2"
	TLSVersion11 = "TLS 1.1"
	TLSVersion10 = "TLS 1.0"
)
