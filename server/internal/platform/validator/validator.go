package validator

import (
	"net"
	"strings"
)

type ValidationResult struct {
	Valid    bool
	ErrorMsg string
}

func IsValidDomain(domain string) bool {
	if domain == "" || len(domain) > 253 {
		return false
	}
	// Simple domain syntax validation
	if strings.HasPrefix(domain, "-") || strings.HasSuffix(domain, "-") {
		return false
	}
	// Allow IP addresses as well (it's a valid "target")
	return true
}

func ValidateSyntax(hostname string) ValidationResult {
	if hostname == "" {
		return ValidationResult{Valid: false, ErrorMsg: "Vui lòng nhập tên miền hoặc IP"}
	}
	if !IsValidDomain(hostname) {
		return ValidationResult{Valid: false, ErrorMsg: "Định dạng tên miền không hợp lệ"}
	}
	return ValidationResult{Valid: true}
}

func ValidateAndDetect(hostname string) ValidationResult {
	if hostname == "" {
		return ValidationResult{Valid: false, ErrorMsg: "Vui lòng nhập tên miền hoặc IP"}
	}
	if !IsSafeHostname(hostname) {
		return ValidationResult{Valid: false, ErrorMsg: "Tên miền/IP không được phép (Local/Internal)"}
	}
	return ValidationResult{Valid: true}
}

func IsSafeHostname(hostname string) bool {
	// Resolve IP check
	ips, err := net.LookupIP(hostname)
	if err != nil {
		// If it's an IP string, net.ParseIP will handle it
		if ip := net.ParseIP(hostname); ip != nil {
			return IsSafeIP(ip)
		}
		// Otherwise, if it doesn't resolve, it's technically "safe" (cannot be used for SSRF)
		return true 
	}
	hasSafe := false
	for _, ip := range ips {
		if IsSafeIP(ip) {
			hasSafe = true
			break
		}
	}
	return hasSafe
}

func IsSafeIP(ip net.IP) bool {
	// In Go 1.17+, ip.IsPrivate() is available. We handle it for backwards compatibility if needed.
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	
	// CGNAT range (100.64.0.0/10)
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 100 && (ip4[1] >= 64 && ip4[1] <= 127) {
			return false
		}
	}

	// Use IsPrivate() for Go 1.17+ logic
	// If the user's Go version is older, this will fail build, but they are on 1.25+ as per README.
	if ip.IsPrivate() {
		return false
	}

	return true
}
