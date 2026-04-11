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

	// Allow IP addresses (used for PTR lookups)
	if net.ParseIP(domain) != nil {
		return true
	}

	// Split into labels and validate each one
	labels := strings.Split(domain, ".")

	// Domain must have at least 2 labels (name + TLD)
	if len(labels) < 2 {
		return false
	}

	// TLD (last label) must be purely alphabetic and at least 2 chars
	tld := labels[len(labels)-1]
	if len(tld) < 2 {
		return false
	}
	for _, ch := range tld {
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')) {
			return false
		}
	}

	// Validate each non-TLD label
	for _, label := range labels[:len(labels)-1] {
		if !isValidDNSLabel(label) {
			return false
		}
	}

	return true
}

// isValidDNSLabel validates a single DNS label.
// Allows: a-z, A-Z, 0-9, hyphen (-), underscore (_)
// Underscore is needed for:
//   - DKIM:  tino._domainkey.domain.com
//   - DMARC: _dmarc.domain.com
//   - ACME:  _acme-challenge.domain.com
//   - SRV:   _sip._tcp.domain.com
func isValidDNSLabel(label string) bool {
	if label == "" || len(label) > 63 {
		return false
	}

	// Label must not start or end with a hyphen
	if label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}

	for _, ch := range label {
		if !((ch >= 'a' && ch <= 'z') ||
			(ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') ||
			ch == '-' || ch == '_') {
			return false
		}
	}
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
