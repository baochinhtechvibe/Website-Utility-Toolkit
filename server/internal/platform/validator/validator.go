package validator

import (
	"context"
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

	// Allow IP addresses for tools that explicitly support PTR or IP lookups.
	if net.ParseIP(domain) != nil {
		return true
	}

	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}

	tld := labels[len(labels)-1]
	if len(tld) < 2 {
		return false
	}
	isASCIILettersOnly := true
	for _, ch := range tld {
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')) {
			isASCIILettersOnly = false
			break
		}
	}

	if !isASCIILettersOnly {
		// Allow punycode TLDs (e.g. xn--p1ai)
		if !strings.HasPrefix(strings.ToLower(tld), "xn--") || !isValidDNSLabel(tld) {
			return false
		}
	}

	allNumericLabels := true
	hasOver255 := false
	for _, label := range labels[:len(labels)-1] {
		if !isValidDNSLabel(label) {
			return false
		}

		isNumeric := true
		val := 0
		for _, ch := range label {
			if ch < '0' || ch > '9' {
				isNumeric = false
				break
			}
			val = val*10 + int(ch-'0')
		}

		if !isNumeric {
			allNumericLabels = false
		} else if val > 255 {
			hasOver255 = true
		}
	}

	// Reject IP-like input such as 999.1.1.com that is usually a mistyped IP.
	if allNumericLabels && hasOver255 && len(labels) >= 3 {
		return false
	}

	return true
}

// isValidDNSLabel validates a single DNS label.
// Allows: a-z, A-Z, 0-9, hyphen (-), underscore (_)
// Underscore is needed for DKIM, DMARC, ACME and SRV records.
func isValidDNSLabel(label string) bool {
	if label == "" || len(label) > 63 {
		return false
	}

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
	return IsSafeHostnameWithContext(context.Background(), hostname)
}

func IsSafeHostnameWithContext(ctx context.Context, hostname string) bool {
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", hostname)
	if err != nil {
		if ctx.Err() != nil {
			return false
		}
		if ip := net.ParseIP(hostname); ip != nil {
			return IsSafeIP(ip)
		}
		// If it does not resolve, it cannot currently be used for SSRF.
		return true
	}
	return areAllResolvedIPsSafe(ips)
}

func areAllResolvedIPsSafe(ips []net.IP) bool {
	if len(ips) == 0 {
		return false
	}
	for _, ip := range ips {
		if !IsSafeIP(ip) {
			return false
		}
	}
	return true
}

func IsSafeIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}

	// CGNAT range (100.64.0.0/10)
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 100 && (ip4[1] >= 64 && ip4[1] <= 127) {
			return false
		}
	}

	if ip.IsPrivate() {
		return false
	}

	return true
}
