// ============================================
// FILE: pkg/validator/validator.go
// Input validation and type detection
// ============================================
package validator

import (
	"net"
	"regexp"
	"strings"
)

var domainRegex = regexp.MustCompile(
	`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`,
)

type InputType int

const (
	InputTypeInvalid InputType = iota
	InputTypeDomain
	InputTypeIPv4
	InputTypeIPv6
)

type ValidationResult struct {
	Valid      bool
	Type       InputType
	Input      string
	ErrorMsg   string
	ValidTypes []string // Valid record types for this input
}

// ValidateAndDetect validates input and detects its type
func ValidateAndDetect(input string) ValidationResult {
	input = strings.TrimSpace(input)

	if input == "" {
		return ValidationResult{
			Valid:    false,
			ErrorMsg: "Hostname không được để trống!",
		}
	}

	// Try to parse as IP
	ip := net.ParseIP(input)

	// Check if it's IPv4
	if ip != nil && ip.To4() != nil {
		if !IsSafeIP(ip) {
			return ValidationResult{
				Valid:    false,
				ErrorMsg: "Địa chỉ IP không được phép (Private/Loopback/Internal). Vui lòng sử dụng IP Public.",
			}
		}

		return ValidationResult{
			Valid:      true,
			Type:       InputTypeIPv4,
			Input:      input,
			ValidTypes: []string{"PTR", "BLACKLIST", "ALL"},
		}
	}

	// Check if it's IPv6
	if ip != nil && ip.To4() == nil {
		if !IsSafeIP(ip) {
			return ValidationResult{
				Valid:    false,
				ErrorMsg: "Địa chỉ IP không được phép (Private/Loopback/Internal). Vui lòng sử dụng IP Public.",
			}
		}

		return ValidationResult{
			Valid:      true,
			Type:       InputTypeIPv6,
			Input:      input,
			ValidTypes: []string{"PTR", "ALL"},
		}
	}

	// Check if it's a valid domain
	if IsValidDomain(input) {
		if !IsSafeHostname(input) {
			return ValidationResult{
				Valid:    false,
				ErrorMsg: "Tên miền không được phép (Local/Internal). Vui lòng sử dụng tên miền Public.",
			}
		}

		return ValidationResult{
			Valid:      true,
			Type:       InputTypeDomain,
			Input:      input,
			ValidTypes: []string{"A", "AAAA", "NS", "MX", "CNAME", "TXT", "DNSSEC", "ALL"},
		}
	}

	return ValidationResult{
		Valid:    false,
		ErrorMsg: "Hostname không hợp lệ. Vui lòng nhập tên miền, địa chỉ IPv4 hoặc IPv6 hợp lệ",
	}
}

// isValidDomain checks if the input is a valid domain name
// func IsValidDomain(domain string) bool {
// 	// Remove trailing dot if present
// 	domain = strings.TrimSuffix(domain, ".")

// 	// Domain regex pattern
// 	// pattern := `^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?
// 	// pattern := `^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`
// 	if !domainRegex.MatchString(domain) {
// 		return false
// 	}

// 	// Additional checks
// 	if len(domain) > 253 {
// 		return false
// 	}

// 	// Check each label length
// 	labels := strings.Split(domain, ".")
// 	for _, label := range labels {
// 		if len(label) > 63 || len(label) == 0 {
// 			return false
// 		}
// 	}

// 	return true
// }

func IsValidDomain(domain string) bool {
	// Remove trailing dot if present
	domain = strings.TrimSuffix(domain, ".")

	// Check length
	if len(domain) > 253 {
		return false
	}

	// 1. Regex cho phép dấu gạch dưới (_) ở các sub-labels (phần đầu)
	// TLD (phần đuôi cùng) thường không chứa dấu gạch dưới.
	// Cấu trúc: (Label chứa _ hoặc - + dấu chấm)* + (Label cuối chỉ chứa -)

	// Giải thích regex mới: Bắt buộc tối thiểu 2 nhãn (có ít nhất 1 dấu chấm)
	// ^ : Bắt đầu chuỗi
	// (
	//   [a-zA-Z0-9_] : Bắt đầu nhãn bằng chữ, số hoặc _
	//   ([a-zA-Z0-9\-_]{0,61}[a-zA-Z0-9_])? : Phần giữa nhãn
	//   \. : Dấu chấm (bắt buộc phải có để thành TLD)
	// )+ : Lặp lại nhóm trên 1 hoặc nhiều lần
	// [a-zA-Z0-9] : TLD bắt đầu bằng chữ/số
	// ([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])? : TLD không chứa _
	// $ : Kết thúc chuỗi

	var dnsRecordRegex = regexp.MustCompile(`^([a-zA-Z0-9_]([a-zA-Z0-9\-_]{0,61}[a-zA-Z0-9_])?\.)+[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$`)

	if !dnsRecordRegex.MatchString(domain) {
		return false
	}

	// Check each label length
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if len(label) > 63 || len(label) == 0 {
			return false
		}
	}

	return true
}

// IsValidRecordType checks if the record type is valid for the input type
func IsValidRecordType(inputType InputType, recordType string) bool {
	validTypes := map[InputType][]string{
		InputTypeDomain: {"A", "AAAA", "NS", "MX", "CNAME", "TXT", "DNSSEC", "ALL"},
		InputTypeIPv4:   {"PTR", "BLACKLIST", "ALL"},
		InputTypeIPv6:   {"PTR", "ALL"},
	}

	types, ok := validTypes[inputType]
	if !ok {
		return false
	}

	for _, t := range types {
		recordType = strings.ToUpper(recordType)
		if t == recordType {
			return true
		}
	}

	return false
}

// GetSuggestedRecordTypes returns suggested record types based on input
func GetSuggestedRecordTypes(inputType InputType) []string {
	switch inputType {
	case InputTypeDomain:
		return []string{"A", "AAAA", "NS", "MX", "CNAME", "TXT", "DNSSEC", "ALL"}
	case InputTypeIPv4:
		return []string{"PTR", "BLACKLIST"}
	case InputTypeIPv6:
		return []string{"PTR"}
	default:
		return []string{}
	}
}

// IsSafeIP checks if an IP is a public, routeable IP address,
// blocking private, loopback, link-local, multicast, and unspecified IPs.
func IsSafeIP(ip net.IP) bool {
	if ip == nil {
		return false
	}

	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return false
	}

	// Check for global multicast
	if ip.IsMulticast() {
		return false
	}

	// For IPv4 specifically
	if ip4 := ip.To4(); ip4 != nil {
		// Check for broadcast (255.255.255.255)
		if ip4.Equal(net.IPv4bcast) {
			return false
		}
	}

	return true
}

// IsSafeHostname checks if a domain appears to be an internal or local hostname.
func IsSafeHostname(hostname string) bool {
	hostname = strings.ToLower(strings.TrimSuffix(hostname, "."))

	// Block standard local hostnames
	if hostname == "localhost" {
		return false
	}

	// Block common internal TLDs
	internalTLDs := []string{".local", ".localhost", ".internal", ".lan", ".home", ".corp"}
	for _, tld := range internalTLDs {
		if strings.HasSuffix(hostname, tld) {
			return false
		}
	}

	return true
}
