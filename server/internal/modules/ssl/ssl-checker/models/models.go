// ============================================
// FILE: ssl-checker/models/models.go
//
// Cấu trúc dữ liệu (data models) cho SSL Checker
// ============================================

package models

import "time"

// ===========================
// Request
// ===========================

type CheckRequest struct {
	Domain      string `json:"domain" binding:"required"`
	BypassCache bool   `json:"bypass_cache"`
}

// ===========================
// Certificate Level
// ===========================

type CertLevel string

const (
	CertLevelDomain       CertLevel = "domain"
	CertLevelIntermediate CertLevel = "intermediate"
	CertLevelRoot         CertLevel = "root"
)

// ===========================
// Trust Level (severity)
// ===========================

type TrustLevel string

const (
	TrustLevelCritical TrustLevel = "critical"
	TrustLevelWarning  TrustLevel = "warning"
)

// ===========================
// Trust Codes
// ===========================

type TrustCode string

const (
	TrustOK TrustCode = "ok"

	// Self-signed (OpenSSL error 18, 19)
	TrustSelfSignedLeaf  TrustCode = "self_signed"
	TrustSelfSignedChain TrustCode = "self_signed_in_chain"

	// Chain / Issuer
	TrustMissingIssuer TrustCode = "missing_issuer"
	TrustBadChain      TrustCode = "bad_chain"
	TrustUntrustedRoot TrustCode = "untrusted_root"

	// Expiration
	TrustCertExpired  TrustCode = "cert_expired"
	TrustChainExpired TrustCode = "chain_expired"
	TrustExpiringSoon TrustCode = "expiring_soon"

	// Hostname
	TrustNameMismatch TrustCode = "name_mismatch"

	// Weak security (Warnings)
	TrustWeakKey       TrustCode = "weak_key"
	TrustWeakAlgorithm TrustCode = "weak_algorithm"

	// Fallback
	TrustUnknown TrustCode = "unknown"
)

type TrustIssue struct {
	Code    TrustCode  `json:"code"`
	Level   TrustLevel `json:"level"`
	Message string     `json:"message"`
}

// ===========================
// Certificate Detail
// ===========================

type CertDetail struct {
	CommonName string    `json:"common_name"`
	Issuer     string    `json:"issuer"`
	Level      CertLevel `json:"level"`

	Organization []string `json:"organization,omitempty"`
	Country      []string `json:"country,omitempty"`
	Locality     []string `json:"locality,omitempty"`
	Province     []string `json:"province,omitempty"`

	SANs []string `json:"sans,omitempty"`

	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`

	SerialNumberDec string `json:"serial_dec"`
	SerialNumberHex string `json:"serial_hex"`

	SignatureAlgo string `json:"signature_algo"`

	// Security details
	PublicKeyAlgorithm string `json:"public_key_algorithm,omitempty"`
	PublicKeyBits      int    `json:"public_key_bits,omitempty"`
	FingerprintSHA256  string `json:"fingerprint_sha256,omitempty"`
	FingerprintSHA1    string `json:"fingerprint_sha1,omitempty"`
}

// ===========================
// Main SSL Response
// ===========================

type SSLCheckResponse struct {
	Hostname   string `json:"hostname"`
	IP         string `json:"ip"`
	ServerType string `json:"server_type"`

	Valid     bool  `json:"valid"`
	IsExpired bool  `json:"is_expired"` // Rõ ràng hơn cho frontend
	DaysLeft  int64 `json:"days_left"`  // Có thể âm nếu đã hết hạn

	HostnameOK  bool         `json:"hostname_ok"`
	Trusted     bool         `json:"trusted"`
	TrustIssues []TrustIssue `json:"trust_issues,omitempty"`

	TLSVersion         string `json:"tls_version"`
	CipherSuite        string `json:"cipher_suite,omitempty"`
	InsecureConnection bool   `json:"insecure_connection,omitempty"` // Track fallback TLS

	CertChain []CertDetail `json:"cert_chain"`

	CheckTime time.Time `json:"check_time"`
}
