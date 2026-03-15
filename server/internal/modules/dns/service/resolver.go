// ============================================
// FILE: internal/dns/resolver.go
// PURPOSE:
//   - Expose a single DNS resolver interface
//   - Default resolver is DNS-over-HTTPS (DoH)
//   - UDP resolver is used only when:
//     1. User explicitly selects UDP
//     2. (Optional) DoH fails → fallback to UDP
//
// ============================================
package dns

import (
	"errors"

	"tools.bctechvibe.com/server/internal/modules/dns/models"

	dnslib "github.com/miekg/dns"
)

// ============================================
// Resolver Interface
// ============================================

// Resolver defines a unified interface for DNS resolution.
//
// All resolver implementations (DoH, UDP, TCP, etc.) MUST
// implement this interface to keep handlers decoupled from
// transport-specific logic.
type Resolver interface {
	// Query performs a DNS lookup for a given domain and record type.
	//
	// domain MUST be a fully-qualified domain name (FQDN).
	// qtype follows miekg/dns Type constants (TypeA, TypeAAAA, ...).
	Query(domain string, qtype uint16) ([]models.DNSRecord, error)
}

// ============================================
// Resolver Manager
// ============================================

// ResolverManager controls resolver selection logic.
//
// It decides:
//   - Which resolver is default
//   - When to fallback
//   - How to extend future transports (TCP, DoT, DoQ, ...)
type ResolverManager struct {
	Default Resolver
	UDP     Resolver
}

// NewResolverManager creates a resolver manager.
//
// Default resolver: DoH
// UDP resolver: used only when explicitly requested
func NewResolverManager(doh Resolver, udp Resolver) *ResolverManager {
	return &ResolverManager{
		Default: doh,
		UDP:     udp,
	}
}

// ============================================
// Public Resolution Logic
// ============================================

// Resolve performs DNS resolution using configured strategy.
//
// resolverType:
//   - "doh" (default)
//   - "udp" (explicit)
//
// NOTE:
//   - DoH is always preferred
//   - UDP fallback is OPTIONAL and intentionally disabled
func (rm *ResolverManager) Resolve(
	domain string,
	qtype uint16,
	resolverType string,
) ([]models.DNSRecord, error) {

	// Explicit UDP selection
	if resolverType == "udp" {
		if rm.UDP == nil {
			return nil, errors.New("UDP resolver not configured")
		}
		return rm.UDP.Query(domain, qtype)
	}

	// Default: DoH
	return rm.Default.Query(domain, qtype)
}

// ============================================
// Helpers
// ============================================

// ToQType converts string record type to DNS qtype
func ToQType(t string) (uint16, error) {
	switch t {
	case "A":
		return dnslib.TypeA, nil
	case "AAAA":
		return dnslib.TypeAAAA, nil
	case "CNAME":
		return dnslib.TypeCNAME, nil
	case "MX":
		return dnslib.TypeMX, nil
	case "NS":
		return dnslib.TypeNS, nil
	case "TXT":
		return dnslib.TypeTXT, nil
	case "PTR":
		return dnslib.TypePTR, nil
	default:
		return 0, errors.New("unsupported DNS record type")
	}
}
