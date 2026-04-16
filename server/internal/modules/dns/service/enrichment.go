package dns

import (
	"strings"

	"tools.bctechvibe.com/server/internal/modules/dns/models"
	"tools.bctechvibe.com/server/internal/pkg/iana"
)

// EnrichmentManager handles the context enrichment for DNS trace steps
type EnrichmentManager struct{}

func NewEnrichmentManager() *EnrichmentManager {
	return &EnrichmentManager{}
}

// EnrichStep adds metadata to a trace step
func (em *EnrichmentManager) EnrichStep(step *models.TraceStep, queryDomain string) {
	if step == nil || (step.ServerName == "" && step.ServerIP == "") {
		return
	}

	step.Enrichment = &models.TraceEnrichment{}

	// 1. Identify ROOT servers
	if org, ok := iana.RootServerOrgs[step.ServerName]; ok {
		step.Enrichment.Organization = org
		step.Enrichment.NodeType = "ROOT"
		step.Enrichment.Location = "Global"
		return
	}
	if org, ok := iana.RootServerOrgs[step.ServerIP]; ok {
		step.Enrichment.Organization = org
		step.Enrichment.NodeType = "ROOT"
		step.Enrichment.Location = "Global"
		return
	}

	// 2. Identify TLD servers
	// A server is likely a TLD server if the query domain is very short (e.g., "com.", "vn.")
	// or if we compare with IANA bootstrap list.
	tld := getTLD(step.ServerName)
	if tld == "" {
		tld = getTLD(queryDomain) // Fallback to checking the query itself
	}

	if tld != "" {
		rdapURL := iana.GetRDAPURL(tld)
		if rdapURL != "" {
			step.Enrichment.NodeType = "TLD"
			step.Enrichment.RegistryURL = rdapURL
			
			// Hardcoded common registries for better UX without extra requests
			switch strings.ToLower(tld) {
			case "com", "net":
				step.Enrichment.Organization = "Verisign, Inc."
				step.Enrichment.Location = "USA"
			case "org":
				step.Enrichment.Organization = "Public Interest Registry (PIR)"
				step.Enrichment.Location = "USA"
			case "vn":
				step.Enrichment.Organization = "Vietnam Internet Network Information Center (VNNIC)"
				step.Enrichment.Location = "Vietnam"
			case "io":
				step.Enrichment.Organization = "Internet Computer Bureau"
				step.Enrichment.Location = "British Indian Ocean Territory"
			default:
				step.Enrichment.Organization = strings.ToUpper(tld) + " Registry"
			}
			return
		}
	}

	// 3. Authoritative
	step.Enrichment.NodeType = "AUTHORITATIVE"
	step.Enrichment.Organization = "Authoritative Nameserver"
}

func getTLD(domain string) string {
	parts := strings.Split(strings.TrimSuffix(domain, "."), ".")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return ""
}
