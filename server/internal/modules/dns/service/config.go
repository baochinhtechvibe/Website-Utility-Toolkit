// ============================================
// FILE: internal/dns/config.go
// DNS configuration và constants
// ============================================
package dns

import "tools.bctechvibe.com/server/internal/modules/dns/models"

// UDP DNS servers (fallback cho OpenDNS hoặc khi DoH fail)
var DNSServers = map[string]string{
	"google":     "8.8.8.8:53",
	"cloudflare": "1.1.1.1:53",
	"quad9":      "9.9.9.9:53",
	"opendns":    "208.67.222.222:53",
}

var RBLProviders = []models.RBLProvider{
	// === HIGH — Widely trusted, low false positive ===
	// Note: Spamhaus (zen) may block queries from public resolvers like 8.8.8.8.
	// Our current authoritative-first lookup strategy helps mitigate this.
	{Host: "zen.spamhaus.org", Level: "High"},
	{Host: "bl.spamcop.net", Level: "High"},
	{Host: "b.barracudacentral.org", Level: "High"},
	{Host: "dnsbl-1.uceprotect.net", Level: "High"},
	{Host: "psbl.surriel.com", Level: "High"},
	{Host: "bl.mailspike.net", Level: "High"},
	{Host: "cbl.abuseat.org", Level: "High"},
	{Host: "dnsbl.dronebl.org", Level: "High"},

	// === MEDIUM — Good signal, some noise ===
	{Host: "dnsbl.sorbs.net", Level: "Medium"},
	{Host: "dnsbl.blocklist.de", Level: "Medium"},
	{Host: "mail.abusix.zone", Level: "Medium"},
	{Host: "ix.dnsbl.manitu.net", Level: "Medium"},
	{Host: "truncate.gbudb.net", Level: "Medium"},
	{Host: "spam.dnsbl.sorbs.net", Level: "Medium"},
	{Host: "z.mailspike.net", Level: "Medium"},
	{Host: "ips.backscatterer.org", Level: "Medium"},
	{Host: "db.wpbl.info", Level: "Medium"},
	{Host: "dnsbl.spfbl.net", Level: "Medium"},
	{Host: "rbl.interserver.net", Level: "Medium"},
	{Host: "dnsbl.0spam.org", Level: "Medium"},

	// === LOW — Supplemental, niche coverage ===
	{Host: "tor.dan.me.uk", Level: "Low"},
	{Host: "torexit.dan.me.uk", Level: "Low"},
	{Host: "http.dnsbl.sorbs.net", Level: "Low"},
	{Host: "socks.dnsbl.sorbs.net", Level: "Low"},
	{Host: "smtp.dnsbl.sorbs.net", Level: "Low"},
	{Host: "all.s5h.net", Level: "Low"},
	{Host: "bl.nordspam.com", Level: "Low"},
	{Host: "backscatter.spameatingmonkey.net", Level: "Low"},
	{Host: "bl.spameatingmonkey.net", Level: "Low"},
	{Host: "dnsbl.kempt.net", Level: "Low"},
	{Host: "relays.nether.net", Level: "Low"},
}

func ResolveUDPServer(serverKey string) string {
	if s, ok := DNSServers[serverKey]; ok {
		return s
	}
	// fallback an toàn
	return "8.8.8.8:53"
}
