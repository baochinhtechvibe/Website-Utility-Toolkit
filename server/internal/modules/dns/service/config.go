// ============================================
// FILE: internal/dns/config.go
// DNS configuration và constants
// ============================================
package dns

import (
	"os"
	"strings"

	"tools.bctechvibe.com/server/internal/modules/dns/models"
)

// UDP DNS servers (fallback cho OpenDNS hoặc khi DoH fail)
var DNSServers = map[string]string{
	"google":     "8.8.8.8:53",
	"cloudflare": "1.1.1.1:53",
	"quad9":      "9.9.9.9:53",
	"opendns":    "208.67.222.222:53",
}

var RBLProviders = buildRBLProviders()

func buildRBLProviders() []models.RBLProvider {
	providers := []models.RBLProvider{
		{Host: "bl.spamcop.net", Name: "SpamCop", Level: "High", Category: "Uy tín email", PolicyURL: "https://www.spamcop.net/bl.shtml"},
		{Host: "b.barracudacentral.org", Name: "Barracuda Reputation", Level: "High", Category: "Uy tín email", PolicyURL: "https://www.barracudacentral.org/rbl"},
		{Host: "dnsbl-1.uceprotect.net", Name: "UCEPROTECT Level 1", Level: "High", Category: "Uy tín email", PolicyURL: "https://www.uceprotect.net/en/index.php?m=3&s=0"},
		{Host: "psbl.surriel.com", Name: "PSBL", Level: "High", Category: "Uy tín email", PolicyURL: "https://psbl.org/"},
		{Host: "bl.mailspike.net", Name: "Mailspike BL", Level: "High", Category: "Uy tín email", PolicyURL: "https://mailspike.org/"},
		{Host: "dnsbl.dronebl.org", Name: "DroneBL", Level: "Medium", Category: "Máy chủ bị xâm nhập", PolicyURL: "https://www.dronebl.org/docs/howtouse"},
		{Host: "truncate.gbudb.net", Name: "GBUdb Truncate", Level: "Medium", Category: "Uy tín email", PolicyURL: "https://www.gbudb.com/truncate/"},
		{Host: "z.mailspike.net", Name: "Mailspike Z", Level: "Medium", Category: "Uy tín email", PolicyURL: "https://mailspike.org/"},
		{Host: "dnsbl.spfbl.net", Name: "SPFBL", Level: "Medium", Category: "Uy tín email", PolicyURL: "https://spfbl.net/en/dnsbl/"},
		{Host: "rbl.interserver.net", Name: "InterServer RBL", Level: "Medium", Category: "Uy tín email", PolicyURL: "https://rbl.interserver.net/"},
		{Host: "bl.0spam.org", Name: "0SPAM BL", Level: "Medium", Category: "Uy tín email", PolicyURL: "https://0spam.org/"},
		{Host: "bl.blocklist.de", Name: "blocklist.de", Level: "Medium", Category: "Nguồn tấn công", PolicyURL: "https://www.blocklist.de/en/rbldns.html"},
		{Host: "all.s5h.net", Name: "S5H", Level: "Low", Category: "Uy tín email", PolicyURL: "https://www.usenix.org.uk/content/rbl.html"},
		{Host: "bl.nordspam.com", Name: "NordSpam", Level: "Low", Category: "Uy tín email", PolicyURL: "https://www.nordspam.com/"},
		{Host: "bl.spameatingmonkey.net", Name: "SEM BL", Level: "Low", Category: "Uy tín email", PolicyURL: "https://spameatingmonkey.com/services"},
		{Host: "dnsbl.kempt.net", Name: "Kempt BL", Level: "Low", Category: "Uy tín email", PolicyURL: "https://www.kempt.net/dnsbl/"},
		{Host: "ips.backscatterer.org", Name: "Backscatterer", Level: "Low", Category: "Backscatter", PolicyURL: "https://www.backscatterer.org/?target=usage"},
		{Host: "torexit.dan.me.uk", Name: "Tor Exit Nodes", Level: "Low", Category: "Nút thoát Tor", PolicyURL: "https://www.dan.me.uk/dnsbl"},
	}

	if key := strings.TrimSpace(os.Getenv("SPAMHAUS_DQS_KEY")); key != "" {
		providers = append([]models.RBLProvider{{
			Host:      "zen.dq.spamhaus.net",
			QueryHost: key + ".zen.dq.spamhaus.net",
			Name:      "Spamhaus ZEN DQS",
			Level:     "High",
			Category:  "Uy tín email",
			PolicyURL: "https://docs.spamhaus.com/datasets/docs/source/70-access-methods/data-query-service/000-intro.html",
		}}, providers...)
	}

	if key := strings.TrimSpace(os.Getenv("ABUSIX_API_KEY")); key != "" {
		providers = append(providers, models.RBLProvider{
			Host:      "combined.mail.abusix.zone",
			QueryHost: key + ".combined.mail.abusix.zone",
			Name:      "Abusix Combined",
			Level:     "High",
			Category:  "Uy tín email",
			PolicyURL: "https://docs.abusix.com/docs/guardian-mail/production-zones",
		})
	}

	return providers
}

func ResolveUDPServer(serverKey string) string {
	if s, ok := DNSServers[serverKey]; ok {
		return s
	}
	// fallback an toàn
	return "8.8.8.8:53"
}
