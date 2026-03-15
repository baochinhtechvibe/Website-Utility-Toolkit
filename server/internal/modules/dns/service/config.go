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
	// High Priority RBLs
	{Host: "b.barracudacentral.org", Level: "High"},         // BARRACUDA
	{Host: "zen.spamhaus.org", Level: "High"},               // Spamhaus ZEN (gộp SBL/XBL/PBL)
	{Host: "bl.spamcop.net", Level: "High"},                 // SPAMCOP
	{Host: "dnsbl-1.uceprotect.net", Level: "High"},         // UCEPROTECT Level 1
	{Host: "dnsbl.blocklist.de", Level: "High"},             // BLOCKLIST.DE
	{Host: "bl.mailspike.net", Level: "High"},               // MAILSPIKE BL
	{Host: "psbl.surriel.com", Level: "High"},               // PSBL
	{Host: "db.wpbl.info", Level: "High"},                   // WPBL
	{Host: "mail-abuse.blacklist.jippg.org", Level: "High"}, // JIPPG

	// Medium Priority RBLs
	{Host: "dnsbl.sorbs.net", Level: "Medium"},               // SORBS Aggregate
	{Host: "ips.backscatterer.org", Level: "Medium"},         // BACKSCATTERER
	{Host: "dnsbl-2.uceprotect.net", Level: "Medium"},        // UCEPROTECT Level 2
	{Host: "dnsbl.0spam.org", Level: "Medium"},               // 0SPAM
	{Host: "dbl.0spam.org", Level: "Medium"},                 // 0SPAM NBL
	{Host: "mail.abusix.zone", Level: "Medium"},              // Abusix Mail Intel
	{Host: "rbl.0spam.org", Level: "Medium"},                 // 0SPAM RBL
	{Host: "dyna.spamrats.com", Level: "Medium"},             // RATS Dyna
	{Host: "noptr.spamrats.com", Level: "Medium"},            // RATS NoPtr
	{Host: "spam.spamrats.com", Level: "Medium"},             // RATS Spam
	{Host: "z.mailspike.net", Level: "Medium"},               // MAILSPIKE Z
	{Host: "sem.blacklist.spamhaus.org", Level: "Medium"},    // SEM BLACK
	{Host: "cbl.abuseat.org", Level: "Medium"},               // Abuseat CBL
	{Host: "dnsbl.dronebl.org", Level: "Medium"},             // DRONE BL
	{Host: "dnsbl.zapbl.net", Level: "Medium"},               // ZapBL
	{Host: "hostkarma.junkemailfilter.com", Level: "Medium"}, // Hostkarma Black
	{Host: "woodys.smtp.blacklist", Level: "Medium"},         // Woodys SMTP (hay timeout)
	{Host: "lashback.uoregon.edu", Level: "Medium"},          // LASHBACK
	{Host: "rbl.schulte.org", Level: "Medium"},               // Manitu (Schulte)
	{Host: "dnsbl.konstant.no", Level: "Medium"},             // Konstant
	{Host: "dnsbl.spfbl.net", Level: "Medium"},               // SPFBL DNSBL
	{Host: "rbl.interserver.net", Level: "Medium"},           // INTERSERVER
	{Host: "surgate.net", Level: "Medium"},                   // Surgate
	{Host: "spamsources.fabel.dk", Level: "Medium"},          // FABELSOURCES
	{Host: "dnsbl.anonmails.de", Level: "Medium"},            // Anonmails
	{Host: "dnsbl.scientificspam.net", Level: "Medium"},      // Scientific Spam
	{Host: "dnsbl.pacifier.net", Level: "Medium"},            // Pacifier
	{Host: "spamguard.leadmon.net", Level: "Medium"},         // Leadmon
	{Host: "bad.psky.me", Level: "Medium"},                   // PSky Bad

	// Low Priority RBLs
	{Host: "dnsbl-3.uceprotect.net", Level: "Low"},           // UCEPROTECT Level 3
	{Host: "backscatter.spameatingmonkey.net", Level: "Low"}, // SEM BACKSCATTER
	{Host: "tor.dan.me.uk", Level: "Low"},                    // DAN TOR
	{Host: "torexit.dan.me.uk", Level: "Low"},                // DAN TOREXIT
	{Host: "http.dnsbl.sorbs.net", Level: "Low"},             // SORBS HTTP
	{Host: "socks.dnsbl.sorbs.net", Level: "Low"},            // SORBS SOCKS
	{Host: "misc.dnsbl.sorbs.net", Level: "Low"},             // SORBS Misc
	{Host: "smtp.dnsbl.sorbs.net", Level: "Low"},             // SORBS SMTP
	{Host: "web.dnsbl.sorbs.net", Level: "Low"},              // SORBS Web
	{Host: "bl.nordspam.com", Level: "Low"},                  // Nordspam
	{Host: "all.s5h.net", Level: "Low"},                      // s5h.net
	{Host: "korea.services.net", Level: "Low"},               // SERVICESNET
	{Host: "dnsbl.cymru.com", Level: "Low"},                  // CYMRU BOGONS
	{Host: "calivent.com", Level: "Low"},                     // CALIVENT
	{Host: "rbl.redhawk.org", Level: "Low"},                  // Redhawk (DRMX)
	{Host: "dnsbl.drbl.gremlin.ru", Level: "Low"},            // DRBL Gremlin
	{Host: "dnsbl.kempt.net", Level: "Low"},                  // KEMPTBL
	{Host: "dnsbl.swinog.ch", Level: "Low"},                  // SWINOG
	{Host: "dnsbl.suomispam.net", Level: "Low"},              // Suomispam
	{Host: "relays.nether.net", Level: "Low"},                // NETHERRELAYS
	{Host: "unsure.nether.net", Level: "Low"},                // NETHERUNSURE
	{Host: "rbl.triumf.ca", Level: "Low"},                    // TRIUMF
	{Host: "hil.habeas.com", Level: "Low"},                   // HIL
	{Host: "hil2.habeas.com", Level: "Low"},                  // HIL2
}

func ResolveUDPServer(serverKey string) string {
	if s, ok := DNSServers[serverKey]; ok {
		return s
	}
	// fallback an toàn
	return "8.8.8.8:53"
}
