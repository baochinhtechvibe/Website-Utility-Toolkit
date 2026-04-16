package iana

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

var (
	// RootServerOrgs maps Root Server IPs/Hostnames to their managing organizations
	RootServerOrgs = map[string]string{
		"198.41.0.4":     "Verisign, Inc.",
		"199.9.14.201":   "University of Southern California (ISI)",
		"192.33.4.12":    "Cogent Communications",
		"199.7.91.13":    "University of Maryland",
		"192.203.230.10": "NASA (Ames Research Center)",
		"192.5.5.241":    "Internet Systems Consortium, Inc. (ISC)",
		"192.112.36.4":   "U.S. Department of Defense (NIC)",
		"198.97.190.53":  "U.S. Army (Research Lab)",
		"192.36.148.17":  "Netnod (Autonomica)",
		"192.58.128.30":  "Verisign, Inc.",
		"193.0.14.129":   "RIPE NCC",
		"199.7.83.42":    "ICANN",
		"202.12.27.33":   "WIDE Project",

		"A.ROOT-SERVERS.NET": "Verisign, Inc.",
		"B.ROOT-SERVERS.NET": "University of Southern California (ISI)",
		"C.ROOT-SERVERS.NET": "Cogent Communications",
		"D.ROOT-SERVERS.NET": "University of Maryland",
		"E.ROOT-SERVERS.NET": "NASA (Ames Research Center)",
		"F.ROOT-SERVERS.NET": "Internet Systems Consortium, Inc. (ISC)",
		"G.ROOT-SERVERS.NET": "U.S. Department of Defense (NIC)",
		"H.ROOT-SERVERS.NET": "U.S. Army (Research Lab)",
		"I.ROOT-SERVERS.NET": "Netnod (Autonomica)",
		"J.ROOT-SERVERS.NET": "Verisign, Inc.",
		"K.ROOT-SERVERS.NET": "RIPE NCC",
		"L.ROOT-SERVERS.NET": "ICANN",
		"M.ROOT-SERVERS.NET": "WIDE Project",
	}

	rdapBootstrap  sync.Map // TLD → Base RDAP URL
	tldNSBootstrap sync.Map // TLD → TLD Nameserver IP
)

// Init initializes the IANA bootstrap data
func Init() {
	go func() {
		// Initial load
		if err := FetchAndCacheRDAPBootstrap(); err != nil {
			log.Warn().Err(err).Msg("IANA RDAP Bootstrap: initial load failed")
		} else {
			// Only try TLD NS bootstrap if RDAP is loaded (needs TLD list)
			if err := FetchAndCacheTLDNSBootstrap(); err != nil {
				log.Warn().Err(err).Msg("IANA TLD NS Bootstrap: initial load failed")
			}
		}

		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			if err := FetchAndCacheRDAPBootstrap(); err != nil {
				log.Warn().Err(err).Msg("IANA RDAP Bootstrap: periodic refresh failed")
			}
			if err := FetchAndCacheTLDNSBootstrap(); err != nil {
				log.Warn().Err(err).Msg("IANA TLD NS Bootstrap: periodic refresh failed")
			}
		}
	}()
}

// FetchAndCacheRDAPBootstrap loads the IANA RDAP Bootstrap JSON
func FetchAndCacheRDAPBootstrap() error {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get("https://data.iana.org/rdap/dns.json")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var data struct {
		Services [][]json.RawMessage `json:"services"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return err
	}

	for _, service := range data.Services {
		if len(service) < 2 {
			continue
		}
		var tlds []string
		if err := json.Unmarshal(service[0], &tlds); err != nil {
			continue
		}
		var urls []string
		if err := json.Unmarshal(service[1], &urls); err != nil {
			continue
		}
		if len(urls) > 0 {
			baseURL := urls[0]
			if !strings.HasSuffix(baseURL, "/") {
				baseURL += "/"
			}
			for _, tld := range tlds {
				rdapBootstrap.Store(strings.ToLower(tld), baseURL)
			}
		}
	}
	log.Info().Msg("IANA Bootstrap: Loaded RDAP data")
	return nil
}

// FetchAndCacheTLDNSBootstrap resolves IPs for TLD nameservers
func FetchAndCacheTLDNSBootstrap() error {
	var tlds []string
	rdapBootstrap.Range(func(key, _ interface{}) bool {
		tlds = append(tlds, key.(string))
		return true
	})

	if len(tlds) == 0 {
		return fmt.Errorf("iana tld ns: no tlds available")
	}

	client := new(dns.Client)
	client.Timeout = 3 * time.Second

	for _, tld := range tlds {
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(tld), dns.TypeNS)
		msg.RecursionDesired = true

		resp, _, err := client.Exchange(msg, "8.8.8.8:53")
		if err != nil || resp == nil || len(resp.Answer) == 0 {
			continue
		}

		var nsName string
		for _, rr := range resp.Answer {
			if ns, ok := rr.(*dns.NS); ok {
				nsName = ns.Ns
				break
			}
		}
		if nsName == "" {
			continue
		}

		// Resolve IP for the NS name
		msgA := new(dns.Msg)
		msgA.SetQuestion(nsName, dns.TypeA)
		respA, _, errA := client.Exchange(msgA, "8.8.8.8:53")
		if errA == nil && respA != nil && len(respA.Answer) > 0 {
			if a, ok := respA.Answer[0].(*dns.A); ok {
				tldNSBootstrap.Store(tld, a.A.String())
			}
		}
	}
	log.Info().Msg("IANA Bootstrap: Loaded TLD Nameserver data")
	return nil
}

// GetRDAPURL returns the base RDAP URL for a TLD
func GetRDAPURL(tld string) string {
	if val, ok := rdapBootstrap.Load(strings.ToLower(tld)); ok {
		return val.(string)
	}
	return ""
}

// GetTLDNS returns the IP of a TLD nameserver
func GetTLDNS(tld string) string {
	if val, ok := tldNSBootstrap.Load(strings.ToLower(tld)); ok {
		return val.(string)
	}
	return ""
}

// GetAuthoritativeRDAPServer returns the record-specific RDAP URL
func GetAuthoritativeRDAPServer(domain string) string {
	parts := strings.Split(strings.ToLower(domain), ".")
	if len(parts) < 2 {
		return ""
	}
	tld := parts[len(parts)-1]
	baseURL := GetRDAPURL(tld)
	if baseURL != "" {
		return baseURL + "domain/" + domain
	}
	return ""
}
