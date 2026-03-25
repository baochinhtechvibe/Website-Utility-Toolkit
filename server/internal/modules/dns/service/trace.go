package dns

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"tools.bctechvibe.com/server/internal/modules/dns/models"
)

var RootServers = []string{
	"198.41.0.4",     // A.ROOT-SERVERS.NET
	"199.9.14.201",   // B.ROOT-SERVERS.NET
	"192.33.4.12",    // C.ROOT-SERVERS.NET
	"199.7.91.13",    // D.ROOT-SERVERS.NET
	"192.203.230.10", // E.ROOT-SERVERS.NET
	"192.5.5.241",    // F.ROOT-SERVERS.NET
	"192.112.36.4",   // G.ROOT-SERVERS.NET
	"198.97.190.53",  // H.ROOT-SERVERS.NET
	"192.36.148.17",  // I.ROOT-SERVERS.NET
	"192.58.128.30",  // J.ROOT-SERVERS.NET
	"193.0.14.129",   // K.ROOT-SERVERS.NET
	"199.7.83.42",    // L.ROOT-SERVERS.NET
	"202.12.27.33",   // M.ROOT-SERVERS.NET
}

var RootServerNames = map[string]string{
	"198.41.0.4":     "A.ROOT-SERVERS.NET",
	"199.9.14.201":   "B.ROOT-SERVERS.NET",
	"192.33.4.12":    "C.ROOT-SERVERS.NET",
	"199.7.91.13":    "D.ROOT-SERVERS.NET",
	"192.203.230.10": "E.ROOT-SERVERS.NET",
	"192.5.5.241":    "F.ROOT-SERVERS.NET",
	"192.112.36.4":   "G.ROOT-SERVERS.NET",
	"198.97.190.53":  "H.ROOT-SERVERS.NET",
	"192.36.148.17":  "I.ROOT-SERVERS.NET",
	"192.58.128.30":  "J.ROOT-SERVERS.NET",
	"193.0.14.129":   "K.ROOT-SERVERS.NET",
	"199.7.83.42":    "L.ROOT-SERVERS.NET",
	"202.12.27.33":   "M.ROOT-SERVERS.NET",
}

type TraceResolver struct {
	Timeout time.Duration
}

func NewTraceResolver(timeout time.Duration) *TraceResolver {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &TraceResolver{Timeout: timeout}
}

func getRandomRoot() (string, string) {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(RootServers))))
	ip := RootServers[n.Int64()]
	return ip, RootServerNames[ip]
}

func (tr *TraceResolver) DoTrace(domain string, qtype uint16) ([]models.DNSRecord, []models.TraceStep, error) {
	domain = dns.Fqdn(domain)
	var logs []models.TraceStep
	var records []models.DNSRecord

	// Pick a random root server to start
	nsIP, nsName := getRandomRoot()

	ctx, cancel := context.WithTimeout(context.Background(), tr.Timeout)
	defer cancel()

	client := &dns.Client{
		Net:     "udp",
		Timeout: 3 * time.Second, // Increased timeout per hop
	}

	visited := make(map[string]bool)

	for {
		if ctx.Err() != nil {
			return nil, logs, fmt.Errorf("trace timeout exceeded")
		}

		if visited[nsIP] {
			logs = append(logs, models.TraceStep{
				ServerName: nsName, ServerIP: nsIP, Message: "Loop detected, aborting trace.",
			})
			break
		}
		visited[nsIP] = true

		msg := new(dns.Msg)
		msg.SetQuestion(domain, qtype)
		// Root iteration -> NO recursion
		msg.RecursionDesired = false

		start := time.Now()
		resp, _, err := client.ExchangeContext(ctx, msg, net.JoinHostPort(nsIP, "53"))
		duration := time.Since(start).Milliseconds()

		// Descriptive log message
		targetTypeStr := dns.TypeToString[qtype]
		domainNoDot := strings.TrimSuffix(domain, ".")
		logMsg := fmt.Sprintf("Searching for %s. %s record at %s. [%s] ...took %d ms", domainNoDot, targetTypeStr, nsName, nsIP, duration)
		logs = append(logs, models.TraceStep{
			ServerName: nsName,
			ServerIP:   nsIP,
			DurationMs: duration,
			Message:    logMsg,
		})

		if err != nil {
			logs = append(logs, models.TraceStep{ServerName: nsName, ServerIP: nsIP, Message: fmt.Sprintf("Error querying %s: %v", nsName, err)})
			return nil, logs, err
		}

		// 1. Check Answer section
		if len(resp.Answer) > 0 {
			// Found answers!
			for _, ans := range resp.Answer {
				rec := models.DNSRecord{
					Domain: domain,
					TTL:    ans.Header().Ttl,
				}
				valStr := ""
				switch rr := ans.(type) {
				case *dns.A:
					rec.Type = "A"
					rec.Address = rr.A.String()
					valStr = rec.Address
				case *dns.AAAA:
					rec.Type = "AAAA"
					rec.Address = rr.AAAA.String()
					valStr = rec.Address
				case *dns.CNAME:
					rec.Type = "CNAME"
					rec.Value = strings.TrimSuffix(rr.Target, ".")
					valStr = rec.Value
				case *dns.MX:
					rec.Type = "MX"
					rec.Priority = rr.Preference
					rec.Exchange = strings.TrimSuffix(rr.Mx, ".")
					valStr = fmt.Sprintf("%s (Priority: %d)", rec.Exchange, rec.Priority)
				case *dns.NS:
					rec.Type = "NS"
					rec.Nameserver = strings.TrimSuffix(rr.Ns, ".")
					valStr = rec.Nameserver
				case *dns.TXT:
					rec.Type = "TXT"
					rec.Value = strings.Join(rr.Txt, " ")
					valStr = rec.Value
				case *dns.PTR:
					rec.Type = "PTR"
					rec.Value = strings.TrimSuffix(rr.Ptr, ".")
					valStr = rec.Value
				default:
					continue
				}
				records = append(records, rec)

				// Log each found record like DNS Watch
				logs = append(logs, models.TraceStep{
					Message: fmt.Sprintf("%s record found: %s", rec.Type, valStr),
				})
			}

			logs = append(logs, models.TraceStep{
				Message: fmt.Sprintf("\nTrace complete: %d record(s) found.", len(records)),
			})
			return records, logs, nil
		}

		// Check for NXDOMAIN or other errors at authoritative level
		if resp.Rcode != dns.RcodeSuccess {
			statusMsg := dns.RcodeToString[resp.Rcode]
			if resp.Rcode == dns.RcodeNameError {
				statusMsg = "No such host " + domainNoDot
			}
			logs = append(logs, models.TraceStep{
				Message: fmt.Sprintf("Nameserver %s reports: %s", nsName, statusMsg),
			})
			return records, logs, nil
		}

		// 2. No Answer -> Check Authority for Delegation (NS records for the next zone)
		if len(resp.Ns) > 0 {
			var nextNsName string
			// Pick the first NS record in the delegation
			for _, rr := range resp.Ns {
				if ns, ok := rr.(*dns.NS); ok {
					nextNsName = strings.TrimSuffix(ns.Ns, ".")
					break
				}
			}

			if nextNsName == "" {
				// If no NS but it's an authoritative empty response (SOA in Ns)
				var isSOA bool
				for _, rr := range resp.Ns {
					if _, ok := rr.(*dns.SOA); ok {
						isSOA = true
						break
					}
				}
				if isSOA {
					logs = append(logs, models.TraceStep{
						Message: fmt.Sprintf("Nameserver %s reports: No %s records for %s", nsName, targetTypeStr, domainNoDot),
					})
				} else {
					logs = append(logs, models.TraceStep{Message: "Authority section returned but no delegation found. Trace stopped."})
				}
				return records, logs, nil
			}

			// Find glue IP in Extra
			var nextNsIP string
			for _, extra := range resp.Extra {
				if a, ok := extra.(*dns.A); ok {
					if strings.TrimSuffix(a.Hdr.Name, ".") == nextNsName {
						nextNsIP = a.A.String()
						break
					}
				}
			}

			// If no glue record, resolve it silently
			if nextNsIP == "" {
				ips, err := net.LookupHost(nextNsName)
				if err == nil && len(ips) > 0 {
					nextNsIP = ips[0]
				} else {
					logs = append(logs, models.TraceStep{Message: fmt.Sprintf("Failed to resolve authoritative nameserver %s. Trace aborted.", nextNsName)})
					return records, logs, nil
				}
			}

			// Descend to the next NS
			nsName = nextNsName
			nsIP = nextNsIP
			continue
		}


		// No Answer and No Authority
		logs = append(logs, models.TraceStep{Message: fmt.Sprintf("Nameserver %s reports: No %s records found (Incomplete delegation).", nsName, targetTypeStr)})
		break
	}

	return records, logs, nil
}

// DiscoverAuthorities traces from Root to find the authoritative nameservers for a domain.
// It returns the NS records that the PARENT zone (Registry) delegates to — not the zone's own NS.
// Strategy: keep track of the "last delegation" seen, and when we get an ANSWER (zone-self),
// return the last delegation instead — that gives ns1/ns2, not ns3/ns4.
func (tr *TraceResolver) DiscoverAuthorities(domain string) ([]models.NameserverInfo, error) {
	domain = dns.Fqdn(domain)
	nsIP, _ := getRandomRoot()

	ctx, cancel := context.WithTimeout(context.Background(), tr.Timeout)
	defer cancel()

	client := &dns.Client{
		Net:     "udp",
		Timeout: 2 * time.Second,
	}

	visited := make(map[string]bool)
	targetDomain := strings.TrimSuffix(domain, ".")

	// Keep the last delegation seen from an "intermediate" server.
	// When we finally get an ANSWER (self-referential), return this instead.
	var lastDelegation []models.NameserverInfo

	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		if visited[nsIP] {
			if len(lastDelegation) > 0 {
				return lastDelegation, nil
			}
			return nil, fmt.Errorf("loop detected during discovery")
		}
		visited[nsIP] = true

		msg := new(dns.Msg)
		msg.SetQuestion(domain, dns.TypeNS)
		msg.RecursionDesired = false

		resp, _, err := client.ExchangeContext(ctx, msg, net.JoinHostPort(nsIP, "53"))
		if err != nil {
			if len(lastDelegation) > 0 {
				return lastDelegation, nil
			}
			return nil, err
		}

		// If we got an ANSWER section:
		// This is the zone's authoritative server answering about itself (ns3/ns4 self-referential).
		// We want what the PARENT said, so return lastDelegation (which holds ns1/ns2 from parent).
		if len(resp.Answer) > 0 {
			if len(lastDelegation) > 0 {
				// Return parent delegation = Registry-level NS
				return lastDelegation, nil
			}
			// Fallback: no prior delegation found, return these Answer records
			var nsInfos []models.NameserverInfo
			for _, ans := range resp.Answer {
				if ns, ok := ans.(*dns.NS); ok {
					nsInfos = append(nsInfos, models.NameserverInfo{
						Nameserver: strings.TrimSuffix(ns.Ns, "."),
						TTL:        ns.Header().Ttl,
						Domain:     strings.TrimSuffix(ns.Hdr.Name, "."),
					})
				}
			}
			if len(nsInfos) > 0 {
				return nsInfos, nil
			}
		}

		// If we got Authority (delegation):
		if len(resp.Ns) > 0 {
			var nsRecords []models.NameserverInfo
			var nextName string
			var nextIP string
			var delegatedZone string

			for _, rr := range resp.Ns {
				if ns, ok := rr.(*dns.NS); ok {
					nsNameFound := strings.TrimSuffix(ns.Ns, ".")
					hdrZone := strings.TrimSuffix(ns.Hdr.Name, ".")
					nsRecords = append(nsRecords, models.NameserverInfo{
						Nameserver: nsNameFound,
						TTL:        ns.Header().Ttl,
						Domain:     hdrZone,
					})
					if delegatedZone == "" {
						delegatedZone = hdrZone
					}
					if nextName == "" {
						nextName = nsNameFound
					}
				}
			}

			// If this delegation is exactly for our target domain — these ARE the registry NS.
			// (e.g., TLD .vn directly delegates thehaf.io.vn. → ns1/ns2)
			if strings.EqualFold(delegatedZone, targetDomain) && len(nsRecords) > 0 {
				return nsRecords, nil
			}

			// Otherwise, this is an intermediate delegation (e.g., Root → .vn)
			// Save as "last delegation" and descend to next NS
			if len(nsRecords) > 0 {
				lastDelegation = nsRecords
			}

			if nextName == "" {
				if len(lastDelegation) > 0 {
					return lastDelegation, nil
				}
				return nil, fmt.Errorf("incomplete delegation")
			}

			// Find glue
			for _, extra := range resp.Extra {
				if a, ok := extra.(*dns.A); ok {
					if strings.TrimSuffix(a.Hdr.Name, ".") == nextName {
						nextIP = a.A.String()
						break
					}
				}
			}

			if nextIP == "" {
				ips, _ := net.LookupHost(nextName)
				if len(ips) > 0 {
					nextIP = ips[0]
				} else {
					if len(lastDelegation) > 0 {
						return lastDelegation, nil
					}
					return nil, fmt.Errorf("failed to resolve: %s", nextName)
				}
			}

			nsIP = nextIP
			continue
		}

		break
	}

	if len(lastDelegation) > 0 {
		return lastDelegation, nil
	}
	return nil, fmt.Errorf("no authoritative nameservers found")
}


