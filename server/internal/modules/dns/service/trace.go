package dns

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
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
	Timeout         time.Duration
	cacheMu         sync.RWMutex
	delegationCache map[string][]models.NameserverInfo
}

func NewTraceResolver(timeout time.Duration) *TraceResolver {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &TraceResolver{
		Timeout:         timeout,
		delegationCache: make(map[string][]models.NameserverInfo),
	}
}

func getRandomRoot() (string, string) {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(RootServers))))
	ip := RootServers[n.Int64()]
	return ip, RootServerNames[ip]
}

func (tr *TraceResolver) DoTrace(domain string, qtype uint16) ([]models.DNSRecord, []models.TraceStep, error) {
	var logs []models.TraceStep
	var allRecords []models.DNSRecord

	ctx, cancel := context.WithTimeout(context.Background(), tr.Timeout)
	defer cancel()

	client := &dns.Client{
		Net:     "udp",
		Timeout: 3 * time.Second,
	}

	currentQName := dns.Fqdn(domain)
	cnameVisited := make(map[string]bool)

	for cnameHops := 0; cnameHops < 5; cnameHops++ {
		if ctx.Err() != nil {
			return nil, logs, fmt.Errorf("trace timeout exceeded")
		}

		if cnameVisited[currentQName] {
			return allRecords, logs, fmt.Errorf("CNAME loop detected at %s", currentQName)
		}
		cnameVisited[currentQName] = true

		// Try to find the closest ancestor in the cache
		var currentNS []models.NameserverInfo
		var startingZone string

		labels := dns.SplitDomainName(currentQName)
		for i := 0; i < len(labels); i++ {
			zone := strings.Join(labels[i:], ".") + "."
			tr.cacheMu.RLock()
			cached, exists := tr.delegationCache[zone]
			tr.cacheMu.RUnlock()
			if exists {
				currentNS = cached
				startingZone = zone
				break
			}
		}

		if len(currentNS) == 0 {
			// Default to a random root server candidate
			rootIP, rootName := getRandomRoot()
			currentNS = []models.NameserverInfo{
				{Nameserver: rootName, IP: rootIP},
			}
			startingZone = "."
		} else if cnameHops == 0 {
			logs = append(logs, models.TraceStep{
				Message: fmt.Sprintf("Using cached delegation for zone %s", startingZone),
			})
		}

		visitedIPs := make(map[string]bool)
		foundAnswer := false

		// Inner loop for delegation trace
		for {
			if ctx.Err() != nil {
				return nil, logs, fmt.Errorf("trace timeout exceeded")
			}

			if len(currentNS) == 0 {
				logs = append(logs, models.TraceStep{Message: "No more nameservers to query. Trace aborted."})
				break
			}

			var resp *dns.Msg
			var err error
			var lastNS models.NameserverInfo
			var duration int64

			// Try nameservers in the current delegation until one responds
			success := false
			for _, ns := range currentNS {
				if ns.IP == "" {
					ips, _ := net.LookupHost(ns.Nameserver)
					if len(ips) > 0 {
						ns.IP = ips[0]
					} else {
						continue
					}
				}

				if visitedIPs[ns.IP] {
					continue
				}
				visitedIPs[ns.IP] = true

				msg := new(dns.Msg)
				msg.SetQuestion(currentQName, qtype)
				msg.RecursionDesired = false
				msg.SetEdns0(4096, true)

				start := time.Now()
				resp, _, err = client.ExchangeContext(ctx, msg, net.JoinHostPort(ns.IP, "53"))
				duration = time.Since(start).Milliseconds()
				lastNS = ns

				if err == nil {
					success = true
					break
				} else {
					logs = append(logs, models.TraceStep{
						ServerName: ns.Nameserver,
						ServerIP:   ns.IP,
						Message:    fmt.Sprintf("Error querying %s: %v. Trying next NS...", ns.Nameserver, err),
					})
				}
			}

			if !success {
				return nil, logs, fmt.Errorf("failed to get response from any authoritative nameservers")
			}

			// Log successful query
			targetTypeStr := dns.TypeToString[qtype]
			domainNoDot := strings.TrimSuffix(currentQName, ".")
			logMsg := fmt.Sprintf("Searching for %s. %s record at %s. [%s] ...took %d ms", domainNoDot, targetTypeStr, lastNS.Nameserver, lastNS.IP, duration)
			logs = append(logs, models.TraceStep{
				ServerName: lastNS.Nameserver,
				ServerIP:   lastNS.IP,
				DurationMs: duration,
				Message:    logMsg,
			})

			// 1. Check Answer section
			if len(resp.Answer) > 0 {
				foundAnswer = true
				var currentHopsRecords []models.DNSRecord
				var cnameTarget string

				for _, ans := range resp.Answer {
					rec := models.DNSRecord{
						Domain: currentQName,
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
						cnameTarget = dns.Fqdn(rr.Target)
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
					currentHopsRecords = append(currentHopsRecords, rec)
					logs = append(logs, models.TraceStep{Message: fmt.Sprintf("%s record found: %s", rec.Type, valStr)})
				}

				allRecords = append(allRecords, currentHopsRecords...)

				// Task 4: Logical refactor for CNAME following (A/AAAA only)
				// If target type (A/AAAA) wasn't found but a CNAME was, follow the redirect.
				hasTargetType := false
				targetType := dns.TypeToString[qtype]
				for _, r := range currentHopsRecords {
					if r.Type == targetType {
						hasTargetType = true
						break
					}
				}

				if !hasTargetType && cnameTarget != "" && (qtype == dns.TypeA || qtype == dns.TypeAAAA) {
					logs = append(logs, models.TraceStep{
						Message: fmt.Sprintf("\nTarget record not found, following CNAME redirect to %s...", strings.TrimSuffix(cnameTarget, ".")),
					})
					currentQName = cnameTarget
					break // Break inner loop to restart trace with the new target name
				}

				logs = append(logs, models.TraceStep{Message: fmt.Sprintf("\nTrace complete: %d record(s) found.", len(allRecords))})
				return allRecords, logs, nil
			}

			// Check for NXDOMAIN or other errors
			if resp.Rcode != dns.RcodeSuccess {
				statusMsg := dns.RcodeToString[resp.Rcode]
				if resp.Rcode == dns.RcodeNameError {
					statusMsg = "No such host " + domainNoDot
				}
				logs = append(logs, models.TraceStep{Message: fmt.Sprintf("Nameserver %s reports: %s", lastNS.Nameserver, statusMsg)})
				return allRecords, logs, nil
			}

			// 2. Check Authority for Delegation
			if len(resp.Ns) > 0 {
				var nextCandidates []models.NameserverInfo
				nsMap := make(map[string]string)

				for _, extra := range resp.Extra {
					if a, ok := extra.(*dns.A); ok {
						nsMap[strings.TrimSuffix(a.Hdr.Name, ".")] = a.A.String()
					}
				}

				for _, rr := range resp.Ns {
					if ns, ok := rr.(*dns.NS); ok {
						nsNameFound := strings.TrimSuffix(ns.Ns, ".")
						nextCandidates = append(nextCandidates, models.NameserverInfo{
							Nameserver: nsNameFound,
							IP:         nsMap[nsNameFound],
						})
					}
				}

				if len(nextCandidates) == 0 {
					isSOA := false
					for _, rr := range resp.Ns {
						if _, ok := rr.(*dns.SOA); ok {
							isSOA = true
							break
						}
					}
					if isSOA {
						logs = append(logs, models.TraceStep{Message: fmt.Sprintf("Nameserver %s reports: No %s records for %s", lastNS.Nameserver, targetTypeStr, domainNoDot)})
					} else {
						logs = append(logs, models.TraceStep{Message: "Authority section returned but no delegation found. Trace stopped."})
					}
					return allRecords, logs, nil
				}

				currentNS = nextCandidates

				// Task 4: Update per-request cache
				if len(resp.Ns) > 0 {
					if ns, ok := resp.Ns[0].(*dns.NS); ok {
						zone := ns.Hdr.Name
						tr.cacheMu.Lock()
						tr.delegationCache[zone] = nextCandidates
						tr.cacheMu.Unlock()
					}
				}
				continue
			}

			logs = append(logs, models.TraceStep{Message: fmt.Sprintf("Nameserver %s reports: No %s records found (Incomplete delegation).", lastNS.Nameserver, targetTypeStr)})
			return allRecords, logs, nil
		}

		if foundAnswer {
			// This means we hit a CNAME and broke out of the inner loop
			continue
		}
		break
	}

	return allRecords, logs, nil
}

// DiscoverAuthorities traces from Root to find the authoritative nameservers for a domain.
// It returns the NS records that the PARENT zone (Registry) delegates to — not the zone's own NS.
// Strategy: keep track of the "last delegation" seen, and when we get an ANSWER (zone-self),
// return the last delegation instead — that gives ns1/ns2, not ns3/ns4.
func (tr *TraceResolver) DiscoverAuthorities(domain string) ([]models.NameserverInfo, error) {
	domain = dns.Fqdn(domain)
	targetDomain := strings.TrimSuffix(domain, ".")

	ctx, cancel := context.WithTimeout(context.Background(), tr.Timeout)
	defer cancel()

	client := &dns.Client{
		Net:     "udp",
		Timeout: 2 * time.Second,
	}

	// Try to find the closest ancestor in the cache
	var currentNS []models.NameserverInfo
	labels := dns.SplitDomainName(domain)
	for i := 0; i < len(labels); i++ {
		zone := strings.Join(labels[i:], ".") + "."
		tr.cacheMu.RLock()
		cached, exists := tr.delegationCache[zone]
		tr.cacheMu.RUnlock()
		if exists {
			currentNS = cached
			break
		}
	}

	if len(currentNS) == 0 {
		rootIP, rootName := getRandomRoot()
		currentNS = []models.NameserverInfo{
			{Nameserver: rootName, IP: rootIP},
		}
	}

	visited := make(map[string]bool)
	var lastDelegation []models.NameserverInfo

	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		if len(currentNS) == 0 {
			break
		}

		var resp *dns.Msg
		var err error
		var success bool

		// Multiple NS fallback logic
		for _, ns := range currentNS {
			if ns.IP == "" {
				ips, _ := net.LookupHost(ns.Nameserver)
				if len(ips) > 0 {
					ns.IP = ips[0]
				} else {
					continue
				}
			}

			if visited[ns.IP] {
				continue
			}
			visited[ns.IP] = true

			msg := new(dns.Msg)
			msg.SetQuestion(domain, dns.TypeNS)
			msg.RecursionDesired = false
			msg.SetEdns0(4096, true)

			resp, _, err = client.ExchangeContext(ctx, msg, net.JoinHostPort(ns.IP, "53"))
			if err == nil {
				success = true
				break
			}
		}

		if !success {
			if len(lastDelegation) > 0 {
				return lastDelegation, nil
			}
			return nil, fmt.Errorf("failed to discover authorities for %s", domain)
		}

		// If we got an ANSWER section (zone answering about itself)
		if len(resp.Answer) > 0 {
			if len(lastDelegation) > 0 {
				return lastDelegation, nil
			}
			// Fallback: return what they said about themselves
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

		// Delegation handling
		if len(resp.Ns) > 0 {
			var nextCandidates []models.NameserverInfo
			var delegatedZone string
			nsMap := make(map[string]string)

			for _, extra := range resp.Extra {
				if a, ok := extra.(*dns.A); ok {
					nsMap[strings.TrimSuffix(a.Hdr.Name, ".")] = a.A.String()
				}
			}

			for _, rr := range resp.Ns {
				if ns, ok := rr.(*dns.NS); ok {
					nsNameFound := strings.TrimSuffix(ns.Ns, ".")
					hdrZone := strings.TrimSuffix(ns.Hdr.Name, ".")
					nextCandidates = append(nextCandidates, models.NameserverInfo{
						Nameserver: nsNameFound,
						IP:         nsMap[nsNameFound],
						TTL:        ns.Header().Ttl,
						Domain:     hdrZone,
					})
					if delegatedZone == "" {
						delegatedZone = hdrZone
					}
				}
			}

			// Registry check: if parent delegates exactly our target domain
			if strings.EqualFold(delegatedZone, targetDomain) && len(nextCandidates) > 0 {
				// Task 9: Also cache the final authoritative nameservers for the domain itself
				tr.cacheMu.Lock()
				tr.delegationCache[domain] = nextCandidates
				tr.cacheMu.Unlock()
				return nextCandidates, nil
			}

			// Intermediate delegation: update lastDelegation and continue
			if len(nextCandidates) > 0 {
				lastDelegation = nextCandidates
				// Cache it
				if ns, ok := resp.Ns[0].(*dns.NS); ok {
					zone := ns.Hdr.Name
					tr.cacheMu.Lock()
					tr.delegationCache[zone] = nextCandidates
					tr.cacheMu.Unlock()
				}
			}
			currentNS = nextCandidates
			continue
		}
		break
	}

	if len(lastDelegation) > 0 {
		return lastDelegation, nil
	}
	return nil, fmt.Errorf("no authoritative nameservers found for %s", domain)
}


