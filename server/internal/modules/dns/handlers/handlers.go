// ============================================
// FILE: internal/handlers/handlers.go
// HTTP handlers - WITH SUBDOMAIN DETECTION
// ============================================
package handlers

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	// "time"

	"time"

	"tools.bctechvibe.com/server/internal/modules/dns/models"
	dns "tools.bctechvibe.com/server/internal/modules/dns/service"
	"tools.bctechvibe.com/server/internal/platform/cache"
	"tools.bctechvibe.com/server/internal/platform/validator"
	responseAPI "tools.bctechvibe.com/server/internal/response"

	"github.com/gin-gonic/gin"
	dnslib "github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

var dnsCache = cache.NewMemoryCache(30 * time.Minute)

func sendResponse(c *gin.Context, req *models.DNSLookupRequest, res *models.DNSLookupResponse) {
	if res.Success {
		cacheKey := req.Hostname + ":" + req.Type
		if !req.TraceRoot {
			dnsCache.Set(cacheKey, res.Data)
		}
		if res.Message != "" {
			responseAPI.SuccessWithMessage(c, res.Data, res.Message)
		} else {
			responseAPI.Success(c, res.Data, false, time.Now())
		}
	} else {
		// return 200 normal JSON for error conditions that shouldn't be 400
		c.JSON(http.StatusOK, res)
	}
}

// ========================================
// HELPER FUNCTIONS
// ========================================

// Helper function to check if input is an IP address
func isIPAddress(input string) bool {
	return net.ParseIP(input) != nil
}

// Helper function to check if input is IPv4
func isIPv4(input string) bool {
	ip := net.ParseIP(input)
	return ip != nil && ip.To4() != nil
}

// Helper function to check if input is IPv6
func isIPv6(input string) bool {
	ip := net.ParseIP(input)
	return ip != nil && ip.To4() == nil && strings.Contains(input, ":")
}

// Helper to get IP version string
func getIPVersion(ip string) string {
	if isIPv4(ip) {
		return "IPv4"
	}
	if isIPv6(ip) {
		return "IPv6"
	}
	return "Unknown"
}

// ✅ NEW: Check if hostname is subdomain using Mozilla PSL
func isSubdomain(hostname string) bool {
	// Remove trailing dot
	hostname = strings.TrimSuffix(hostname, ".")

	// Get eTLD+1 (effective TLD + 1 label)
	// Example: admin.example.com → example.com
	//          example.co.uk → example.co.uk
	etldPlus1, err := publicsuffix.EffectiveTLDPlusOne(hostname)
	if err != nil {
		// If error (invalid domain), assume not subdomain
		return false
	}

	// If hostname != eTLD+1, it's a subdomain
	// Example: admin.example.com != example.com → true (subdomain)
	//          example.com == example.com → false (not subdomain)
	return hostname != etldPlus1
}

// Normalize hostname: strip http/https, port, path, trailing slash
func normalizeHostname(input string) string {
	input = strings.TrimSpace(input)

	if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
		if u, err := url.Parse(input); err == nil && u.Host != "" {
			input = u.Host
		}
	}

	// Remove port if any (example.com:8080)
	if host, _, err := net.SplitHostPort(input); err == nil {
		input = host
	}

	// Remove trailing slash
	input = strings.TrimSuffix(input, "/")

	return input
}

// ========================================
// MAIN HANDLER
// ========================================

func HandleDNSLookup(c *gin.Context) {
	var req models.DNSLookupRequest

	// ✅ Bind JSON FIRST
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Dữ liệu yêu cầu không hợp lệ",
		})
		return
	}

	// ✅ Normalize hostname AFTER bind
	req.Hostname = normalizeHostname(req.Hostname)

	// ✅ Validate input syntax (allow resolve to any IP for DNS tool)
	valRes := validator.ValidateSyntax(req.Hostname)
	if !valRes.Valid {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": valRes.ErrorMsg,
		})
		return
	}

	// ✅ Caching interception
	cacheKey := req.Hostname + ":" + req.Type
	if !req.BypassCache && !req.TraceRoot {
		if data, fetchedAt, found := dnsCache.Get(cacheKey); found {
			responseAPI.Success(c, data, true, fetchedAt)
			return
		}
	} else {
		dnsCache.Delete(cacheKey)
	}

	// Initialize empty Response object
	var response models.DNSLookupResponse
	response.Success = true
	response.Data.Query.Hostname = req.Hostname
	response.Data.Query.Type = req.Type

	serverKey := "waterfall" // Abstract concept of the pipeline

	if !isIPAddress(req.Hostname) {
		response.Data.Query.IsSubdomain = isSubdomain(req.Hostname)
	}

	if req.TraceRoot {
		handleTraceRootLookup(c, &req, &response)
		return
	}

	switch req.Type {
	case "PTR":
		handlePTRLookup(c, serverKey, &req, &response)
	case "DNSSEC":
		handleDNSSECLookup(c, serverKey, &req, &response)
	case "BLACKLIST":
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Use /dns/blacklist-stream instead",
		})
	case "ALL":
		handleAllRecordsV2(c, serverKey, &req, &response)
	default:
		handleSpecificRecord(c, serverKey, &req, &response)
	}
}

func handleTraceRootLookup(c *gin.Context, req *models.DNSLookupRequest, response *models.DNSLookupResponse) {
	fqdn := dnslib.Fqdn(req.Hostname)
	originalDomain := strings.TrimSuffix(fqdn, ".")

	if !validator.IsValidDomain(originalDomain) {
		response.Success = false
		response.Message = "Tên miền không hợp lệ!"
		c.JSON(http.StatusBadRequest, response)
		return
	}

	response.Data.Query.IsSubdomain = isSubdomain(originalDomain)

	// Fetch canonical NS records first for better UX
	apexDomain := originalDomain
	if etld, err := publicsuffix.EffectiveTLDPlusOne(originalDomain); err == nil {
		apexDomain = etld
	}
	apexFQDN := dnslib.Fqdn(apexDomain)

	// Always seed Nameservers for better UX (NS always at top)
	// EXCEPT if the user specifically asked for NS only (in which case it goes to Records)
	if req.Type != "NS" {
		tracer := dns.NewTraceResolver(10 * time.Second)
		nsRecords, err := tracer.DiscoverAuthorities(originalDomain)
		if err == nil {
			for _, ns := range nsRecords {
				response.Data.Nameservers = append(response.Data.Nameservers, models.NameserverInfo{
					Nameserver: ns.Nameserver,
					TTL:        ns.TTL,
					Domain:     ns.Domain,
				})
			}
		} else {
			// Fallback to public DNS if trace fails
			nsRecordsPub, _ := dns.QueryDNS(apexFQDN, dnslib.TypeNS)
			for _, record := range nsRecordsPub {
				if nsRec, ok := record.(models.DNSRecord); ok && nsRec.Type == "NS" {
					response.Data.Nameservers = append(response.Data.Nameservers, models.NameserverInfo{
						Nameserver: strings.TrimSuffix(nsRec.Nameserver, "."),
						TTL:        nsRec.TTL,
						Domain:     strings.TrimSuffix(apexDomain, "."),
					})
				}
			}
		}
	}

	// Determine types to trace
	var types []uint16
	switch req.Type {
	case "A":
		types = []uint16{dnslib.TypeA}
	case "AAAA":
		types = []uint16{dnslib.TypeAAAA}
	case "NS":
		types = []uint16{dnslib.TypeNS}
	case "MX":
		types = []uint16{dnslib.TypeMX}
	case "CNAME":
		types = []uint16{dnslib.TypeCNAME}
	case "TXT":
		types = []uint16{dnslib.TypeTXT}
	case "ALL":
		types = []uint16{dnslib.TypeA, dnslib.TypeAAAA, dnslib.TypeMX, dnslib.TypeTXT, dnslib.TypeNS, dnslib.TypeCNAME}
	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Không thể Root Trace loại bản ghi này",
		})
		return
	}

	tracer := dns.NewTraceResolver(15 * time.Second)
	var allRecords []models.DNSRecord
	var finalLogs []models.TraceStep
	var finalErr error

	// Map to track unique records and avoid duplicates
	seenRecords := make(map[string]bool)

	// Seed seenRecords with existing Nameservers to avoid trace duplicates showing up in Records
	for _, ns := range response.Data.Nameservers {
		key := fmt.Sprintf("%s:NS:%s", ns.Domain, ns.Nameserver)
		seenRecords[key] = true
	}

	for i, t := range types {
		records, logs, err := tracer.DoTrace(originalDomain, t)
		if i == 0 {
			finalLogs = logs
			finalErr = err
		}

		for _, rec := range records {
			// Normalize for deduplication key
			cleanDomain := strings.TrimSuffix(rec.Domain, ".")
			cleanValue := ""
			if rec.Type == "NS" {
				cleanValue = strings.TrimSuffix(rec.Nameserver, ".")
			} else if rec.Type == "A" || rec.Type == "AAAA" {
				cleanValue = rec.Address
			} else if rec.Type == "MX" {
				cleanValue = fmt.Sprintf("%s:%d", strings.TrimSuffix(rec.Exchange, "."), rec.Priority)
			} else {
				cleanValue = strings.TrimSuffix(rec.Value, ".")
			}

			key := fmt.Sprintf("%s:%s:%s", cleanDomain, rec.Type, cleanValue)

			if seenRecords[key] {
				continue
			}
			seenRecords[key] = true


			// IF record is NS and we are NOT in NS-only mode:
			// Only add to Nameservers if Registry discovery failed (Nameservers list is empty).
			// This prevents Child Zone NS records from overwriting the Registry-level ones.
			if rec.Type == "NS" && req.Type != "NS" {
				if len(response.Data.Nameservers) == 0 {
					response.Data.Nameservers = append(response.Data.Nameservers, models.NameserverInfo{
						Nameserver: cleanValue,
						TTL:        rec.TTL,
						Domain:     cleanDomain,
					})
				}
				// else: Registry NS already populated — skip Child Zone NS records
			} else {
				allRecords = append(allRecords, rec)
			}

		}
	}

	var apiRecords []interface{}
	for i := range allRecords {
		rec := allRecords[i]
		// Normalize for UI consistency
		rec.Domain = strings.TrimSuffix(rec.Domain, ".")
		if rec.Type == "A" || rec.Type == "AAAA" {
			dns.EnrichIPInfoByString(&rec, rec.Address)
		}
		apiRecords = append(apiRecords, rec)
	}

	// Final normalization for Nameservers if any
	for i := range response.Data.Nameservers {
		response.Data.Nameservers[i].Domain = strings.TrimSuffix(response.Data.Nameservers[i].Domain, ".")
	}

	response.Success = true
	response.Data.Records = apiRecords
	response.Data.TraceLogs = finalLogs

	if req.Type == "ALL" && len(finalLogs) > 0 {
		for j := len(finalLogs) - 1; j >= 0; j-- {
			if strings.Contains(finalLogs[j].Message, "record(s) found") {
				finalLogs[j].Message = fmt.Sprintf("\n%d record(s) found across all types.", len(apiRecords))
				break
			}
		}
	}

	if len(apiRecords) == 0 && finalErr == nil {
		if len(finalLogs) > 0 {
			lastIdx := len(finalLogs) - 1
			lastMsg := finalLogs[lastIdx].Message

			// ✅ NEW: Custom formatting for "No records" trace
			// Pattern: "Nameserver [ns] reports: [msg]"
			if strings.Contains(lastMsg, "reports:") {
				// Remove the report line from TraceLogs to keep it technical
				response.Data.TraceLogs = finalLogs[:lastIdx]

				// Translate the message for the Error Card
				// Example: "Nameserver ns1.matbao.vn reports: No A records for meowtopia.com.vn"
				msg := strings.TrimSpace(lastMsg)
				msg = strings.Replace(msg, " reports: ", " báo cáo: ", 1)
				msg = strings.Replace(msg, "No such host ", "Không tồn tại hostname ", 1)
				msg = strings.Replace(msg, "No ", "Không tìm thấy bản ghi ", 1)
				msg = strings.Replace(msg, " records for ", " cho hostname ", 1)
				msg = strings.Replace(msg, " records found", "", 1)

				response.Message = msg
			} else {
				response.Message = strings.TrimSpace(lastMsg)
			}
		} else {
			response.Message = "Không có bản ghi nào được tìm thấy qua Root Trace"
		}
	}
	if finalErr != nil {
		fmt.Printf("Lỗi TraceRoot: %v\n", finalErr)
		response.Message = "Lỗi trong quá trình Trace, vui lòng thử lại sau"
	}

	// Always send response even if empty
	sendResponse(c, req, response)
}

// NEW: Smart ALL handler - detects input type and queries accordingly
func handleAllRecordsV2(c *gin.Context, serverKey string, req *models.DNSLookupRequest, response *models.DNSLookupResponse) {
	input := strings.TrimSpace(req.Hostname)

	// Check if input is IP address
	if isIPAddress(input) {
		// Input is IP → Query PTR only
		handleIPAllRecords(c, serverKey, req, response)
	} else {
		// Input is domain → Query A, AAAA, CNAME, MX, TXT, DNSSEC
		handleDomainAllRecords(c, serverKey, req, response)
	}
}

// Handle ALL records for IP address (PTR)
func handleIPAllRecords(c *gin.Context, serverKey string, req *models.DNSLookupRequest, response *models.DNSLookupResponse) {
	ip := req.Hostname
	var allRecords []interface{}
	response.Data.Query.IsSubdomain = false
	// 1. Query PTR
	arpa, err := dnslib.ReverseAddr(ip)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "Failed to reverse IP address",
		})
		return
	}

	ptrRecords := dns.QueryDNSDirect(serverKey, arpa, dnslib.TypePTR)

	// Enrich PTR records with GeoIP info
	for i := range ptrRecords {
		if record, ok := ptrRecords[i].(models.DNSRecord); ok && record.Type == "PTR" {
			dns.EnrichIPInfoByString(&record, ip)
			ptrRecords[i] = record
		}
	}

	allRecords = append(allRecords, ptrRecords...)

	if len(ptrRecords) == 0 {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "Không tìm thấy bản ghi PTR cho IP này.",
		})
		return
	}

	// 2. Add summary info
	summary := map[string]interface{}{
		"type":         "IP_SUMMARY",
		"ip":           ip,
		"ipVersion":    getIPVersion(ip),
		"recordTypes":  []string{"PTR"},
		"totalRecords": len(ptrRecords),
	}

	// Insert summary at the beginning
	response.Data.Records = append([]interface{}{summary}, allRecords...)

	sendResponse(c, req, response)
}

// Handle ALL records for domain (A, AAAA, CNAME, MX, TXT, DNSSEC)
// WITH DEDUPLICATION
func handleDomainAllRecords(c *gin.Context, serverKey string, req *models.DNSLookupRequest, response *models.DNSLookupResponse) {
	domain := req.Hostname
	var allRecords []interface{}
	fqdn := dnslib.Fqdn(domain)
	originalDomain := strings.TrimSuffix(fqdn, ".")

	if !validator.IsValidDomain(originalDomain) {
		response.Success = false
		response.Message = "Tên miền không hợp lệ!"
		c.JSON(http.StatusBadRequest, response)
		return
	}

	response.Data.Query.IsSubdomain = isSubdomain(domain)
	// Map để track records đã thấy (deduplicate)
	seenRecords := make(map[string]bool)

	// Get apex domain for NS records
	apexDomain := strings.TrimSuffix(fqdn, ".")
	if etld, err := publicsuffix.EffectiveTLDPlusOne(apexDomain); err == nil {
		apexDomain = etld
	}
	apexFQDN := dnslib.Fqdn(apexDomain)

	// 1. Query NS records (for nameservers) - ALWAYS use authoritative trace first
	tracer := dns.NewTraceResolver(5 * time.Second)
	nsRecords, err := tracer.DiscoverAuthorities(originalDomain)
	if err == nil {
		for _, ns := range nsRecords {
			response.Data.Nameservers = append(response.Data.Nameservers, models.NameserverInfo{
				Nameserver: ns.Nameserver,
				TTL:        ns.TTL,
				Domain:     ns.Domain,
			})
		}
	} else {
		// Fallback to public DNS
		nsRecordsPub, _ := dns.QueryDNS(apexFQDN, dnslib.TypeNS)
		for _, record := range nsRecordsPub {
			if nsRec, ok := record.(models.DNSRecord); ok && nsRec.Type == "NS" {
				response.Data.Nameservers = append(response.Data.Nameservers, models.NameserverInfo{
					Nameserver: nsRec.Nameserver,
					TTL:        nsRec.TTL,
					Domain:     apexDomain,
				})
			}
		}
	}

	// 2. Query CNAME records FIRST (chỉ lấy record đầu tiên)
	canonicalName := fqdn
	cnameRecords, _ := dns.QueryDNS(fqdn, dnslib.TypeCNAME)

	if len(cnameRecords) > 0 {
		// Chỉ lấy CNAME record đầu tiên
		if cnameRec, ok := cnameRecords[0].(models.DNSRecord); ok && cnameRec.Type == "CNAME" {
			key := fmt.Sprintf("CNAME:%s", cnameRec.Value)
			if !seenRecords[key] {
				// ✅ FIX: Thêm domain gốc vào CNAME record
				cnameRec.Domain = strings.TrimSuffix(fqdn, ".")
				allRecords = append(allRecords, cnameRec)
				seenRecords[key] = true
				// Update canonical name for A/AAAA queries
				canonicalName = dnslib.Fqdn(cnameRec.Value)
			}
		}

	}

	// 3. Query A records (on canonical name if CNAME exists)
	aRecords, srv := dns.QueryDNS(canonicalName, dnslib.TypeA)
	if srv != "none" {
		response.Data.Query.Server = srv
	}
	if len(aRecords) > 0 {
		for _, record := range aRecords {
			if aRec, ok := record.(models.DNSRecord); ok && aRec.Type == "A" {
				key := fmt.Sprintf("A:%s", aRec.Address)
				if !seenRecords[key] {
					// Thêm domain vào record để frontend biết hiển thị tên nào
					aRec.Domain = strings.TrimSuffix(canonicalName, ".")
					// ✅ Bổ sung Metadata (Flag, ISP)
					dns.EnrichIPInfoByString(&aRec, aRec.Address)
					allRecords = append(allRecords, aRec)
					seenRecords[key] = true
				}
			}
		}

	}

	// 4. Query AAAA records (on canonical name if CNAME exists)
	aaaaRecords, srv := dns.QueryDNS(canonicalName, dnslib.TypeAAAA)
	if srv != "none" {
		response.Data.Query.Server = srv
	}
	if len(aaaaRecords) > 0 {
		for _, record := range aaaaRecords {
			if aaaaRec, ok := record.(models.DNSRecord); ok && aaaaRec.Type == "AAAA" {
				key := fmt.Sprintf("AAAA:%s", aaaaRec.Address)
				if !seenRecords[key] {
					// Thêm domain vào record
					aaaaRec.Domain = strings.TrimSuffix(canonicalName, ".")
					// ✅ Bổ sung Metadata (Flag, ISP)
					dns.EnrichIPInfoByString(&aaaaRec, aaaaRec.Address)
					allRecords = append(allRecords, aaaaRec)
					seenRecords[key] = true
				}
			}
		}

	}

	// 5. Query MX records (always on original domain)
	mxRecords, _ := dns.QueryDNS(fqdn, dnslib.TypeMX)
	if len(mxRecords) > 0 {
		for _, record := range mxRecords {
			if mxRec, ok := record.(models.DNSRecord); ok && mxRec.Type == "MX" {
				key := fmt.Sprintf("MX:%s:%d", mxRec.Exchange, mxRec.Priority)
				if !seenRecords[key] {
					allRecords = append(allRecords, record)
					seenRecords[key] = true
				}
			}
		}

	}

	// 6. Query TXT records (always on original domain)
	txtRecords, _ := dns.QueryDNS(fqdn, dnslib.TypeTXT)
	if len(txtRecords) > 0 {
		for _, record := range txtRecords {
			if txtRec, ok := record.(models.DNSRecord); ok && txtRec.Type == "TXT" {
				// Use substring for dedup (TXT can be very long)
				keyValue := txtRec.Value
				if len(keyValue) > 100 {
					keyValue = keyValue[:100]
				}
				key := fmt.Sprintf("TXT:%s", keyValue)
				if !seenRecords[key] {
					// TXT query trên canonical name nếu có CNAME
					txtRec.Domain = strings.TrimSuffix(canonicalName, ".")
					allRecords = append(allRecords, txtRec)
					seenRecords[key] = true
				}
			}
		}

	}

	// 7. Check DNSSEC
	dnssecInfo := dns.ValidateDNSSEC(serverKey, fqdn)
	response.Data.DNSSEC = &dnssecInfo

	if len(allRecords) == 0 {
		response.Success = true
		response.Message = fmt.Sprintf("Không tìm thấy bản ghi nào cho hostname %s.", domain)
		sendResponse(c, req, response)
		return
	}
	response.Data.Records = allRecords
	sendResponse(c, req, response)
}

// Original handlers remain unchanged
func handlePTRLookup(c *gin.Context, serverKey string, req *models.DNSLookupRequest, response *models.DNSLookupResponse) {
	ip := net.ParseIP(req.Hostname)
	if ip == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Định dạng địa chỉ IP không hợp lệ. Vui lòng nhập IPv4 hoặc IPv6 hợp lệ.",
		})
		return
	}

	arpa, err := dnslib.ReverseAddr(req.Hostname)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "Không thể đảo ngược địa chỉ IP.",
		})
		return
	}

	records := dns.QueryDNSDirect("cloudflare", arpa, dnslib.TypePTR)
	// Enrich PTR records nếu có
	for i := range records {
		if record, ok := records[i].(models.DNSRecord); ok && record.Type == "PTR" {
			dns.EnrichIPInfoByString(&record, req.Hostname)
			records[i] = record
		}
	}

	response.Success = true
	response.Data.Records = records

	if len(records) == 0 {
		response.Message = "Không tồn tại bản ghi PTR cho IP này."
	}

	sendResponse(c, req, response)
}

func handleDNSSECLookup(c *gin.Context, serverKey string, req *models.DNSLookupRequest, response *models.DNSLookupResponse) {
	input := strings.TrimSpace(req.Hostname)

	// 1. DNSSEC không áp dụng cho IP
	if isIPAddress(input) {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "DNSSEC không áp dụng cho IP, vui lòng nhập tên miền hợp lệ!",
		})
		return
	}

	// 2. Validate domain syntax
	if !validator.IsValidDomain(input) {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "Tên miền không hợp lệ, vui lòng kiểm tra lại!",
		})
		return
	}

	fqdn := dnslib.Fqdn(input)

	dnssecInfo := dns.ValidateDNSSEC(serverKey, fqdn)

	response.Success = true
	response.Data.Query.IsSubdomain = isSubdomain(input)
	response.Data.DNSSEC = &dnssecInfo

	// ✅ DNSSEC lookup không có records thường
	response.Data.Records = []interface{}{}

	sendResponse(c, req, response)
}

func handleSpecificRecord(c *gin.Context, serverKey string, req *models.DNSLookupRequest, response *models.DNSLookupResponse) {
	fqdn := dnslib.Fqdn(req.Hostname)
	originalDomain := strings.TrimSuffix(fqdn, ".")

	// Kiểm tra Input nhập có hợp lệ không
	if !validator.IsValidDomain(originalDomain) {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Tên miền không hợp lệ, vui lòng nhập lại!",
		})
		return
	}

	// Get apex domain for NS queries
	apexDomain := originalDomain
	if etld, err := publicsuffix.EffectiveTLDPlusOne(originalDomain); err == nil {
		apexDomain = etld
	}
	apexFQDN := dnslib.Fqdn(apexDomain)

	var records []interface{}

	// 1. Query NS records (nameservers) - ALWAYS use authoritative trace first
	if req.Type != "NS" {
		tracer := dns.NewTraceResolver(5 * time.Second)
		nsRecords, err := tracer.DiscoverAuthorities(originalDomain)
		if err == nil {
			for _, ns := range nsRecords {
				response.Data.Nameservers = append(response.Data.Nameservers, models.NameserverInfo{
					Nameserver: ns.Nameserver,
					TTL:        ns.TTL,
					Domain:     ns.Domain,
				})
			}
		} else {
			// Fallback to public DNS
			nsRecordsPub, _ := dns.QueryDNS(apexFQDN, dnslib.TypeNS)
			for _, record := range nsRecordsPub {
				if nsRec, ok := record.(models.DNSRecord); ok && nsRec.Type == "NS" {
					response.Data.Nameservers = append(response.Data.Nameservers, models.NameserverInfo{
						Nameserver: nsRec.Nameserver,
						TTL:        nsRec.TTL,
						Domain:     apexDomain,
					})
				}
			}
		}
	}

	// 2. Resolve CNAME first (nếu record type không phải CNAME)
	canonicalName := fqdn
	if req.Type != "CNAME" && req.Type != "NS" && req.Type != "MX" {
		cnameRecords, _ := dns.QueryDNS(fqdn, dnslib.TypeCNAME)
		if len(cnameRecords) > 0 {
			if cnameRec, ok := cnameRecords[0].(models.DNSRecord); ok && cnameRec.Type == "CNAME" {
				// Add CNAME record với domain gốc
				cnameRec.Domain = originalDomain
				records = append(records, cnameRec)
				// Update canonical name
				canonicalName = dnslib.Fqdn(cnameRec.Value)
			}
		}
	}

	// 3. Query requested record type
	var dnsType uint16
	switch req.Type {
	case "A":
		dnsType = dnslib.TypeA
	case "AAAA":
		dnsType = dnslib.TypeAAAA
	case "NS":
		dnsType = dnslib.TypeNS
	case "MX":
		dnsType = dnslib.TypeMX
	case "CNAME":
		dnsType = dnslib.TypeCNAME
	case "TXT":
		dnsType = dnslib.TypeTXT
	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Loại bản ghi không hợp lệ.",
		})
		return
	}

	// Query trên canonical name (hoặc original nếu không có CNAME)
	queryTarget := canonicalName
	switch req.Type {
	case "CNAME", "MX":
		queryTarget = fqdn // CNAME, MX luôn query trên original domain
	case "NS":
		queryTarget = apexFQDN // NS luôn query trên apex domain
	}

	queriedRecords, srv := dns.QueryDNS(queryTarget, dnsType)
	if srv != "none" && srv != "" {
		response.Data.Query.Server = srv
	}

	// 4. Add domain field to all records
	for _, record := range queriedRecords {
		switch rec := record.(type) {
		case models.DNSRecord:
			switch rec.Type {
			case "CNAME":
				// CNAME record hiển thị original domain
				rec.Domain = originalDomain
			case "A", "AAAA", "TXT":
				// A/AAAA/TXT records hiển thị canonical name
				rec.Domain = strings.TrimSuffix(canonicalName, ".")
				// ✅ Bổ sung Metadata (Flag, ISP) cho A và AAAA
				if rec.Type == "A" || rec.Type == "AAAA" {
					dns.EnrichIPInfoByString(&rec, rec.Address)
				}
			case "MX", "NS":
				// MX records query trên original domain
				// NS records query trên apex domain
				if rec.Type == "NS" {
					rec.Domain = apexDomain
				} else {
					rec.Domain = originalDomain
				}
			}
			records = append(records, rec)
		default:
			records = append(records, record)
		}
	}
	if len(records) == 0 {
		response.Success = true
		response.Message = fmt.Sprintf("Không tìm thấy bản ghi %s cho hostname %s.", req.Type, originalDomain)
		sendResponse(c, req, response)
		return
	}

	response.Data.Records = records
	sendResponse(c, req, response)
}

func sendSSE(c *gin.Context, payload interface{}) {
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}

	fmt.Fprintf(c.Writer, "data: %s\n\n", data)
	c.Writer.Flush()
}

func HandleBlacklistStream(c *gin.Context) {
	ip := c.Param("ip")

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil || parsedIP.To4() == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Invalid IPv4 address.",
		})
		return
	}

	if !validator.IsSafeIP(parsedIP) {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Địa chỉ IP không được phép (Private/Loopback/Internal). Vui lòng sử dụng IP Public.",
		})
		return
	}

	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no") // nginx: disable buffering

	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "Streaming unsupported",
		})
		return
	}

	// Stream events from DNS engine
	dns.StreamBlacklist(ip, func(e models.BlacklistStreamEvent) {
		sendSSE(c, e)
		flusher.Flush()
	})
}
