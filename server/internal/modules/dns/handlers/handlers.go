// ============================================
// FILE: internal/handlers/handlers.go
// HTTP handlers - WITH SUBDOMAIN DETECTION
// ============================================
package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync" // Task 3: For parallel trace processing
	"time"

	"tools.bctechvibe.com/server/internal/modules/dns/models"
	dns "tools.bctechvibe.com/server/internal/modules/dns/service"
	"tools.bctechvibe.com/server/internal/platform/cache"
	"tools.bctechvibe.com/server/internal/platform/errutil"
	"tools.bctechvibe.com/server/internal/platform/validator"
	responseAPI "tools.bctechvibe.com/server/internal/response"

	"github.com/gin-gonic/gin"
	dnslib "github.com/miekg/dns"
	"github.com/rs/zerolog/log"
	"golang.org/x/net/publicsuffix"
)

type cachedDNS struct {
	Data      interface{} `json:"data"`
	FetchedAt time.Time   `json:"fetched_at"`
}

var dnsCache = cache.New[string, cachedDNS](5000, 30*time.Minute)

const dnsLookupTimeout = 25 * time.Second

func generateCacheKey(req *models.DNSLookupRequest) string {
	rawKey := fmt.Sprintf("%s|%s|trace=%v", req.Hostname, req.Type, req.TraceRoot)
	hash := sha256.Sum256([]byte(rawKey))
	return hex.EncodeToString(hash[:])
}

func isSafeHostnameForRequest(hostname string) bool {
	hostname = strings.TrimSpace(strings.TrimSuffix(hostname, "."))

	// Nếu input là IP trực tiếp, vẫn chặn IP private/local.
	if ip := net.ParseIP(hostname); ip != nil {
		return validator.IsSafeIP(ip)
	}

	// DNS Lookup chỉ hỏi bản ghi qua resolver công khai, không kết nối tới IP đích.
	// Vì vậy không resolve domain tại đây, tránh làm hỏng chức năng kiểm tra domain lỗi DNS.
	lowerHost := strings.ToLower(hostname)
	switch {
	case lowerHost == "localhost":
		return false
	case strings.HasSuffix(lowerHost, ".localhost"),
		strings.HasSuffix(lowerHost, ".local"),
		strings.HasSuffix(lowerHost, ".internal"),
		strings.HasSuffix(lowerHost, ".lan"):
		return false
	}

	return true
}

func sendResponse(c *gin.Context, req *models.DNSLookupRequest, res *models.DNSLookupResponse) {
	if res.Success {
		cacheKey := generateCacheKey(req)

		// 🚨 KHÔNG cache nếu kết quả trả về là trắng thông tin (tự động bypass lần tới)
		hasCacheableDNSSEC := res.Data.DNSSEC != nil && res.Data.DNSSEC.Status != "" && res.Data.DNSSEC.Status != "ERROR"
		hasRecords := len(res.Data.Records) > 0 || len(res.Data.Nameservers) > 0 || hasCacheableDNSSEC
		if !req.TraceRoot && hasRecords {
			dnsCache.Set(cacheKey, cachedDNS{
				Data:      res.Data,
				FetchedAt: time.Now(),
			}, 0)
		}

		if res.Message != "" {
			responseAPI.SuccessWithMessage(c, res.Data, res.Message)
		} else {
			responseAPI.Success(c, res.Data, false, time.Now())
		}
	} else {
		// Nếu có TraceLogs trong response, trả HTTP 200 kèm success: false
		// để Frontend vẫn nhận được toàn bộ data (bao gồm nhật ký hành trình)
		if len(res.Data.TraceLogs) > 0 {
			if res.Message == "" {
				res.Message = "Không tìm thấy bản ghi DNS!"
			}
			responseAPI.FailWithData(c, res.Data, res.Message)
			return
		}

		// Trả về lỗi chuẩn hóa cho các trường hợp không có trace logs
		status := http.StatusBadRequest
		if res.Message == "" {
			res.Message = "Đã xảy ra lỗi trong quá trình xử lý yêu cầu DNS!"
		}
		responseAPI.Error(c, status, res.Message)
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

func firstLookupError(errs ...error) error {
	for _, err := range errs {
		if err != nil && !errors.Is(err, dns.ErrNXDOMAIN) {
			return err
		}
	}
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// Check if hostname is subdomain using Mozilla PSL
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
	ctx, cancel := context.WithTimeout(c.Request.Context(), dnsLookupTimeout)
	defer cancel()
	c.Request = c.Request.WithContext(ctx)

	var req models.DNSLookupRequest

	// Bind JSON FIRST
	if err := c.ShouldBindJSON(&req); err != nil {
		responseAPI.Error(c, http.StatusBadRequest, "Dữ liệu yêu cầu không hợp lệ")
		return
	}

	// Normalize hostname AFTER bind
	req.Hostname = normalizeHostname(req.Hostname)
	req.Type = strings.ToUpper(strings.TrimSpace(req.Type))

	// Validate input syntax
	valRes := validator.ValidateSyntax(req.Hostname)
	if !valRes.Valid {
		responseAPI.Error(c, http.StatusBadRequest, valRes.ErrorMsg)
		return
	}

	// Chặn các IP Private/Local để đảm bảo an toàn hệ thống (SSRF protection)
	if !isSafeHostnameForRequest(req.Hostname) {
		responseAPI.Error(c, http.StatusBadRequest, "Địa chỉ IP hoặc tên miền nội bộ không được phép tra cứu!")
		return
	}

	// ✅ Caching interception
	cacheKey := generateCacheKey(&req)
	if !req.BypassCache && !req.TraceRoot {
		if item, found := dnsCache.Get(cacheKey); found {
			responseAPI.Success(c, item.Data, true, item.FetchedAt)
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

	serverKey := "cloudflare" // Task 10: Clear magic string; defaults to Cloudflare

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
		responseAPI.Error(c, http.StatusBadRequest, "Vui lòng sử dụng endpoint /dns/blacklist-stream để kiểm tra Blacklist.")
	case "ALL":
		handleAllRecordsV2(c, serverKey, &req, &response)
	default:
		handleSpecificRecord(c, serverKey, &req, &response)
	}
}

func handleTraceRootLookup(c *gin.Context, req *models.DNSLookupRequest, response *models.DNSLookupResponse) {
	if isIPAddress(req.Hostname) {
		response.Success = false
		response.Message = "Không hỗ trợ Trace Root DNS cho địa chỉ IP."
		responseAPI.Error(c, http.StatusBadRequest, response.Message)
		return
	}

	fqdn := dnslib.Fqdn(req.Hostname)
	originalDomain := strings.TrimSuffix(fqdn, ".")

	if !validator.IsValidDomain(originalDomain) {
		response.Success = false
		response.Message = "Tên miền không hợp lệ!"
		responseAPI.Error(c, http.StatusBadRequest, response.Message)
		return
	}

	// Chặn các tên miền nội bộ khi chạy Root Trace
	if !isSafeHostnameForRequest(originalDomain) {
		response.Success = false
		response.Message = "Tên miền thuộc mạng nội bộ, không được phép tra cứu!"
		responseAPI.Error(c, http.StatusBadRequest, response.Message)
		return
	}

	response.Data.Query.IsSubdomain = isSubdomain(originalDomain)

	// Fetch canonical NS records first for better UX
	apexDomain := originalDomain
	if etld, err := publicsuffix.EffectiveTLDPlusOne(originalDomain); err == nil {
		apexDomain = etld
	}
	apexFQDN := dnslib.Fqdn(apexDomain)

	// Task 7: Initialize tracer once to reuse delegation cache
	tracer := dns.NewTraceResolver(20 * time.Second)
	tracer.BypassCache = true // Đảm bảo luôn tra từ Root để hiện log đầy đủ

	// Always seed Nameservers for better UX (NS always at top)
	// EXCEPT if the user specifically asked for NS only (in which case it goes to Records)
	if req.Type != "NS" {
		nsRecords, err := tracer.DiscoverAuthorities(originalDomain)
		if err == nil {
			for _, ns := range nsRecords {
				response.Data.Nameservers = append(response.Data.Nameservers, models.NameserverInfo{
					Nameserver: ns.Nameserver,
					IP:         ns.IP,
					TTL:        ns.TTL,
					Domain:     ns.Domain,
				})
			}
		} else {
			// Fallback to public DNS if trace fails
			nsRecordsPub, _, _ := dns.QueryDNSContext(c.Request.Context(), apexFQDN, dnslib.TypeNS)
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
		responseAPI.Error(c, http.StatusBadRequest, "Không thể Root Trace loại bản ghi này")
		return
	}

	var allRecords []models.DNSRecord
	var finalLogs []models.TraceStep
	var finalErr error

	// Map to track unique records and avoid duplicates
	seenRecords := make(map[string]bool)
	seenLogs := make(map[string]bool)

	// Seed seenRecords with existing Nameservers to avoid trace duplicates showing up in Records
	for _, ns := range response.Data.Nameservers {
		key := fmt.Sprintf("%s:NS:%s", ns.Domain, ns.Nameserver)
		seenRecords[key] = true
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	for i, t := range types {
		wg.Add(1)
		go func(idx int, qType uint16) {
			defer wg.Done()

			records, logs, err := tracer.DoTrace(originalDomain, qType)

			mu.Lock()
			defer mu.Unlock()

			// Merge and deduplicate trace logs dynamically
			for _, step := range logs {
				if !seenLogs[step.Message] {
					seenLogs[step.Message] = true
					finalLogs = append(finalLogs, step)
				}
			}

			if err != nil && finalErr == nil {
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
		}(i, t)
	}
	wg.Wait()

	var apiRecords []interface{}
	// Local cache để tránh query trùng lặp geoip trong cùng 1 request
	geoCache := make(map[string]models.DNSRecord)

	for i := range allRecords {
		rec := allRecords[i]
		// Normalize for UI consistency
		rec.Domain = strings.TrimSuffix(rec.Domain, ".")
		if rec.Type == "A" || rec.Type == "AAAA" {
			if cached, ok := geoCache[rec.Address]; ok {
				rec.Country = cached.Country
				rec.CountryCode = cached.CountryCode
				rec.ISP = cached.ISP
				rec.Org = cached.Org
			} else {
				dns.EnrichIPInfoByString(&rec, rec.Address)
				geoCache[rec.Address] = rec
			}
		}
		apiRecords = append(apiRecords, rec)
	}

	// Final normalization for Nameservers if any
	for i := range response.Data.Nameservers {
		response.Data.Nameservers[i].Domain = strings.TrimSuffix(response.Data.Nameservers[i].Domain, ".")
	}

	response.Success = true
	response.Data.Records = apiRecords

	if req.Type == "ALL" && len(finalLogs) > 0 {
		var cleanedLogs []models.TraceStep
		for _, step := range finalLogs {
			// Strip the individual trace completion metrics
			isCompletionLog := strings.Contains(step.Message, "Trace hoàn tất:")
			isRecordFoundLog := strings.Contains(step.Message, "Tìm thấy bản ghi")
			if !isCompletionLog && !isRecordFoundLog {
				cleanedLogs = append(cleanedLogs, step)
			}
		}
		finalLogs = cleanedLogs
		// Append a single consolidated master message at the very end
		finalLogs = append(finalLogs, models.TraceStep{
			Message: fmt.Sprintf("\nTìm thấy %d bản ghi trên tất cả loại bản ghi.", len(apiRecords)),
		})
	}
	response.Data.TraceLogs = finalLogs

	if len(apiRecords) == 0 && finalErr == nil {
		response.Success = false // 🚨 QUAN TRỌNG: Không có bản ghi thì coi như lookup thất bại
		if len(finalLogs) > 0 {
			lastIdx := len(finalLogs) - 1
			lastMsg := finalLogs[lastIdx].Message

			// Giữ nhánh này để xử lý an toàn nếu còn log trace định dạng cũ trong quá trình phát triển.
			if strings.Contains(lastMsg, "reports:") {
				// Remove the report line from TraceLogs to keep it technical
				response.Data.TraceLogs = finalLogs[:lastIdx]

				// Translate the message for the Error Card
				msg := strings.TrimSpace(lastMsg)
				msg = strings.Replace(msg, " reports: ", " báo cáo: ", 1)
				msg = strings.Replace(msg, "No such host ", "Không tồn tại tên miền ", 1)
				msg = strings.Replace(msg, "No ", "Không tìm thấy bản ghi ", 1)
				msg = strings.Replace(msg, " records for ", " cho tên miền ", 1)
				msg = strings.Replace(msg, " records found", "", 1)

				response.Message = msg
			} else {
				response.Message = strings.TrimSpace(lastMsg)
			}
		} else {
			response.Message = "Không có bản ghi nào được tìm thấy qua Root Trace!"
		}
	}
	if finalErr != nil {
		log.Warn().Err(finalErr).Str("hostname", req.Hostname).Msg("TraceRoot lookup error")
		response.Success = false
		response.Message = errutil.TranslateError(finalErr)
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
		responseAPI.Error(c, http.StatusBadRequest, "Không thể đảo ngược địa chỉ IP. Vui lòng kiểm tra lại.")
		return
	}

	ptrRecords, lookupErr := dns.QueryDNSDirectContext(c.Request.Context(), serverKey, arpa, dnslib.TypePTR)

	// Enrich PTR records with GeoIP info
	for i := range ptrRecords {
		if record, ok := ptrRecords[i].(models.DNSRecord); ok && record.Type == "PTR" {
			dns.EnrichIPInfoByString(&record, ip)
			ptrRecords[i] = record
		}
	}

	allRecords = append(allRecords, ptrRecords...)

	if len(ptrRecords) == 0 {
		response.Success = false
		if lookupErr != nil && !errors.Is(lookupErr, dns.ErrNXDOMAIN) {
			response.Message = fmt.Sprintf("Lỗi từ máy chủ DNS: %s", errutil.TranslateError(lookupErr))
		} else {
			response.Message = "Không tìm thấy bản ghi PTR cho IP này."
		}
		sendResponse(c, req, response)
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
		responseAPI.Error(c, http.StatusBadRequest, response.Message)
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
		nsRecordsPub, _, _ := dns.QueryDNSContext(c.Request.Context(), apexFQDN, dnslib.TypeNS)
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
	cnameRecords, _, _ := dns.QueryDNSContext(c.Request.Context(), fqdn, dnslib.TypeCNAME)

	if len(cnameRecords) > 0 {
		// Chỉ lấy CNAME record đầu tiên
		if cnameRec, ok := cnameRecords[0].(models.DNSRecord); ok && cnameRec.Type == "CNAME" {
			key := fmt.Sprintf("CNAME:%s", cnameRec.Value)
			if !seenRecords[key] {
				// FIX: Thêm domain gốc vào CNAME record
				cnameRec.Domain = strings.TrimSuffix(fqdn, ".")
				allRecords = append(allRecords, cnameRec)
				seenRecords[key] = true
				// Update canonical name for A/AAAA queries
				canonicalName = dnslib.Fqdn(cnameRec.Value)
			}
		}

	}

	// 3-7. Query A, AAAA, MX, TXT, DNSSEC in parallel
	// After CNAME resolution (sequential), these queries are independent
	type parallelResult struct {
		records []interface{}
		server  string
		err     error
	}

	var (
		wgAll      sync.WaitGroup
		muAll      sync.Mutex
		aResult    parallelResult
		aaaaResult parallelResult
		mxResult   parallelResult
		txtResult  parallelResult
	)

	// A records (on canonical name)
	wgAll.Add(1)
	go func() {
		defer wgAll.Done()
		recs, srv, err := dns.QueryDNSContext(c.Request.Context(), canonicalName, dnslib.TypeA)
		muAll.Lock()
		aResult = parallelResult{records: recs, server: srv, err: err}
		muAll.Unlock()
	}()

	// AAAA records (on canonical name)
	wgAll.Add(1)
	go func() {
		defer wgAll.Done()
		recs, srv, err := dns.QueryDNSContext(c.Request.Context(), canonicalName, dnslib.TypeAAAA)
		muAll.Lock()
		aaaaResult = parallelResult{records: recs, server: srv, err: err}
		muAll.Unlock()
	}()

	// MX records (on original domain)
	wgAll.Add(1)
	go func() {
		defer wgAll.Done()
		recs, _, err := dns.QueryDNSContext(c.Request.Context(), fqdn, dnslib.TypeMX)
		muAll.Lock()
		mxResult = parallelResult{records: recs, err: err}
		muAll.Unlock()
	}()

	// TXT records (on original domain)
	wgAll.Add(1)
	go func() {
		defer wgAll.Done()
		recs, _, err := dns.QueryDNSContext(c.Request.Context(), fqdn, dnslib.TypeTXT)
		muAll.Lock()
		txtResult = parallelResult{records: recs, err: err}
		muAll.Unlock()
	}()

	// DNSSEC check
	var dnssecInfo models.DNSSECInfo
	wgAll.Add(1)
	go func() {
		defer wgAll.Done()
		info := dns.ValidateDNSSECContext(c.Request.Context(), serverKey, fqdn)
		muAll.Lock()
		dnssecInfo = info
		muAll.Unlock()
	}()

	wgAll.Wait()

	// Process A records
	if aResult.server != "none" {
		response.Data.Query.Server = aResult.server
	}
	for _, record := range aResult.records {
		if aRec, ok := record.(models.DNSRecord); ok && aRec.Type == "A" {
			key := fmt.Sprintf("A:%s", aRec.Address)
			if !seenRecords[key] {
				aRec.Domain = strings.TrimSuffix(canonicalName, ".")
				dns.EnrichIPInfoByString(&aRec, aRec.Address)
				allRecords = append(allRecords, aRec)
				seenRecords[key] = true
			}
		}
	}

	// Process AAAA records
	if aaaaResult.server != "none" && aaaaResult.server != "" {
		response.Data.Query.Server = aaaaResult.server
	}
	for _, record := range aaaaResult.records {
		if aaaaRec, ok := record.(models.DNSRecord); ok && aaaaRec.Type == "AAAA" {
			key := fmt.Sprintf("AAAA:%s", aaaaRec.Address)
			if !seenRecords[key] {
				aaaaRec.Domain = strings.TrimSuffix(canonicalName, ".")
				dns.EnrichIPInfoByString(&aaaaRec, aaaaRec.Address)
				allRecords = append(allRecords, aaaaRec)
				seenRecords[key] = true
			}
		}
	}

	// Process MX records
	for _, record := range mxResult.records {
		if mxRec, ok := record.(models.DNSRecord); ok && mxRec.Type == "MX" {
			key := fmt.Sprintf("MX:%s:%d", mxRec.Exchange, mxRec.Priority)
			if !seenRecords[key] {
				allRecords = append(allRecords, record)
				seenRecords[key] = true
			}
		}
	}

	// Process TXT records
	for _, record := range txtResult.records {
		if txtRec, ok := record.(models.DNSRecord); ok && txtRec.Type == "TXT" {
			keyValue := txtRec.Value
			runes := []rune(keyValue)
			if len(runes) > 100 {
				keyValue = string(runes[:100])
			}
			key := fmt.Sprintf("TXT:%s", keyValue)
			if !seenRecords[key] {
				txtRec.Domain = strings.TrimSuffix(canonicalName, ".")
				allRecords = append(allRecords, txtRec)
				seenRecords[key] = true
			}
		}
	}

	// Set DNSSEC
	response.Data.DNSSEC = &dnssecInfo

	if len(allRecords) == 0 {
		response.Success = false
		if lookupErr := firstLookupError(aResult.err, aaaaResult.err, mxResult.err, txtResult.err); lookupErr != nil && !errors.Is(lookupErr, dns.ErrNXDOMAIN) {
			response.Message = fmt.Sprintf("Lỗi từ máy chủ DNS: %s", errutil.TranslateError(lookupErr))
		} else {
			response.Message = fmt.Sprintf("Không tìm thấy bản ghi nào cho tên miền %s!", domain)
		}
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
		responseAPI.Error(c, http.StatusBadRequest, "Định dạng địa chỉ IP không hợp lệ. Vui lòng nhập IPv4 hoặc IPv6 hợp lệ!")
		return
	}

	arpa, err := dnslib.ReverseAddr(req.Hostname)
	if err != nil {
		// Lỗi đảo ngược IP → lỗi input, dùng 400
		responseAPI.Error(c, http.StatusBadRequest, "Không thể đảo ngược địa chỉ IP. Vui lòng kiểm tra lại.")
		return
	}

	// Dùng tham số serverKey thay vì hardcode "cloudflare"
	records, lookupErr := dns.QueryDNSDirectContext(c.Request.Context(), serverKey, arpa, dnslib.TypePTR)
	// Enrich PTR records nếu có
	for i := range records {
		if record, ok := records[i].(models.DNSRecord); ok && record.Type == "PTR" {
			dns.EnrichIPInfoByString(&record, req.Hostname)
			records[i] = record
		}
	}

	if len(records) == 0 {
		// Không tìm thấy PTR → success:false để FE hiện message-card--error
		response.Success = false
		if lookupErr != nil && !errors.Is(lookupErr, dns.ErrNXDOMAIN) {
			response.Message = fmt.Sprintf("Lỗi từ máy chủ DNS: %s", errutil.TranslateError(lookupErr))
		} else {
			response.Message = "Không tồn tại bản ghi PTR cho IP này."
		}
		sendResponse(c, req, response)
		return
	}

	response.Success = true
	response.Data.Records = records
	sendResponse(c, req, response)
}

func handleDNSSECLookup(c *gin.Context, serverKey string, req *models.DNSLookupRequest, response *models.DNSLookupResponse) {
	input := strings.TrimSpace(req.Hostname)

	// 1. DNSSEC không áp dụng cho IP → lỗi input, dùng 400
	if isIPAddress(input) {
		responseAPI.Error(c, http.StatusBadRequest, "DNSSEC không áp dụng cho địa chỉ IP. Vui lòng nhập tên miền hợp lệ.")
		return
	}

	// 2. Validate domain syntax → lỗi input, dùng 400
	if !validator.IsValidDomain(input) {
		responseAPI.Error(c, http.StatusBadRequest, "Tên miền không hợp lệ. Vui lòng kiểm tra lại.")
		return
	}

	fqdn := dnslib.Fqdn(input)

	dnssecInfo := dns.ValidateDNSSECContext(c.Request.Context(), serverKey, fqdn)

	response.Success = true
	response.Data.Query.IsSubdomain = isSubdomain(input)
	response.Data.DNSSEC = &dnssecInfo

	// DNSSEC lookup không có records thường
	response.Data.Records = []interface{}{}

	sendResponse(c, req, response)
}

func handleSpecificRecord(c *gin.Context, serverKey string, req *models.DNSLookupRequest, response *models.DNSLookupResponse) {
	fqdn := dnslib.Fqdn(req.Hostname)
	originalDomain := strings.TrimSuffix(fqdn, ".")

	// Kiểm tra Input nhập có hợp lệ không
	if !validator.IsValidDomain(originalDomain) {
		responseAPI.Error(c, http.StatusBadRequest, "Tên miền không hợp lệ!")
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
			nsRecordsPub, _, _ := dns.QueryDNSContext(c.Request.Context(), apexFQDN, dnslib.TypeNS)
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
		cnameRecords, _, _ := dns.QueryDNSContext(c.Request.Context(), fqdn, dnslib.TypeCNAME)
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
		// Loại bản ghi không được hỗ trợ
		responseAPI.Error(c, http.StatusBadRequest, "Loại bản ghi không được hỗ trợ.")
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

	queriedRecords, srv, err := dns.QueryDNSContext(c.Request.Context(), queryTarget, dnsType)
	if srv != "none" && srv != "" {
		response.Data.Query.Server = srv
	}

	// 4. Add domain field to all records
	for _, record := range queriedRecords {
		switch rec := record.(type) {
		case models.DNSRecord:
			switch rec.Type {
			case "CNAME":
				// CNAME record hiển thị với domain gốc
				rec.Domain = originalDomain
			case "A", "AAAA", "TXT":
				// A/AAAA/TXT records hiển thị với canonical name
				rec.Domain = strings.TrimSuffix(canonicalName, ".")
				// Bổ sung Metadata (Flag, ISP) cho A và AAAA
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
		// Không có bản ghi → success:false để FE hiện message-card--error
		response.Success = false
		if err != nil {
			response.Message = fmt.Sprintf("Lỗi từ máy chủ DNS: %v", errutil.TranslateError(err))
		} else {
			response.Message = fmt.Sprintf("Không tìm thấy bản ghi %s cho tên miền %s!", req.Type, originalDomain)
		}
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
		responseAPI.Error(c, http.StatusBadRequest, "Định dạng địa chỉ IP không hợp lệ. Vui lòng nhập địa chỉ IPv4 hợp lệ.")
		return
	}

	if !validator.IsSafeIP(parsedIP) {
		responseAPI.Error(c, http.StatusBadRequest, "Định dạng địa chỉ IP không hợp lệ. Vui lòng nhập địa chỉ IPv4 hợp lệ.")
		return
	}

	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no") // nginx: disable buffering

	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		responseAPI.Error(c, http.StatusInternalServerError, "Trình duyệt hoặc máy chủ không hỗ trợ streaming")
		return
	}

	// Stream events from DNS engine with context awareness
	ctx := c.Request.Context()
	dns.StreamBlacklist(ctx, ip, func(e models.BlacklistStreamEvent) {
		// Kiểm tra client còn kết nối không trước khi ghi
		select {
		case <-ctx.Done():
			return
		default:
		}
		sendSSE(c, e)
		flusher.Flush()
	})
}
