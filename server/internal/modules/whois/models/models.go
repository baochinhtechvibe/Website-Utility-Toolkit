package models

import dnsModels "tools.bctechvibe.com/server/internal/modules/dns/models"

// WhoisResponse là cấu trúc dữ liệu đã parse từ whois query
type WhoisResponse struct {
	Domain       string   `json:"domain"`
	Registrar    string   `json:"registrar"`
	Registrant   string   `json:"registrant"`
	RegisteredOn string   `json:"registered_on"`
	ExpiresOn    string   `json:"expires_on"`
	UpdatedOn    string   `json:"updated_on"`
	Status       []string `json:"status"`
	Nameservers  []string `json:"nameservers"`
	// Flags
	IsParseFailed   bool   `json:"is_parse_failed"`
	IsVNDomain      bool   `json:"is_vn_domain"`
	IsAvailable     bool   `json:"is_available"`
	AvailableSource string `json:"available_source,omitempty"`
	// TLDType phân loại TLD cho frontend: "vn", "gtld", "cctld"
	TLDType string `json:"tld_type"`
	// Raw text fallback (khi parse thất bại hoặc VNNIC)
	RawText string `json:"raw_text,omitempty"`
	// Nguồn dữ liệu và độ tin cậy
	Source        string `json:"source,omitempty"`
	Confidence    string `json:"confidence,omitempty"`     // "high", "medium", "low"
	Authoritative bool   `json:"authoritative"`
	// DNSSEC Info
	DNSSEC *dnsModels.DNSSECInfo `json:"dnssec,omitempty"`
}

// WhoisMeta chứa metadata về truy vấn (cache tracking)
type WhoisMeta struct {
	FetchedAt string `json:"fetched_at"`
	Cached    bool   `json:"cached"`
}

// WhoisCacheEntry gộp WhoisResponse + WhoisMeta vào 1 struct duy nhất.
// Tránh race condition khi 2 LRU cache riêng biệt evict entry không đồng bộ.
type WhoisCacheEntry struct {
	Response *WhoisResponse
	Meta     *WhoisMeta
}

// APIResponse đã được xóa — sử dụng internal/response.APIResponse (shared) theo GEMINI.md rule B-02

// TinoWhoisData là dữ liệu WHOIS đã parse sẵn từ API của Tino
type TinoWhoisData struct {
	Domain         string   `json:"domain"`
	Registrar      string   `json:"registrar"`
	CreateDate     string   `json:"createDate"`
	ExpiredDate    string   `json:"expiredDate"`
	RegistrantName string   `json:"registrantName"`
	Status         []string `json:"status"`
	Nameservers    []string `json:"nameservers"`
}

// TinoAPIResponse là cấu trúc JSON trả về từ http://tino.vn/backend-api/whois/{domain}
type TinoAPIResponse struct {
	Success   bool           `json:"success"`
	Domain    string         `json:"domain"`
	Available bool           `json:"available"`
	Status    string         `json:"status"`
	Raw       string         `json:"raw"`
	Whois     *TinoWhoisData `json:"whois"`
}

// RDAPEvent holds dates for RDAP response
type RDAPEvent struct {
	EventAction string `json:"eventAction"`
	EventDate   string `json:"eventDate"`
}

// RDAPEntity holds registrar/registrant info for RDAP response
type RDAPEntity struct {
	Handle     string        `json:"handle"`
	Roles      []string      `json:"roles"`
	VCardArray []interface{} `json:"vcardArray"`
	Links      []RDAPLink    `json:"links"`
	Entities   []RDAPEntity  `json:"entities"`
}

// RDAPResponse is the structure returned by RDAP servers
type RDAPResponse struct {
	Handle      string       `json:"handle"`
	LDHName     string       `json:"ldhName"`
	Status      []string     `json:"status"`
	Links       []RDAPLink   `json:"links"`
	Events      []RDAPEvent  `json:"events"`
	Entities    []RDAPEntity `json:"entities"`
	Nameservers []struct {
		LDHName string `json:"ldhName"`
	} `json:"nameservers"`
	ErrorCode int    `json:"errorCode"`
	Title     string `json:"title"`
}

type RDAPLink struct {
	Value string `json:"value"`
	Rel   string `json:"rel"`
	Href  string `json:"href"`
	Type  string `json:"type"`
}
