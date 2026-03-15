package models

import "time"

// =======================
// DNS Lookup
// =======================

type DNSLookupRequest struct {
	Hostname    string `json:"hostname" binding:"required"`
	Type        string `json:"type" binding:"required"`
	Server      string `json:"server"`
	BypassCache bool   `json:"bypassCache"`
	TraceRoot   bool   `json:"traceRoot"`
}

type DNSRecord struct {
	Type       string `json:"type"`
	Domain     string `json:"domain,omitempty"`
	Address    string `json:"address,omitempty"`
	Nameserver string `json:"nameserver,omitempty"`
	Exchange   string `json:"exchange,omitempty"`
	Priority   uint16 `json:"priority,omitempty"`
	Value      string `json:"value,omitempty"`
	TTL        uint32 `json:"ttl,omitempty"`

	// GeoIP (optional)
	Country     string `json:"country,omitempty"`
	CountryCode string `json:"countryCode,omitempty"`
	ISP         string `json:"isp,omitempty"`
	Org         string `json:"org,omitempty"`
}

// =======================
// DNSSEC
// =======================

type DNSSECRecord struct {
	Type string `json:"type"`

	// DNSKEY
	Flags     uint16 `json:"flags,omitempty"`
	Protocol  uint8  `json:"protocol,omitempty"`
	Algorithm uint8  `json:"algorithm,omitempty"`
	KeyTag    uint16 `json:"keyTag,omitempty"`
	PublicKey string `json:"publicKey,omitempty"`

	// DS
	DigestType uint8  `json:"digestType,omitempty"`
	Digest     string `json:"digest,omitempty"`

	// RRSIG
	TypeCovered string    `json:"typeCovered,omitempty"`
	SignerName  string    `json:"signerName,omitempty"`
	Expiration  time.Time `json:"expiration,omitempty"`
}

type DNSSECInfo struct {
	Enabled bool           `json:"enabled"`
	Status  string         `json:"status"` // SECURE | BOGUS | INSECURE | ERROR
	Message string         `json:"message,omitempty"`
	Records []DNSSECRecord `json:"records,omitempty"`
}

// =======================
// Nameserver
// =======================

type NameserverInfo struct {
	Nameserver string `json:"nameserver"`
	TTL        uint32 `json:"ttl"`
	Domain     string `json:"domain,omitempty"`
}

// =======================
// Blacklist
// =======================

type BlacklistRecord struct {
	Provider string `json:"provider"`
	Type     string `json:"type"` // BLACKLIST
	Level    string `json:"level"`
	Status   string `json:"status"` // OK | LISTED
	IP       string `json:"ip"`
}

type BlacklistSummary struct {
	Type    string `json:"type"` // BLACKLIST_SUMMARY
	IP      string `json:"ip"`
	Checked int    `json:"checked"`
	Listed  int    `json:"listed"`
	Total   int    `json:"total"`
	Status  string `json:"status"` // OK | LISTED
}

type BlacklistEvent struct {
	Record  *BlacklistRecord `json:"record,omitempty"`
	Checked int              `json:"checked"`
	Listed  int              `json:"listed"`
	Total   int              `json:"total"`
	Done    bool             `json:"done"`
}

type BlacklistStreamEvent struct {
	Type     string `json:"type"`     // BLACKLIST | BLACKLIST_SUMMARY
	Provider string `json:"provider"` // rbl host
	Status   string `json:"status"`   // OK | LISTED | TIMEOUT
	Level    string `json:"level,omitempty"`
	IP       string `json:"ip,omitempty"`
	Listed   int    `json:"listed"`
	Total    int    `json:"total"`
}

// =======================
// Root Trace
// =======================

type TraceStep struct {
	ServerName string `json:"serverName"`
	ServerIP   string `json:"serverIp"`
	DurationMs int64  `json:"durationMs"`
	Message    string `json:"message"`
}

// =======================
// API Response
// =======================

type DNSLookupResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Query       QueryInfo        `json:"query"`
		Records     []interface{}    `json:"records"` // DNSRecord | Blacklist*
		Nameservers []NameserverInfo `json:"nameservers,omitempty"`
		DNSSEC      *DNSSECInfo      `json:"dnssec,omitempty"`
		TraceLogs   []TraceStep      `json:"traceLogs,omitempty"`
	} `json:"data"`
	Message string `json:"message,omitempty"`
}

// =======================
// Misc
// =======================

type RBLProvider struct {
	Host  string
	Level string
}

type QueryInfo struct {
	Hostname    string `json:"hostname"`
	Type        string `json:"type"`
	Server      string `json:"server"`
	IsSubdomain bool   `json:"isSubdomain"`
}
