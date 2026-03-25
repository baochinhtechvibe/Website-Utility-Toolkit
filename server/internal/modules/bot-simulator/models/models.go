package models

// AnalyzeRequest chứa các tham số đầu vào cho việc phân tích bot access.
type AnalyzeRequest struct {
	URL             string   `json:"url" binding:"required"`
	Bot             string   `json:"bot" binding:"required"`
	IgnoreTLSErrors bool     `json:"ignoreTlsErrors"`
	CheckSitemap    bool     `json:"checkSitemap"`
	CompareMode     bool     `json:"compareMode"`
	CompareBots     []string `json:"compareBots"`
	BypassCache     bool     `json:"bypassCache"`
}

// RedirectHopSummary mô tả một bước trong chuỗi redirect.
type RedirectHopSummary struct {
	Step       int    `json:"step"`
	URL        string `json:"url"`
	StatusCode int    `json:"statusCode"`
	StatusText string `json:"statusText"`
}

// CrawlAccess mô tả mức độ bot có thể tiếp cận trang web.
// allowed | blocked | unreachable | timeout | error
type CrawlAccess struct {
	Status       string `json:"status"`
	RobotsStatus string `json:"robots_status"` // 2xx, 3xx, 4xx, 5xx, timeout, none
	MatchedGroup string `json:"matched_group,omitempty"`
	MatchedRule  string `json:"matched_rule,omitempty"`
	Decision     string `json:"decision,omitempty"` // allow | disallow | default_allow | default_disallow
}

// Indexability mô tả khả năng trang được đưa vào chỉ mục tìm kiếm.
// allowed | blocked | unknown_due_to_crawl_block
type Indexability struct {
	Status           string `json:"status"`
	MetaRobots       string `json:"meta_robots,omitempty"`
	XRobotsTag       string `json:"x_robots_tag,omitempty"`
	CanonicalSelf    bool   `json:"canonical_self"`
	CanonicalURL     string `json:"canonical_url,omitempty"`
	CanonicalMissing bool   `json:"canonical_missing"`
	Note             string `json:"note,omitempty"`
}

// Serving mô tả cách server phản hồi (HTTP, redirect chain, content type).
type Serving struct {
	FinalURL              string               `json:"final_url"`
	InitialStatusCode     int                  `json:"initial_status_code"`
	InitialStatusText     string               `json:"initial_status_text"`
	ContentType           string               `json:"content_type,omitempty"`
	PayloadBytes          int64                `json:"payload_bytes"`
	RedirectCount         int                  `json:"redirect_count"`
	RedirectChainSummary  []RedirectHopSummary `json:"redirect_chain_summary"`
	ResponseHeaders       map[string]string    `json:"response_headers,omitempty"`
	BodySnippet           string               `json:"body_snippet,omitempty"`
	Title                 string               `json:"title,omitempty"`
}

// SitemapResult chứa kết quả kiểm tra sitemap.
type SitemapResult struct {
	Checked       bool     `json:"checked"`
	DiscoveryPath string   `json:"discovery_path,omitempty"` // robots.txt | /sitemap.xml
	Found         bool     `json:"found"`
	SitemapURL    string   `json:"sitemap_url,omitempty"`
	URLInSitemap  bool     `json:"url_in_sitemap"`
	Note          string   `json:"note,omitempty"`
	FilesScanned  int      `json:"files_scanned"`
	URLsChecked   int      `json:"urls_checked"`
	ParseErrors   []string `json:"parse_errors,omitempty"`
}

// Verdict là phán quyết cuối cùng của engine.
type Verdict struct {
	Result      string       `json:"result"`       // Indexable | Blocked | Risky | Unknown
	Confidence  string       `json:"confidence"`   // high | medium | low
	ReasonCodes []string     `json:"reason_codes"` // DS_ROBOTS_BLOCK, DS_NOINDEX_META, etc.
	Summary     string       `json:"summary"`
	Suggestions []string     `json:"suggestions,omitempty"`
}

// Limitation mô tả giới hạn của công cụ này là UA Simulation.
type Limitation struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// BotCompareResult chứa kết quả so sánh của một bot profile.
type BotCompareResult struct {
	Bot         string      `json:"bot"`
	BotLabel    string      `json:"bot_label"`
	CrawlStatus string      `json:"crawl_status"` // allowed | blocked | ...
	IndexStatus string      `json:"index_status"` // allowed | blocked | unknown_due_to_crawl_block
	FinalURL    string      `json:"final_url"`
	StatusCode  int         `json:"status_code"`
	ContentHash string      `json:"content_hash,omitempty"`
	Title       string      `json:"title,omitempty"`
	Canonical   string      `json:"canonical,omitempty"`
	MetaRobots  string      `json:"meta_robots,omitempty"`
	Diff        []string    `json:"diff,omitempty"` // các điểm khác biệt với bot đầu tiên
	Error       string      `json:"error,omitempty"`
}

// AnalyzeData là struct payload chính được bọc bởi response envelope của repo.
type AnalyzeData struct {
	Target       string             `json:"target"`
	BotProfile   BotProfileInfo     `json:"bot_profile"`
	CrawlAccess  CrawlAccess        `json:"crawl_access"`
	Indexability Indexability       `json:"indexability"`
	Serving      Serving            `json:"serving"`
	Sitemap      *SitemapResult     `json:"sitemap,omitempty"`
	Verdict      Verdict            `json:"verdict"`
	Compare      []BotCompareResult `json:"compare,omitempty"`
	Limitations  []Limitation       `json:"limitations"`
}

// BotProfileInfo mô tả thông tin về bot đang được sử dụng.
type BotProfileInfo struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	UserAgent   string `json:"user_agent"`
	RobotsToken string `json:"robots_token"`
	Family      string `json:"family"`
	DocsURL     string `json:"docs_url,omitempty"`
}
