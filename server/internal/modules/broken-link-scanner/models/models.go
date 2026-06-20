package models

type ScanRequest struct {
	URL             string `json:"url" binding:"required"`
	Scope           string `json:"scope" binding:"required,oneof=same-host all"`
	MaxWorkers      int    `json:"maxWorkers" binding:"max=100"`
	IgnoreTlsErrors bool   `json:"ignoreTlsErrors"`
	BypassCache     bool   `json:"bypassCache"`
	MaxDepth        int    `json:"maxDepth" binding:"max=10"`
	MaxPages        int    `json:"maxPages" binding:"max=500"`
	MaxLinks        int    `json:"maxLinks" binding:"max=5000"`
	RespectRobots   *bool  `json:"respectRobots"`
	CrawlDelay      int    `json:"crawlDelay" binding:"max=10000"` // Explicit global crawl delay override in milliseconds
	UserAgent       string `json:"userAgent"` // To customize the crawler's User-Agent string
}

func (r *ScanRequest) IsRespectRobots() bool {
	if r.RespectRobots == nil {
		return true
	}
	return *r.RespectRobots
}

// ScanResultRow represents a single check result for a given link asset
type ScanResultRow struct {
	Kind          string `json:"kind"`           // <a>, <img>, <link>, <script>, <source>, <iframe>, <form>
	SourceTag     string `json:"source_tag"`     // raw tag content snippet
	SourcePage    string `json:"source_page"`    // URL of the page where this link was found
	OriginalURL   string `json:"original_url"`   // raw URL in the tag
	FinalURL      string `json:"final_url"`      // absolute URL requested
	StatusCode    int    `json:"status_code"`    // Final HTTP status code
	StatusText    string `json:"status_text"`    // Standard HTTP status text (e.g. NOT FOUND)
	StatusClass   string `json:"status_class"`   // ok, redirect, broken, blocked, skipped
	RedirectCount int    `json:"redirect_count"` // Number of redirects
	ResponseMs    int64  `json:"response_ms"`    // Time it took to get the verdict
	Error         string `json:"error"`          // Any textual error message
}

// ScanSummary represents the aggregations
type ScanSummary struct {
	Total             int  `json:"total"`
	UniqueTargets     int  `json:"unique_targets"`
	PagesCrawled      int  `json:"pages_crawled"`
	PagesSkipped      int  `json:"pages_skipped"`
	LimitReached      bool `json:"limit_reached"`
	Ok                int  `json:"ok"`
	Redirect          int `json:"redirect"`
	Broken            int `json:"broken"`
	Blocked           int `json:"blocked"`
	Timeout           int `json:"timeout"`
	SkippedInvalid    int `json:"skipped_invalid"`      // specific to invalid schemes like mailto:, data:, blob:, javascript:
	SkippedOverLimit  int `json:"skipped_over_limit"`   // if website has > 250 links
	SkippedOutOfScope int `json:"skipped_out_of_scope"` // if same-host is active
}

// ScanData is the core output wrapping the summary and the final array sequence.
type ScanData struct {
	RequestedURL string          `json:"requested_url"`
	FinalPageURL string          `json:"final_page_url"`
	Summary      ScanSummary     `json:"summary"`
	Results      []ScanResultRow `json:"results"`
}
