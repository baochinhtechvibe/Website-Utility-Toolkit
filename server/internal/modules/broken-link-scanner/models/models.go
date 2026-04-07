package models

// ScanRequest represents the input JSON for the scan request
type ScanRequest struct {
	URL             string `json:"url" binding:"required,url"`
	Scope           string `json:"scope" binding:"required,oneof=same-host all"`
	MaxWorkers      int    `json:"maxWorkers" binding:"min=1,max=100"`
	IgnoreTlsErrors bool   `json:"ignoreTlsErrors"`
	BypassCache     bool   `json:"bypassCache"`
}

// ScanResultRow represents a single check result for a given link asset
type ScanResultRow struct {
	Kind          string `json:"kind"`           // <a>, <img>, <link>, <script>, <source>, <iframe>, <form>
	SourceTag     string `json:"source_tag"`     // raw tag content snippet
	OriginalURL   string `json:"original_url"`   // raw URL in the tag
	FinalURL      string `json:"final_url"`      // absolute URL requested
	StatusCode    int    `json:"status_code"`    // Final HTTP status code
	StatusClass   string `json:"status_class"`   // ok, redirect, broken, blocked, skipped
	RedirectCount int    `json:"redirect_count"` // Number of redirects
	ResponseMs    int64  `json:"response_ms"`    // Time it took to get the verdict
	Error         string `json:"error"`          // Any textual error message
}

// ScanSummary represents the aggregations
type ScanSummary struct {
	Total          int `json:"total"`
	Ok             int `json:"ok"`
	Redirect       int `json:"redirect"`
	Broken         int `json:"broken"`
	Blocked        int `json:"blocked"`
	SkippedInvalid int `json:"skipped_invalid"` // specific to invalid schemes like mailto:, data:, blob:, javascript:
}

// ScanData is the core output wrapping the summary and the final array sequence.
type ScanData struct {
	RequestedURL  string          `json:"requested_url"`
	FinalPageURL  string          `json:"final_page_url"`
	Summary       ScanSummary     `json:"summary"`
	Results       []ScanResultRow `json:"results"`
}
