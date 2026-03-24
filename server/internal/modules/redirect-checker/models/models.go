package models

// RedirectAnalyzeRequest contains the parameters for analyzing a redirect chain.
type RedirectAnalyzeRequest struct {
	URL             string `json:"url" binding:"required"`
	UserAgent       string `json:"userAgent"`
	DeepScan        bool   `json:"deepScan"`
	IgnoreTLSErrors bool   `json:"ignoreTlsErrors"`
}

// RedirectHop represents a single step in the redirect chain.
type RedirectHop struct {
	Step       int                 `json:"step"`
	URL        string              `json:"url"`
	IP         string              `json:"ip"`
	StatusCode int                 `json:"statusCode"`
	StatusText string              `json:"statusText"`
	Protocol   string              `json:"protocol"`
	Method     string              `json:"method"`
	Timings    RedirectTimings     `json:"timings"`
	// Headers contains the response headers for this hop. 
	// Sensitive headers like 'Server' or 'X-Powered-By' are filtered in the service layer for security.
	Headers    map[string][]string `json:"headers"`
	Error      string              `json:"error,omitempty"`
}

// RedirectTimings holds the timing breakdown for a single HTTP request.
type RedirectTimings struct {
	DNSLookup     int64 `json:"dnsLookup"`
	TCPConnection int64 `json:"tcpConnection"`
	TLSHandshake  int64 `json:"tlsHandshake"`
	TTFB          int64 `json:"ttfb"`
	Total         int64 `json:"total"`
}

// RedirectSecurity contains security audits like checking for HTTP downgrade.
type RedirectSecurity struct {
	IsHTTPSDowngrade bool `json:"isHttpsDowngrade"`
	IsOpenRedirect   bool `json:"isOpenRedirect"`
}

// RedirectPerformance contains overall metrics for the entire chain.
type RedirectPerformance struct {
	TotalRedirects int   `json:"totalRedirects"`
	TotalTime      int64 `json:"totalTime"`
	TooMany        bool  `json:"tooMany"`
}

// SEOAudit contains extracted SEO meta tags from the final page.
type SEOAudit struct {
	Canonical string `json:"canonical,omitempty"`
	Title     string `json:"title,omitempty"`
	OGTitle   string `json:"ogTitle,omitempty"`
	Robots    string `json:"robots,omitempty"`
}

// RedirectAnalyzeData holds the detailed results of the analysis.
type RedirectAnalyzeData struct {
	Chain       []RedirectHop       `json:"chain"`
	Performance RedirectPerformance `json:"performance"`
	Security    RedirectSecurity    `json:"security"`
	SEO         SEOAudit            `json:"seo"`
}

// RedirectAnalyzeResponse is the API response model.
type RedirectAnalyzeResponse struct {
	Success bool                `json:"success"`
	Data    RedirectAnalyzeData `json:"data"`
	Message string              `json:"message,omitempty"`
}
