package models

type SpeedTestRequest struct {
	URL         string `json:"url" binding:"required"`
	BypassCache bool   `json:"bypassCache"`
}

type TimelineBreakdown struct {
	Blocked float64 `json:"blocked"` // ms
	DNS     float64 `json:"dns"`     // ms
	Connect float64 `json:"connect"` // ms
	SSL     float64 `json:"ssl"`     // ms
	Send    float64 `json:"send"`    // ms
	Wait    float64 `json:"wait"`    // ms (TTFB)
	Receive float64 `json:"receive"` // ms (Content Download)
}

type NetworkRequest struct {
	URL          string            `json:"url"`
	Method       string            `json:"method"`
	StatusCode   int               `json:"statusCode"`
	ResourceType string            `json:"resourceType"` // image, script, stylesheet, document, font, etc.
	MimeType     string            `json:"mimeType"`
	Size         int64             `json:"size"`         // bytes
	StartTime    float64           `json:"startTime"`    // relative to page load start (ms)
	EndTime      float64           `json:"endTime"`      // relative to page load start (ms)
	Duration     float64           `json:"duration"`     // ms
	Timeline     TimelineBreakdown `json:"timeline"`
	ReqHeaders   map[string]string `json:"reqHeaders"`
	RespHeaders  map[string]string `json:"respHeaders"`
	Error        string            `json:"error,omitempty"`
}

type ContentStat struct {
	Type     string `json:"type"`
	Size     int64  `json:"size"`
	Requests int    `json:"requests"`
}

type DomainStat struct {
	Domain   string `json:"domain"`
	Size     int64  `json:"size"`
	Requests int    `json:"requests"`
}

type PerformanceGrade struct {
	Rule        string `json:"rule"`
	Score       int    `json:"score"` // 0-100
	Grade       string `json:"grade"` // A, B, C, D, F
	Description string `json:"description,omitempty"`
	Warning     string `json:"warning,omitempty"`
}

type SpeedTestResult struct {
	TargetURL string `json:"targetUrl"`
	FinalURL  string `json:"finalUrl"`

	// Top Summary
	PerformanceGrade int     `json:"performanceGrade"`
	PerformanceLetter string `json:"performanceLetter"`
	PageSizeBytes    int64   `json:"pageSizeBytes"`
	LoadTimeMs       float64 `json:"loadTimeMs"`
	TotalRequests    int     `json:"totalRequests"`

	// Breakdown
	Grades           []PerformanceGrade `json:"grades"`
	ContentStats     []ContentStat      `json:"contentStats"`
	DomainStats      []DomainStat       `json:"domainStats"`
	ResponseCodes    map[string]int     `json:"responseCodes"` // e.g. "200": 150, "404": 2

	// Waterfall
	Requests []NetworkRequest `json:"requests"`
}
