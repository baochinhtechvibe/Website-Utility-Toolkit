package models

// Header status constants
const (
	StatusOK      = "ok"
	StatusWarning = "warning"
	StatusDanger  = "danger"
)

// Cookie severity constants
const (
	SeverityHigh   = "high"
	SeverityMedium = "medium"
	SeverityGood   = "good"
)

type AnalyzeRequest struct {
	TargetURL       string `json:"target_url" binding:"required"`
	BypassCache     bool   `json:"bypassCache"`
	FollowRedirects *bool  `json:"followRedirects"`
}

type HeaderResult struct {
	Name         string `json:"name"`
	Status       string `json:"status"` // "ok", "warning", "danger"
	CurrentValue string `json:"current_value"`
	Risk         string      `json:"risk"`
	Fix          string      `json:"fix,omitempty"`
	CSPIssues    []CSPIssue  `json:"csp_issues,omitempty"`
}

type CSPIssue struct {
	Directive string `json:"directive"`
	Severity  string `json:"severity"` // "high", "medium", "low"
	Message   string `json:"message"`
}

// LeakResult — type riêng cho information leakage.
// Không cần Status vì leak luôn là "warning"
type LeakResult struct {
	Name         string `json:"name"`
	CurrentValue string `json:"current_value"`
	Risk         string `json:"risk"`
	Fix          string `json:"fix"`
}

type CookieResult struct {
	Name     string `json:"name"`
	HttpOnly bool   `json:"http_only"`
	Secure   bool   `json:"secure"`
	SameSite string `json:"same_site"`
	Severity string `json:"severity"` // "high", "medium", "good"
}

type ServerConfig struct {
	Nginx  string `json:"nginx"`
	Apache string `json:"apache"`
}

// RawHeader — một cặp header name/value từ HTTP response
type RawHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// AdditionalHeaderResult — header informational (không tính điểm)
type AdditionalHeaderResult struct {
	Name        string `json:"name"`
	Value       string `json:"value"`   // giá trị thực tế, rỗng nếu không có
	Present     bool   `json:"present"` // header có tồn tại không
	Status      string `json:"status"`  // "ok", "info", "warning", "deprecated"
	Description string `json:"description"`
}

type CORSResult struct {
	Status      string `json:"status"` // "ok", "warning", "danger"
	Description string `json:"description"`
	Risk        string `json:"risk,omitempty"`
	Fix         string `json:"fix,omitempty"`
}

type CORSAnalysisResult struct {
	Enabled bool         `json:"enabled"` // true if CORS headers are present
	Error   string       `json:"error,omitempty"`
	Issues  []CORSResult `json:"issues"`
}

type DetectedStack struct {
	Name       string   `json:"name"`
	Confidence string   `json:"confidence"` // "high", "medium", "low"
	Evidence   []string `json:"evidence"`
}

type AnalyzeResponse struct {
	ScannedURL         string                   `json:"scanned_url"`
	FinalURL           string                   `json:"final_url"`
	RedirectCount      int                      `json:"redirect_count"`
	RedirectChain      []RedirectHop            `json:"redirect_chain"`
	HasInsecureSSL     bool                     `json:"has_insecure_ssl"`
	Score              int                      `json:"score"`
	Grade              string                   `json:"grade"` // A+, A, B, C, D, F
	Headers            []HeaderResult           `json:"headers"`
	Cookies            []CookieResult           `json:"cookies"`
	HasSetCookie       bool                     `json:"has_set_cookie"`
	InformationLeakage []LeakResult             `json:"information_leakage"`
	Config             ServerConfig             `json:"config"`
	RawHeaders         []RawHeader              `json:"raw_headers"`
	AdditionalInfo     []AdditionalHeaderResult `json:"additional_info"`
	CORSAnalysis       CORSAnalysisResult       `json:"cors_analysis"`
	DetectedTech       []DetectedStack          `json:"detected_tech"`
}

type RedirectHop struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	HasHSTS    bool   `json:"has_hsts"`
}
