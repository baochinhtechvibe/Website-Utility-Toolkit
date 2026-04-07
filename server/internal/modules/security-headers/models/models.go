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
	TargetURL string `json:"target_url" binding:"required"`
}

type HeaderResult struct {
	Name         string `json:"name"`
	Status       string `json:"status"` // "ok", "warning", "danger"
	CurrentValue string `json:"current_value"`
	Risk         string `json:"risk"`
	Fix          string `json:"fix,omitempty"`
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

type AnalyzeResponse struct {
	ScannedURL         string         `json:"scanned_url"`
	FinalURL           string         `json:"final_url"`
	RedirectCount      int            `json:"redirect_count"`
	HasInsecureSSL     bool           `json:"has_insecure_ssl"`
	Score              int            `json:"score"`
	Grade              string         `json:"grade"` // A+, A, B, C, D, F
	Headers            []HeaderResult `json:"headers"`
	Cookies            []CookieResult `json:"cookies"`
	HasSetCookie       bool           `json:"has_set_cookie"`
	InformationLeakage []LeakResult   `json:"information_leakage"`
	Config             ServerConfig   `json:"config"`
}

