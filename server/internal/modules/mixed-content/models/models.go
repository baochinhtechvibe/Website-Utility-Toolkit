package models

// ScanRequest là payload gửi từ client
type ScanRequest struct {
	URL              string `json:"url" binding:"required"`
	IgnoreTLSErrors  bool   `json:"ignoreTLSErrors"`
}

// MixedItem đại diện một tài nguyên HTTP tìm thấy trên trang HTTPS
type MixedItem struct {
	URL           string `json:"url"`            // URL dạng http://...
	Type          string `json:"type"`           // Active | Passive
	Subtype       string `json:"subtype"`        // script, img, iframe, audio, video, css, font, other
	Origin        string `json:"origin"`         // same-domain | third-party
	FoundIn       string `json:"foundIn"`        // HTML element tìm thấy, VD: <script src>, <img src>
	FixSuggestion string `json:"fixSuggestion"`  // gợi ý fix: thay http:// → https://
}

// ScanData chứa kết quả scan
type ScanData struct {
	ScannedURL   string      `json:"scannedUrl"`
	TotalFound   int         `json:"totalFound"`
	ActiveCount  int         `json:"activeCount"`
	PassiveCount int         `json:"passiveCount"`
	Items        []MixedItem `json:"items"`
	Truncated    bool        `json:"truncated"` // true nếu có hơn 200 items
}

// ScanResponse là response trả về client
type ScanResponse struct {
	Success bool      `json:"success"`
	Message string    `json:"message,omitempty"`
	Data    *ScanData `json:"data,omitempty"`
}
