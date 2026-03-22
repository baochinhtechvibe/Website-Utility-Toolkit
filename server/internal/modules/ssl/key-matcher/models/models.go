// ============================================
// FILE: key-matcher/models/models.go
//
// Cấu trúc dữ liệu cho SSL Key Matcher
// ============================================

package models

type MatchRequest struct {
	Type   string `json:"type" binding:"required"` // cert_key | csr_cert
	Input1 string `json:"input1" binding:"required"`
	Input2 string `json:"input2" binding:"required"`
}

// InputErrors chứa lỗi riêng cho từng input — chỉ set khi có parse error
type InputErrors struct {
	Input1 string `json:"input1,omitempty"`
	Input2 string `json:"input2,omitempty"`
}

// MatchResponse là response duy nhất của Key Matcher.
// Nếu InputErrors != nil → có lỗi parse, không đối soát được.
// Nếu InputErrors == nil → Matched chứa kết quả khớp/không khớp.
type MatchResponse struct {
	Matched     bool         `json:"matched"`
	Status      string       `json:"status"`
	Message     string       `json:"message"`
	Hash1       string       `json:"hash1,omitempty"`
	Hash2       string       `json:"hash2,omitempty"`
	KeyType     string       `json:"key_type,omitempty"`
	KeySize     int          `json:"key_size,omitempty"`
	InputErrors *InputErrors `json:"input_errors,omitempty"`
}
