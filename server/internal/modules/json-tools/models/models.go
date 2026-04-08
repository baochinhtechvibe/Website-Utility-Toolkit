package models

// ConvertRequest là request chung cho JSON → Go Struct và JSON → YAML
type ConvertRequest struct {
	JSON string `json:"json" binding:"required"`
}

// ConvertResponse là response chung cho các chức năng convert
type ConvertResponse struct {
	Result string `json:"result"`
}
