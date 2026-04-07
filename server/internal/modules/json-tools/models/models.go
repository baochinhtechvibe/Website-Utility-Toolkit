package models

// ConvertRequest là request chung cho JSON → Go Struct và JSON → YAML
type ConvertRequest struct {
	JSON string `json:"json" binding:"required"`
}

// ConvertResponse là response chung cho các chức năng convert
type ConvertResponse struct {
	Result string `json:"result"`
}

// DiffRequest là request cho so sánh JSON
type DiffRequest struct {
	Original string `json:"original" binding:"required"`
	Modified string `json:"modified" binding:"required"`
}

// DiffEntry chứa thông tin 1 key thay đổi
type DiffEntry struct {
	Key      string      `json:"key"`
	Type     string      `json:"type"` // "added", "removed", "modified"
	OldValue interface{} `json:"oldValue,omitempty"`
	NewValue interface{} `json:"newValue,omitempty"`
	Value    interface{} `json:"value,omitempty"`
}

// DiffResponse là response cho chức năng diff
type DiffResponse struct {
	Added    []DiffEntry `json:"added"`
	Removed  []DiffEntry `json:"removed"`
	Modified []DiffEntry `json:"modified"`
	Summary  DiffSummary `json:"summary"`
}

// DiffSummary tóm tắt số lượng thay đổi
type DiffSummary struct {
	TotalAdded    int `json:"totalAdded"`
	TotalRemoved  int `json:"totalRemoved"`
	TotalModified int `json:"totalModified"`
}
