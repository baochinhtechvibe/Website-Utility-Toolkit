package service

import (
	"testing"
)

func TestNormalizeForLoop(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Trường hợp domain trần (chưa chuẩn hoá, nhưng url.Parse có thể lỗi hoặc không)",
			input:    "https://example.com",
			expected: "https://example.com",
		},
		{
			name:     "Trailing slash KHÔNG bị xoá sai",
			input:    "https://example.com/blog/",
			expected: "https://example.com/blog/",
		},
		{
			name:     "Không có trailing slash giữ nguyên",
			input:    "https://example.com/blog",
			expected: "https://example.com/blog",
		},
		{
			name:     "Loại bỏ fragment / anchor",
			input:    "https://example.com/page#section1",
			expected: "https://example.com/page",
		},
		{
			name:     "Giữ nguyên query parameter",
			input:    "https://example.com/page?test=1&sort=desc",
			expected: "https://example.com/page?test=1&sort=desc",
		},
		{
			name:     "Query string và loại bỏ fragment",
			input:    "https://example.com/page?test=1#section1",
			expected: "https://example.com/page?test=1",
		},
		{
			name:     "Chữ hoa chữ thường ở Hostname",
			input:    "HTTPS://EXAMPLE.COM/Page",
			expected: "https://example.com/Page",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeForLoop(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeForLoop(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}
