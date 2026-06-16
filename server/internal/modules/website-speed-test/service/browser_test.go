package service

import (
	"testing"

	"tools.bctechvibe.com/server/internal/modules/website-speed-test/models"
)

func TestCalculatePerformanceGrades(t *testing.T) {
	tests := []struct {
		name           string
		requests       []models.NetworkRequest
		expectedCookie int
		expectedGzip   int
		expectedCache  int
		expectedEmpty  int
	}{
		{
			name: "Perfect Score",
			requests: []models.NetworkRequest{
				{
					URL:          "https://example.com",
					ResourceType: "Document",
					StatusCode:   200,
				},
				{
					URL:          "https://example.com/style.css",
					ResourceType: "Stylesheet",
					StatusCode:   200,
					ReqHeaders:   map[string]string{}, // no cookie
					RespHeaders: map[string]string{
						"Content-Encoding": "gzip",
						"Cache-Control":    "max-age=31536000",
					},
				},
			},
			expectedCookie: 100,
			expectedGzip:   100,
			expectedCache:  100,
			expectedEmpty:  100,
		},
		{
			name: "Poor Score",
			requests: []models.NetworkRequest{
				{
					URL:          "https://example.com",
					ResourceType: "Document",
					StatusCode:   200,
				},
				{
					URL:          "https://example.com/script.js",
					ResourceType: "Other", // Will be normalized by MIME
					MimeType:     "application/javascript",
					StatusCode:   200,
					ReqHeaders:   map[string]string{"Cookie": "session=123"},
					RespHeaders:  map[string]string{}, // missing gzip and cache
				},
				{
					// Empty src simulation: fetches document URL but it's an Image
					URL:          "https://example.com",
					ResourceType: "Image",
					StatusCode:   200,
				},
			},
			expectedCookie: 50, // 1 violation out of 2 static reqs
			expectedGzip:   95, // 100 - (1 * 5)
			expectedCache:  0,
			expectedEmpty:  80, // 100 - (1 * 20)
		},
		{
			name: "Cache Control Directives",
			requests: []models.NetworkRequest{
				{
					URL:          "https://example.com",
					ResourceType: "Document",
					StatusCode:   200,
				},
				{
					URL:          "https://example.com/no-store.js",
					ResourceType: "Script",
					StatusCode:   200,
					RespHeaders: map[string]string{
						"Cache-Control": "no-store",
					},
				},
				{
					URL:          "https://example.com/max-age-0.css",
					ResourceType: "Stylesheet",
					StatusCode:   200,
					RespHeaders: map[string]string{
						"Cache-Control": "max-age=0",
					},
				},
				{
					URL:          "https://example.com/private.jpg",
					ResourceType: "Image",
					StatusCode:   200,
					RespHeaders: map[string]string{
						"Cache-Control": "private",
					},
				},
			},
			expectedCookie: 100, // No cookie headers sent in test
			expectedGzip:   90,  // 2 text static requests missing gzip: 100 - (2 * 5)
			expectedCache:  0,   // 3 static requests missing cache (all 3): 100 - (3 * 100 / 3) = 0
			expectedEmpty:  100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := &models.SpeedTestResult{
				FinalURL:      "https://example.com",
				TotalRequests: len(tt.requests),
				Requests:      tt.requests,
			}

			calculatePerformanceGrades(res)

			getScore := func(ruleName string) int {
				for _, g := range res.Grades {
					if g.Rule == ruleName {
						return g.Score
					}
				}
				return -1
			}

			if got := getScore("Sử dụng tên miền Cookie-free"); got != tt.expectedCookie {
				t.Errorf("Cookie score = %v, want %v", got, tt.expectedCookie)
			}
			if got := getScore("Nén tài nguyên bằng Gzip/Brotli"); got != tt.expectedGzip {
				t.Errorf("Gzip score = %v, want %v", got, tt.expectedGzip)
			}
			if got := getScore("Bổ sung HTTP Header Cache/Expires"); got != tt.expectedCache {
				t.Errorf("Cache score = %v, want %v", got, tt.expectedCache)
			}
			if got := getScore("Tránh để trống thuộc tính src/href"); got != tt.expectedEmpty {
				t.Errorf("Empty src score = %v, want %v", got, tt.expectedEmpty)
			}
		})
	}
}
