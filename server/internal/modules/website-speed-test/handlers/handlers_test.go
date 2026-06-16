package handlers

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"tools.bctechvibe.com/server/internal/modules/website-speed-test/models"
)

func TestHandleAnalyze_Validation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name         string
		payload      models.SpeedTestRequest
		expectedCode int
	}{
		{
			name: "Empty URL",
			payload: models.SpeedTestRequest{
				URL: "",
			},
			expectedCode: http.StatusBadRequest,
		},
		{
			name: "Localhost SSRF",
			payload: models.SpeedTestRequest{
				URL: "http://127.0.0.1:5500",
			},
			expectedCode: http.StatusBadRequest, // Should be rejected by IsSafeHostname
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.POST("/analyze", HandleAnalyze)

			body, _ := json.Marshal(tt.payload)
			req, _ := http.NewRequest(http.MethodPost, "/analyze", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != tt.expectedCode {
				t.Errorf("expected status %d, got %d. Body: %s", tt.expectedCode, w.Code, w.Body.String())
			}
		})
	}
}

func TestHandleAnalyze_CacheBypassLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/analyze", HandleAnalyze)

	// Seed cache directly
	cacheKey := fmt.Sprintf("%x", sha256.Sum256([]byte("https://example.com|v=1")))
	speedTestCache.Set(cacheKey, cachedResult{
		Data: &models.SpeedTestResult{
			TargetURL: "https://example.com",
			FinalURL:  "https://example.com",
		},
		FetchedAt: time.Now(),
	}, 5*time.Minute)

	for i := 0; i < 15; i++ {
		payload := models.SpeedTestRequest{
			URL:         "https://example.com",
			BypassCache: false,
		}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest(http.MethodPost, "/analyze", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		// Simulate same IP to trigger limiter if cache fails
		req.RemoteAddr = "127.0.0.1:12345"

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Iteration %d: expected 200, got %d. Body: %s", i, w.Code, w.Body.String())
		}
		
		var resp map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}
		
		meta, ok := resp["meta"].(map[string]interface{})
		if !ok || meta["cached"] != true {
			t.Errorf("Iteration %d: expected cached=true, got %v", i, meta["cached"])
		}
	}
}

func TestHandleAnalyze_OversizedBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/analyze", HandleAnalyze)

	// Tạo payload có kích thước > 64KB
	largePadding := string(make([]byte, 70*1024)) // 70KB
	payload := map[string]string{
		"url":     "https://example.com",
		"padding": largePadding,
	}
	body, _ := json.Marshal(payload)

	req, _ := http.NewRequest(http.MethodPost, "/analyze", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// MaxBytesReader sẽ khiến ShouldBindJSON trả về lỗi
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d for oversized body, got %d", http.StatusBadRequest, w.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Errorf("Failed to parse response body: %v. Body was: %s", err, w.Body.String())
	} else {
		if success, ok := resp["success"].(bool); !ok || success != false {
			t.Errorf("Expected success=false, got %v", resp["success"])
		}
		if msg, ok := resp["message"].(string); !ok || msg == "" {
			t.Errorf("Expected an error message, got empty or missing")
		}
	}
}
