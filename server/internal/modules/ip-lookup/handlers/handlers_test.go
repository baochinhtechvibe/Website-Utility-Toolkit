package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestHandleCheckIP_TrustedProxiesGuard(t *testing.T) {
	// Setup Gin to Release mode to test the guard
	gin.SetMode(gin.ReleaseMode)
	defer gin.SetMode(gin.TestMode)

	r := gin.New()
	r.GET("/my-ip/check", HandleCheckIP)

	req, _ := http.NewRequest("GET", "/my-ip/check", nil)
	// Simulate a request from a private IP (e.g., misconfigured proxy)
	req.RemoteAddr = "192.168.1.1:12345"
	req.Header.Set("X-Forwarded-For", "192.168.1.1")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status code 500, got %v", w.Code)
	}

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if success, ok := response["success"].(bool); !ok || success != false {
		t.Errorf("Expected success=false, got %v", response["success"])
	}

	if msg, ok := response["message"].(string); !ok || msg == "" {
		t.Errorf("Expected error message, got %v", response["message"])
	}
}

func TestHandleMyIP_TrustedProxiesGuard(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	defer gin.SetMode(gin.TestMode)

	r := gin.New()
	r.GET("/my-ip", HandleMyIP)

	req, _ := http.NewRequest("GET", "/my-ip", nil)
	req.RemoteAddr = "10.0.0.1:54321"
	req.Header.Set("X-Real-IP", "10.0.0.1")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status code 500, got %v", w.Code)
	}
}
