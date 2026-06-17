package handlers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestHandleAnalyze_MaxBytesReader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/analyze", HandleAnalyze)

	// Create a large body string > 64KB
	largeBody := `{"target_url":"https://example.com","bypassCache":false,"followRedirects":true,"padding":"` + strings.Repeat("A", 65536) + `"}`

	req, _ := http.NewRequest(http.MethodPost, "/analyze", bytes.NewBufferString(largeBody))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status Bad Request 400 for oversized body, got %d", w.Code)
	}
}
