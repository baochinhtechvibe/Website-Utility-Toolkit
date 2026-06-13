package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestIDNNormalization(t *testing.T) {
	// whoisIDNAProfile is package level in handlers.go
	tests := []struct {
		input    string
		expected string
		hasError bool
	}{
		{"việt.vn", "xn--vit-5kz.vn", false},
		{"日本語.jp", "xn--wgv71a119e.jp", false},
		{"google.com", "google.com", false},
		// Tricky characters that might fail IDN lookup profile
		{"\u200D", "", true}, 
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			ascii, err := whoisIDNAProfile.ToASCII(tt.input)
			if tt.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, ascii)
			}
		})
	}
}

func TestHandleWhoisLookup_IPv4(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	c.Request = httptest.NewRequest("GET", "/api/whois/lookup?domain=1.1.1.1", nil)
	HandleWhoisLookup(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "địa chỉ IP hiện chưa được hỗ trợ")
}

func TestHandleWhoisLookup_Timeout(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	// Tạo một request với context đã hết hạn (timeout)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()
	time.Sleep(5 * time.Millisecond) // Đảm bảo context hết hạn

	req := httptest.NewRequest("GET", "/api/whois/lookup?domain=example.com", nil)
	c.Request = req.WithContext(ctx)

	HandleWhoisLookup(c)

	assert.Equal(t, http.StatusGatewayTimeout, w.Code)
	assert.Contains(t, w.Body.String(), "quá hạn")
}
