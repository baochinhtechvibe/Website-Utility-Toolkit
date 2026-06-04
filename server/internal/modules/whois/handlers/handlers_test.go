package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

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
