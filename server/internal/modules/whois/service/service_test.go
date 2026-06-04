package service

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"tools.bctechvibe.com/server/internal/modules/whois/models"
)

func TestClassifyTLDType(t *testing.T) {
	// Call IsGTLD with some common ones. 
	// Because we don't want to rely on the external IANA fetch for unit tests,
	// the iana package has legacyGTLDs as a fallback which includes .com
	// But we can manually populate gtldSet if we want, or rely on legacy.
	// For this test, let's just use the legacy ones and some ccTLDs.
	
	tests := []struct {
		domain   string
		isVN     bool
		expected string
	}{
		{"bctechvibe.vn", true, "vn"},
		{"chinhphu.vn", true, "vn"},
		{"google.com", false, "gtld"},
		{"google.net", false, "gtld"},
		{"github.io", false, "cctld"}, // .io is ccTLD
		{"bbc.co.uk", false, "cctld"},
		// app is a new gTLD, it might fall back to cctld if iana fetch hasn't run.
		// So we won't assert it strictly unless we mock iana.
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			result := classifyTLDType(tt.domain, tt.isVN)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestVNNIC_Timeout_FallbackTino(t *testing.T) {
	// Setup a dummy Tino API server
	tinoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := models.TinoAPIResponse{
			Success:   true,
			Domain:    "test.vn",
			Available: false,
			Status:    "registered",
			Whois: &models.TinoWhoisData{
				Domain:         "test.vn",
				Registrar:      "iNET",
				RegistrantName: "Test User",
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer tinoServer.Close()

	// Setup a dummy Port 43 server that times out (sleeps longer than the test timeout or returns nothing)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer l.Close()

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			// Just sleep to simulate timeout
			time.Sleep(5 * time.Second)
			conn.Close()
		}
	}()

	// Override globals
	origTinoAPIBase := tinoAPIBase
	origVnnicServer := vnnicWhoisServer
	defer func() {
		tinoAPIBase = origTinoAPIBase
		vnnicWhoisServer = origVnnicServer
	}()

	tinoAPIBase = tinoServer.URL + "/"
	vnnicWhoisServer = l.Addr().String()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resp, err := queryVNDomain(ctx, "test.vn")
	assert.NoError(t, err)
	assert.NotNil(t, resp)

	// Should fallback to Tino's data
	assert.Equal(t, "Tino API", resp.Source)
	assert.Equal(t, "medium", resp.Confidence)
	assert.False(t, resp.Authoritative)
	assert.Equal(t, "Test User", resp.Registrant)
}


