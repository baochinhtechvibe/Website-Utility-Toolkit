package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchAndParseRobots_StatusMatrix(t *testing.T) {
	// Override HTTP clients to bypass SSRF protection (SafeDialContext) during testing
	oldDefaultClient := defaultClient
	oldInsecureClient := insecureClient
	defer func() {
		defaultClient = oldDefaultClient
		insecureClient = oldInsecureClient
	}()
	noRedirectClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defaultClient = noRedirectClient
	insecureClient = noRedirectClient

	cases := []struct {
		name           string
		handlers       func(w http.ResponseWriter, r *http.Request)
		expectedStatus RobotsAccessStatus
	}{
		{
			name: "Direct 200",
			handlers: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
				w.Write([]byte("User-agent: *\nAllow: /"))
			},
			expectedStatus: RobotsStatus2xx,
		},
		{
			name: "Direct 401 Allow (RFC 9309 & Google)",
			handlers: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(401)
			},
			expectedStatus: RobotsStatus4xx,
		},
		{
			name: "Direct 403 Allow (RFC 9309 & Google)",
			handlers: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(403)
			},
			expectedStatus: RobotsStatus4xx,
		},
		{
			name: "Direct 429 Block (Google Policy)",
			handlers: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(429)
			},
			expectedStatus: RobotsStatus5xx,
		},
		{
			name: "Direct 404 Allow (RFC 9309)",
			handlers: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(404)
			},
			expectedStatus: RobotsStatus4xx,
		},
		{
			name: "Redirect 302 to 403 (Allow)",
			handlers: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/robots.txt" {
					http.Redirect(w, r, "/login", http.StatusFound)
					return
				}
				w.WriteHeader(403)
			},
			expectedStatus: RobotsStatus4xx,
		},
		{
			name: "Redirect 301 to 404",
			handlers: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/robots.txt" {
					http.Redirect(w, r, "/missing", http.StatusMovedPermanently)
					return
				}
				w.WriteHeader(404)
			},
			expectedStatus: RobotsStatus4xx,
		},
		{
			name: "Redirect 301 to 500",
			handlers: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/robots.txt" {
					http.Redirect(w, r, "/error", http.StatusMovedPermanently)
					return
				}
				w.WriteHeader(500)
			},
			expectedStatus: RobotsStatus5xx,
		},
		{
			name: "Redirect Loop > 5 hops (P2 review fix)",
			handlers: func(w http.ResponseWriter, r *http.Request) {
				// Redirect vô tận
				http.Redirect(w, r, r.URL.Path+"-redirect", http.StatusFound)
			},
			expectedStatus: RobotsStatus4xx,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(c.handlers))
			defer ts.Close()

			res, _ := FetchAndParseRobots(context.Background(), ts.URL, "googlebot", false)
			// Không check err vì redirect loop sẽ sinh ra err nhưng chúng ta vẫn muốn kiểm tra res.FetchStatus
			if res.FetchStatus != c.expectedStatus {
				t.Errorf("expected status %s, got %s", c.expectedStatus, res.FetchStatus)
			}
		})
	}
}
