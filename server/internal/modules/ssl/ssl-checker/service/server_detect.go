// ============================================
// FILE: ssl-checker/service/server_detect.go
//
// Phát hiện loại server dựa trên HTTP response headers.
// Bổ sung ~25 fingerprint so với code cũ.
// ============================================

package service

import (
	"context"
	"strings"
)

// ===========================
// Helper functions
// ===========================

func isGenericServer(v string) bool {
	s := strings.ToLower(v)
	switch s {
	case "server", "unknown", "":
		return true
	}
	return false
}

// normalizeServer chuẩn hoá tên server về dạng gọn, dễ đọc.
func normalizeServer(v string) string {
	s := strings.ToLower(v)

	switch {

	// ===== CDN / Edge =====
	case strings.Contains(s, "cloudflare"):
		return "cloudflare"
	case strings.Contains(s, "cloudfront"):
		return "CloudFront"
	case strings.Contains(s, "fastly"),
		strings.Contains(s, "github"):
		return "Fastly"
	case strings.Contains(s, "akamaighost"):
		return "AkamaiGHost"
	case strings.Contains(s, "akamai"):
		return "Akamai"
	case strings.Contains(s, "sucuri"),
		strings.Contains(s, "cloudproxy"):
		return "Sucuri WAF"
	case strings.Contains(s, "imperva"),
		strings.Contains(s, "incapsula"):
		return "Imperva"

	// ===== Big Tech =====
	case strings.Contains(s, "gws"),
		strings.Contains(s, "esf"):
		return "Google Web Server"
	case strings.Contains(s, "google frontend"):
		return "Google Frontend"
	case strings.Contains(s, "proxygen"):
		return "proxygen-bolt"
	case strings.Contains(s, "awselb"):
		return "AWS ELB"

	// ===== PaaS =====
	case strings.Contains(s, "vercel"):
		return "Vercel"
	case strings.Contains(s, "netlify"):
		return "Netlify"
	case strings.Contains(s, "heroku"):
		return "Heroku"
	case strings.Contains(s, "render"):
		return "Render"
	case strings.Contains(s, "railway"):
		return "Railway"
	case strings.Contains(s, "fly.io"),
		strings.HasPrefix(s, "fly/"):
		return "Fly.io"

	// ===== Reverse Proxy / LB =====
	case strings.Contains(s, "envoy"):
		return "Envoy"
	case strings.Contains(s, "traefik"):
		return "Traefik"
	case strings.Contains(s, "haproxy"):
		return "HAProxy"
	case strings.Contains(s, "varnish"):
		return "Varnish"
	case strings.Contains(s, "caddy"):
		return "Caddy"

	// ===== Web Servers =====
	case strings.Contains(s, "openresty"):
		return "OpenResty"
	case strings.Contains(s, "tengine"):
		return "Tengine"
	case strings.Contains(s, "litespeed"):
		return "LiteSpeed"
	case strings.Contains(s, "kestrel"):
		return "Kestrel"
	case strings.Contains(s, "cowboy"):
		return "Cowboy"
	case strings.Contains(s, "gunicorn"):
		return "gunicorn"
	case strings.Contains(s, "uvicorn"):
		return "uvicorn"
	case strings.Contains(s, "jetty"):
		return "Jetty"
	case strings.Contains(s, "apache-coyote"):
		return "Apache Tomcat"
	case strings.Contains(s, "wildfly"),
		strings.Contains(s, "undertow"):
		return "WildFly"
	}

	return v
}

// ===========================
// Main detection
// ===========================

// DetectServerType gửi HTTP probe rồi phân tích response headers
// để xác định loại web server. Trả về chuỗi rỗng "" nếu không detect được.
func DetectServerType(ctx context.Context, domain string, ip string) string {
	probes := collectProbes(ctx, domain, ip)

	scores := map[string]int{}
	var fallback string

	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" || isGenericServer(v) {
			return
		}
		scores[v]++
	}

	for _, p := range probes {
		if p.Response == nil {
			continue
		}

		h := p.Response.Header
		server := h.Get("Server")
		serverLower := strings.ToLower(server)
		viaLower := strings.ToLower(h.Get("Via"))

		// =====================
		// Strong: Server header
		// =====================
		add(server)

		// =====================
		// Big Tech fingerprints
		// =====================

		// Facebook
		if h.Get("X-Fb-Debug") != "" ||
			h.Get("X-Fb-Connection-Quality") != "" {
			add("proxygen-bolt")
		}

		// Google
		if strings.Contains(strings.ToLower(h.Get("Report-To")), "gws") {
			add("gws")
		}

		// =====================
		// CDN / Edge
		// =====================

		// Cloudflare
		if h.Get("CF-Ray") != "" ||
			strings.Contains(serverLower, "cloudflare") {
			add("cloudflare")
		}

		// CloudFront
		if h.Get("X-Amz-Cf-Id") != "" ||
			h.Get("X-Amz-Cf-Pop") != "" ||
			strings.Contains(viaLower, "cloudfront") {
			add("cloudfront")
		}

		// Fastly
		if strings.Contains(strings.ToLower(h.Get("X-Served-By")), "fastly") ||
			strings.Contains(viaLower, "fastly") {
			add("fastly")
		}

		// Akamai
		if strings.Contains(serverLower, "akamaighost") {
			add("AkamaiGHost")
		} else if strings.Contains(serverLower, "akamai") ||
			strings.Contains(viaLower, "akamai") ||
			h.Get("X-Akamai-Transformed") != "" ||
			h.Get("X-Akamai-Staging") != "" ||
			h.Get("X-Akamai-Request-ID") != "" ||
			h.Get("Akamai-Origin-Hop") != "" {
			add("akamai")
		}

		// =====================
		// PaaS
		// =====================

		// Vercel
		if h.Get("X-Vercel-Id") != "" ||
			strings.Contains(serverLower, "vercel") {
			add("Vercel")
		}

		// Netlify
		if h.Get("X-NF-Request-ID") != "" ||
			strings.Contains(serverLower, "netlify") {
			add("Netlify")
		}

		// Heroku
		if strings.Contains(viaLower, "heroku") {
			add("Heroku")
		}

		// Fly.io
		if h.Get("Fly-Request-Id") != "" {
			add("Fly.io")
		}

		// Render
		if h.Get("Rndr-Id") != "" ||
			strings.Contains(serverLower, "render") {
			add("Render")
		}

		// =====================
		// Cloud LB
		// =====================

		// Azure Front Door
		if h.Get("X-Azure-Ref") != "" ||
			h.Get("X-FD-HealthProbe") != "" {
			add("Azure Front Door")
		}

		// AWS ALB/ELB
		if strings.Contains(serverLower, "awselb") {
			add("AWS ELB")
		}

		// Google Cloud LB
		if strings.Contains(viaLower, "google") &&
			!strings.Contains(serverLower, "gws") {
			add("Google Frontend")
		}

		// =====================
		// Reverse Proxy
		// =====================

		// Envoy
		if strings.Contains(serverLower, "envoy") ||
			h.Get("X-Envoy-Upstream-Service-Time") != "" {
			add("envoy")
		}

		// Varnish
		if h.Get("X-Varnish") != "" ||
			strings.Contains(viaLower, "varnish") {
			add("varnish")
		}

		// =====================
		// WAF / Security
		// =====================

		// Sucuri
		if h.Get("X-Sucuri-ID") != "" ||
			strings.Contains(serverLower, "sucuri") {
			add("Sucuri")
		}

		// Imperva / Incapsula
		if h.Get("X-CDN") == "Imperva" ||
			h.Get("X-Iinfo") != "" {
			add("Imperva")
		}

		// =====================
		// Weak fallback
		// =====================
		if fallback == "" {
			fallback = h.Get("X-Powered-By")
			if fallback == "" {
				fallback = h.Get("Via")
			}
		}
	}

	// Pick winner by highest score
	best := ""
	bestScore := 0

	for k, s := range scores {
		if s > bestScore {
			best = k
			bestScore = s
		}
	}

	if best != "" {
		return normalizeServer(best)
	}

	if fallback != "" {
		return normalizeServer(fallback)
	}

	// Không detect được → frontend hiển thị "Không công khai"
	return ""
}
