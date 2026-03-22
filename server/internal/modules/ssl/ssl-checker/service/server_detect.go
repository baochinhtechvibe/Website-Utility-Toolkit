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

// normalizeServer chuẩn hoá tên server về dạng gọn, dễ đọc và gán độ ưu tiên.
// Độ ưu tiên: CDN (100) > BigTech (90) > PaaS (80) > Proxy (60) > Web Server (40)
func normalizeServer(v string) (string, int) {
	s := strings.ToLower(v)

	switch {
	// ===== CDN / Edge (100) =====
	case strings.Contains(s, "cloudflare"):
		return "Cloudflare", 100
	case strings.Contains(s, "cloudfront"):
		return "CloudFront", 100
	case strings.Contains(s, "fastly"), strings.Contains(s, "github"):
		return "Fastly", 100
	case strings.Contains(s, "akamaighost"):
		return "AkamaiGHost", 100
	case strings.Contains(s, "akamai"):
		return "Akamai", 100
	case strings.Contains(s, "sucuri"), strings.Contains(s, "cloudproxy"):
		return "Sucuri WAF", 100
	case strings.Contains(s, "imperva"), strings.Contains(s, "incapsula"):
		return "Imperva", 100

	// ===== Big Tech (90) =====
	case strings.Contains(s, "gws"), strings.Contains(s, "esf"):
		return "Google Web Server", 90
	case strings.Contains(s, "google frontend"):
		return "Google Frontend", 90
	case strings.Contains(s, "proxygen"):
		return "proxygen-bolt", 90
	case strings.Contains(s, "awselb"):
		return "AWS ELB", 90
	case strings.Contains(s, "azure front door"):
		return "Azure Front Door", 90

	// ===== PaaS (80) =====
	case strings.Contains(s, "vercel"):
		return "Vercel", 80
	case strings.Contains(s, "netlify"):
		return "Netlify", 80
	case strings.Contains(s, "heroku"):
		return "Heroku", 80
	case strings.Contains(s, "render"):
		return "Render", 80
	case strings.Contains(s, "railway"):
		return "Railway", 80
	case strings.Contains(s, "fly.io"), strings.HasPrefix(s, "fly/"):
		return "Fly.io", 80

	// ===== Reverse Proxy / LB (60) =====
	case strings.Contains(s, "envoy"):
		return "Envoy", 60
	case strings.Contains(s, "traefik"):
		return "Traefik", 60
	case strings.Contains(s, "haproxy"):
		return "HAProxy", 60
	case strings.Contains(s, "varnish"):
		return "Varnish", 60
	case strings.Contains(s, "caddy"):
		return "Caddy", 60

	// ===== Web Servers (40) =====
	case strings.Contains(s, "openresty"):
		return "OpenResty", 40
	case strings.Contains(s, "tengine"):
		return "Tengine", 40
	case strings.Contains(s, "litespeed"):
		return "LiteSpeed", 40
	case strings.Contains(s, "kestrel"):
		return "Kestrel", 40
	case strings.Contains(s, "cowboy"):
		return "Cowboy", 40
	case strings.Contains(s, "gunicorn"):
		return "gunicorn", 40
	case strings.Contains(s, "uvicorn"):
		return "uvicorn", 40
	case strings.Contains(s, "jetty"):
		return "Jetty", 40
	case strings.Contains(s, "apache-coyote"):
		return "Apache Tomcat", 40
	case strings.Contains(s, "wildfly"), strings.Contains(s, "undertow"):
		return "WildFly", 40
	}

	return v, 20 // Unknown / Generic
}

// ===========================
// Main detection
// ===========================

// DetectServerType gửi HTTP probe rồi phân tích response headers
// để xác định loại web server. Trả về chuỗi rỗng "" nếu không detect được.
func DetectServerType(ctx context.Context, domain string, ip string) string {
	probes := collectProbes(ctx, domain, ip)

	type scoreInfo struct {
		count    int
		priority int
	}
	scores := map[string]*scoreInfo{}
	var fallback string

	add := func(v string) {
		name, priority := normalizeServer(v)
		name = strings.TrimSpace(name)
		if name == "" || isGenericServer(name) {
			return
		}
		if _, ok := scores[name]; !ok {
			scores[name] = &scoreInfo{priority: priority}
		}
		scores[name].count++
	}

	for _, p := range probes {
		if p.Response == nil {
			continue
		}

		h := p.Response.Header
		server := h.Get("Server")
		viaLower := strings.ToLower(h.Get("Via"))

		// 1. Dùng header Server gốc
		add(server)

		// 2. Dùng fingerprints (nhận diện thêm từ các header khác)
		// Cloudflare
		if h.Get("CF-Ray") != "" {
			add("Cloudflare")
		}
		// CloudFront
		if h.Get("X-Amz-Cf-Id") != "" || h.Get("X-Amz-Cf-Pop") != "" || strings.Contains(viaLower, "cloudfront") {
			add("CloudFront")
		}
		// Fastly
		if strings.Contains(strings.ToLower(h.Get("X-Served-By")), "fastly") || strings.Contains(viaLower, "fastly") {
			add("Fastly")
		}
		// Akamai
		if h.Get("X-Akamai-Transformed") != "" || h.Get("X-Akamai-Request-ID") != "" {
			add("Akamai")
		}
		// Vercel
		if h.Get("X-Vercel-Id") != "" {
			add("Vercel")
		}
		// Netlify
		if h.Get("X-NF-Request-ID") != "" {
			add("Netlify")
		}
		// Fly.io
		if h.Get("Fly-Request-Id") != "" {
			add("Fly.io")
		}
		// Azure Front Door
		if h.Get("X-Azure-Ref") != "" {
			add("Azure Front Door")
		}
		// Facebook/Proxygen
		if h.Get("X-Fb-Debug") != "" {
			add("proxygen-bolt")
		}
		// Envoy
		if h.Get("X-Envoy-Upstream-Service-Time") != "" {
			add("Envoy")
		}

		// Weak fallback
		if fallback == "" {
			fallback = h.Get("X-Powered-By")
			if fallback == "" {
				fallback = h.Get("Via")
			}
		}
	}

	// Pick winner: 
	// 1. Cao nhất về count (số lần xuất hiện qua các probe)
	// 2. Tie-break theo priority (CDN > PaaS > Proxy...)
	// 3. Tie-break cuối cùng theo Alphabet để đảm bảo tính deterministic
	best := ""
	bestCount := 0
	bestPriority := 0

	for name, info := range scores {
		isBetter := false
		if info.count > bestCount {
			isBetter = true
		} else if info.count == bestCount {
			if info.priority > bestPriority {
				isBetter = true
			} else if info.priority == bestPriority {
				if name < best || best == "" {
					isBetter = true
				}
			}
		}

		if isBetter {
			best = name
			bestCount = info.count
			bestPriority = info.priority
		}
	}

	if best != "" {
		return best
	}

	if fallback != "" {
		name, _ := normalizeServer(fallback)
		return name
	}

	return ""
}
