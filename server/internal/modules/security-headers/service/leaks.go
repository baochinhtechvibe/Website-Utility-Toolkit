// ============================================
// FILE: security-headers/service/leaks.go
//
// Phân tích Information Leakage:
//   - Server header (nginx/1.18, Apache/2.4)
//   - X-Powered-By header (PHP/8.1, Express)
//   - X-AspNet-Version (ASP.NET version)
//   - X-AspNetMvc-Version (ASP.NET MVC version)
//   - X-Generator (CMS/Generator: WordPress, Drupal)
//
// Mỗi leak trừ 2 điểm (low severity)
// ============================================

package service

import (
	"net/http"
	"strings"

	"tools.bctechvibe.com/server/internal/modules/security-headers/models"
)

// LeakAnalysisResult chứa output phân tích information leak
type LeakAnalysisResult struct {
	Leaks     []models.LeakResult
	Penalty   int
	TechStack []models.DetectedStack
}

// leakHeaderDef định nghĩa một header cần check leak
type leakHeaderDef struct {
	Name string
	Risk string
	Fix  string
}

// Danh sách header leak cần kiểm tra
var leakHeaders = []leakHeaderDef{
	{
		Name: "Server",
		Risk: "Rò rỉ thông tin: giúp attacker nhận diện software stack (VD: Nginx phiên bản có lỗ hổng).",
		Fix:  "Thêm 'server_tokens off;' trong Nginx hoặc 'ServerTokens Prod' trong Apache.",
	},
	{
		Name: "X-Powered-By",
		Risk: "Rò rỉ thông tin: tiết lộ ngôn ngữ hoặc framework backend (VD: PHP, Express).",
		Fix:  "Với PHP: 'expose_php = Off' trong php.ini. Với Express: app.disable('x-powered-by').",
	},
	{
		Name: "X-AspNet-Version",
		Risk: "Rò rỉ thông tin: tiết lộ phiên bản ASP.NET đang chạy.",
		Fix:  "Thêm '<httpRuntime enableVersionHeader=\"false\" />' trong web.config.",
	},
	{
		Name: "X-AspNetMvc-Version",
		Risk: "Rò rỉ thông tin: tiết lộ phiên bản ASP.NET MVC framework.",
		Fix:  "Thêm 'MvcHandler.DisableMvcResponseHeader = true;' trong Application_Start().",
	},
	{
		Name: "X-Generator",
		Risk: "Rò rỉ thông tin: tiết lộ CMS hoặc Generator (VD: WordPress, Drupal).",
		Fix:  "Xóa HTTP header X-Generator tại web server/proxy. Với WordPress meta tag: thêm remove_action('wp_head', 'wp_generator') vào functions.php.",
	},
}

// analyzeLeaks phát hiện rò rỉ thông tin Server Stack
func analyzeLeaks(resp *http.Response) LeakAnalysisResult {
	var leaks []models.LeakResult
	penalty := 0

	for _, def := range leakHeaders {
		value := resp.Header.Get(def.Name)
		if value != "" {
			penalty += 2
			leaks = append(leaks, models.LeakResult{
				Name:         def.Name,
				CurrentValue: value,
				Risk:         def.Risk,
				Fix:          def.Fix,
			})
		}
	}

	var techStack []models.DetectedStack

	server := strings.ToLower(resp.Header.Get("Server"))
	if strings.Contains(server, "nginx") {
		techStack = append(techStack, models.DetectedStack{
			Name:       "nginx",
			Confidence: "high",
			Evidence:   []string{"Server: " + resp.Header.Get("Server")},
		})
	} else if strings.Contains(server, "apache") {
		techStack = append(techStack, models.DetectedStack{
			Name:       "apache",
			Confidence: "high",
			Evidence:   []string{"Server: " + resp.Header.Get("Server")},
		})
	} else if strings.Contains(server, "cloudflare") {
		techStack = append(techStack, models.DetectedStack{
			Name:       "cloudflare",
			Confidence: "high",
			Evidence:   []string{"Server: " + resp.Header.Get("Server")},
		})
	}

	xPoweredBy := strings.ToLower(resp.Header.Get("X-Powered-By"))
	if strings.Contains(xPoweredBy, "express") {
		techStack = append(techStack, models.DetectedStack{
			Name:       "express",
			Confidence: "high",
			Evidence:   []string{"X-Powered-By: " + resp.Header.Get("X-Powered-By")},
		})
	} else if strings.Contains(xPoweredBy, "php") {
		techStack = append(techStack, models.DetectedStack{
			Name:       "php",
			Confidence: "high",
			Evidence:   []string{"X-Powered-By: " + resp.Header.Get("X-Powered-By")},
		})
	} else if strings.Contains(xPoweredBy, "asp.net") || resp.Header.Get("X-AspNet-Version") != "" {
		evidence := []string{}
		if resp.Header.Get("X-Powered-By") != "" {
			evidence = append(evidence, "X-Powered-By: "+resp.Header.Get("X-Powered-By"))
		}
		if resp.Header.Get("X-AspNet-Version") != "" {
			evidence = append(evidence, "X-AspNet-Version: "+resp.Header.Get("X-AspNet-Version"))
		}
		techStack = append(techStack, models.DetectedStack{
			Name:       "asp.net",
			Confidence: "high",
			Evidence:   evidence,
		})
	}

	xGenerator := strings.ToLower(resp.Header.Get("X-Generator"))
	if strings.Contains(xGenerator, "wordpress") || strings.Contains(strings.ToLower(resp.Header.Get("Link")), "wp-json") {
		evidence := []string{}
		if resp.Header.Get("X-Generator") != "" {
			evidence = append(evidence, "X-Generator: "+resp.Header.Get("X-Generator"))
		}
		techStack = append(techStack, models.DetectedStack{
			Name:       "wordpress",
			Confidence: "high",
			Evidence:   evidence,
		})
	}

	return LeakAnalysisResult{
		Leaks:     leaks,
		Penalty:   penalty,
		TechStack: techStack,
	}
}
