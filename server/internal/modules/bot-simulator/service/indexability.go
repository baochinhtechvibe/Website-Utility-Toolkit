package service

import (
	"fmt"
	"strings"

	"tools.bctechvibe.com/server/internal/modules/bot-simulator/models"
)

// VerdictResult | Indexable | Blocked | Risky | Unknown
type VerdictResult string

const (
	VerdictIndexable VerdictResult = "Indexable"
	VerdictBlocked   VerdictResult = "Blocked"
	VerdictRisky     VerdictResult = "Risky"
	VerdictUnknown   VerdictResult = "Unknown"
)

// IndexabilityStatus cho từng dimension
const (
	IndexStatusAllowed              = "allowed"
	IndexStatusBlocked              = "blocked"
	IndexStatusUnknownDueToCrawlBlock = "unknown_due_to_crawl_block"
)

// CrawlStatus cho crawl_access
const (
	CrawlAllowed    = "allowed"
	CrawlBlocked    = "blocked"
	CrawlTimeout    = "timeout"
	CrawlError      = "error"
	CrawlDeferred   = "deferred" // 5xx → bot nên hoãn
	CrawlUnreachable = "unreachable"
)

// EvaluateAccess đánh giá đầy đủ crawl_access, indexability, và suy ra verdict.
// Đây là trái tim của indexability engine.
func EvaluateAccess(
	botDecision RobotsDecision,
	robotsResult *RobotsParseResult,
	meta *MetaParseResult,
	serving *models.Serving,
	botFamily string,
) (models.CrawlAccess, models.Indexability, models.Verdict) {

	crawlAccess := models.CrawlAccess{}
	indexability := models.Indexability{}
	verdict := models.Verdict{}

	reasons := []string{}
	suggestions := []string{}

	// ─── Bước 1: Đánh giá Crawl Access ────────────────────────────────

	// Xét robots fetch status
	if robotsResult != nil {
		crawlAccess.RobotsStatus = string(robotsResult.FetchStatus)
	}

	// Xét quyết định từ robots.txt
	switch {
	case serving.InitialStatusCode == 0 || serving.FinalURL == "":
		// Không lấy được trang
		crawlAccess.Status = CrawlError
		if robotsResult != nil && robotsResult.FetchStatus == RobotsStatusTimeout {
			crawlAccess.Status = CrawlTimeout
		} else if robotsResult != nil && robotsResult.FetchStatus == RobotsStatusUnreachable {
			crawlAccess.Status = CrawlUnreachable
		}

	case robotsResult != nil && robotsResult.FetchStatus == RobotsStatus5xx:
		// 5xx robots → bot nên hoãn
		crawlAccess.Status = CrawlDeferred
		reasons = append(reasons, "ROBOTS_5XX")
		suggestions = append(suggestions, "Máy chủ đang gặp lỗi. Bot thường hoãn crawl khi gặp lỗi 5xx từ robots.txt.")

	case !botDecision.Allowed:
		crawlAccess.Status = CrawlBlocked
		crawlAccess.MatchedGroup = botDecision.MatchedGroup
		crawlAccess.MatchedRule = botDecision.MatchedRule
		crawlAccess.Decision = botDecision.Decision
		reasons = append(reasons, "ROBOTS_DISALLOW")
		suggestions = append(suggestions, fmt.Sprintf("Xoá rule Disallow: %s trong robots.txt để cho phép bot crawl.", botDecision.MatchedRule))

	default:
		crawlAccess.Status = CrawlAllowed
		crawlAccess.MatchedGroup = botDecision.MatchedGroup
		crawlAccess.MatchedRule = botDecision.MatchedRule
		crawlAccess.Decision = botDecision.Decision
	}

	// ─── Bước 2: Đánh giá Indexability (dựa trên precedence rule) ──────
	//
	// PRECEDENCE RULE CỨNG:
	// Nếu bot bị chặn crawl → bot không đọc được nội dung trang →
	// không biết meta robots/X-Robots-Tag → indexability = unknown_due_to_crawl_block.
	// (Bot vẫn có thể giữ URL-only entry nếu biết URL từ nguồn khác)

	if crawlAccess.Status == CrawlBlocked || crawlAccess.Status == CrawlDeferred {
		indexability.Status = IndexStatusUnknownDueToCrawlBlock
		indexability.Note = "Bot bị chặn crawl nên không thể đọc meta robots/X-Robots-Tag. " +
			"Trang vẫn có thể xuất hiện trong index dưới dạng URL-only nếu search engine biết URL từ nguồn khác."
		reasons = append(reasons, "CRAWL_BLOCK_UNKNOWN_INDEX")
	} else if crawlAccess.Status == CrawlError || crawlAccess.Status == CrawlUnreachable || crawlAccess.Status == CrawlTimeout {
		indexability.Status = IndexStatusUnknownDueToCrawlBlock
		indexability.Note = "Không thể lấy nội dung trang để đánh giá tín hiệu indexability."
	} else {
		// Crawl OK → đọc meta signals
		indexability.MetaRobots = meta.MetaRobots
		indexability.XRobotsTag = meta.XRobotsTag
		indexability.CanonicalURL = meta.Canonical
		indexability.CanonicalSelf = meta.CanonicalSelf
		indexability.CanonicalMissing = meta.CanonicalMissing

		isNoindex := HasNoindex(meta.MetaRobots) || HasNoindex(meta.XRobotsTag)

		if isNoindex {
			indexability.Status = IndexStatusBlocked
			if HasNoindex(meta.MetaRobots) {
				reasons = append(reasons, "META_NOINDEX")
				suggestions = append(suggestions, "Xoá 'noindex' khỏi <meta name=\"robots\"> để cho phép indexing.")
			}
			if HasNoindex(meta.XRobotsTag) {
				reasons = append(reasons, "XROBOTS_NOINDEX")
				suggestions = append(suggestions, "Xoá 'noindex' khỏi X-Robots-Tag header.")
			}
		} else {
			indexability.Status = IndexStatusAllowed

			// Cảnh báo canonical
			if meta.CanonicalMissing {
				reasons = append(reasons, "CANONICAL_MISSING")
				suggestions = append(suggestions, "Thêm <link rel=\"canonical\"> để chỉ rõ URL canonical cho trang.")
			} else if !meta.CanonicalSelf {
				reasons = append(reasons, "CANONICAL_MISMATCH")
				suggestions = append(suggestions, fmt.Sprintf("Canonical đang trỏ đến %s thay vì trang hiện tại. Kiểm tra cấu hình canonical.", meta.Canonical))
			}
		}
	}

	// ─── Bước 3: HTTP serving signals ──────────────────────────────────
	if serving.InitialStatusCode == 404 {
		reasons = append(reasons, "HTTP_404")
		suggestions = append(suggestions, "Trang trả về 404 - sẽ bị loại khỏi index.")
	} else if serving.InitialStatusCode >= 500 {
		reasons = append(reasons, "HTTP_5XX")
		suggestions = append(suggestions, "Máy chủ đang lỗi. Bot thường hoãn xử lý khi nhận 5xx.")
	}

	// ─── Bước 4: Cảnh báo đặc biệt cho AI bots ────────────────────────
	if botFamily == "user_fetcher" {
		reasons = append(reasons, "UA_USER_FETCHER")
		suggestions = append(suggestions, "Bot này là user-triggered fetcher. Robots Exclusion Protocol không ràng buộc hoàn toàn loại bot này.")
	}

	// ─── Bước 5: Suy ra Verdict cuối cùng ──────────────────────────────
	confidence := "high"
	var verdictResult VerdictResult
	var summaryParts []string

	switch {
	case crawlAccess.Status == CrawlBlocked && indexability.Status == IndexStatusUnknownDueToCrawlBlock:
		verdictResult = VerdictBlocked
		summaryParts = append(summaryParts, "Bot bị chặn crawl bởi robots.txt.")

	case crawlAccess.Status == CrawlDeferred:
		verdictResult = VerdictRisky
		confidence = "medium"
		summaryParts = append(summaryParts, "Robots.txt trả về lỗi 5xx. Bot có thể hoãn crawl.")

	case crawlAccess.Status == CrawlError || crawlAccess.Status == CrawlUnreachable || crawlAccess.Status == CrawlTimeout:
		verdictResult = VerdictUnknown
		confidence = "low"
		summaryParts = append(summaryParts, "Không kết nối được tới trang.")

	case indexability.Status == IndexStatusBlocked:
		verdictResult = VerdictBlocked
		if crawlAccess.Status == CrawlAllowed {
			summaryParts = append(summaryParts, "Bot có thể crawl nhưng trang có tín hiệu noindex.")
		}

	case indexability.Status == IndexStatusAllowed && len(findRiskyReasons(reasons)) > 0:
		verdictResult = VerdictRisky
		confidence = "medium"
		summaryParts = append(summaryParts, "Trang có thể được index nhưng có một số cảnh báo.")

	case indexability.Status == IndexStatusAllowed:
		verdictResult = VerdictIndexable
		summaryParts = append(summaryParts, "Trang có thể được crawl và index bình thường.")

	default:
		verdictResult = VerdictUnknown
		confidence = "low"
		summaryParts = append(summaryParts, "Không đủ thông tin để kết luận.")
	}

	verdict.Result = string(verdictResult)
	verdict.Confidence = confidence
	verdict.ReasonCodes = reasons
	verdict.Summary = strings.Join(summaryParts, " ")
	verdict.Suggestions = suggestions

	return crawlAccess, indexability, verdict
}

// findRiskyReasons lọc các reason codes cần cảnh báo (nhưng chưa block hoàn toàn).
func findRiskyReasons(reasons []string) []string {
	riskySet := map[string]bool{
		"CANONICAL_MISSING":   true,
		"CANONICAL_MISMATCH":  true,
		"UA_USER_FETCHER":     true,
		"HTTP_5XX":            true,
	}
	out := []string{}
	for _, r := range reasons {
		if riskySet[r] {
			out = append(out, r)
		}
	}
	return out
}

// DefaultLimitations trả về danh sách limitation mặc định của UA Simulation.
func DefaultLimitations() []models.Limitation {
	return []models.Limitation{
		{
			Code:    "UA_SIMULATION_ONLY",
			Message: "Đây là mô phỏng User-Agent (UA Simulation). Công cụ này không xác thực IP thực của Googlebot hay thực hiện JavaScript rendering.",
		},
		{
			Code:    "NO_IP_VERIFICATION",
			Message: "Google và Bing xác thực bot thật bằng reverse DNS. Công cụ này không thể mô phỏng được điều đó.",
		},
		{
			Code:    "NO_JS_RENDERING",
			Message: "Trang sử dụng JavaScript render sẽ không được tính toán đúng. Chỉ raw HTML được phân tích.",
		},
		{
			Code:    "USER_FETCHER_SEMANTICS",
			Message: "User-triggered fetchers (ChatGPT-User, Claude-User, Perplexity-User) có semantics robots khác với search crawlers thông thường.",
		},
	}
}
