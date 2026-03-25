package service

import (
	"tools.bctechvibe.com/server/internal/modules/bot-simulator/models"
)

// BotProfile chứa thông tin đầy đủ về một bot agent.
type BotProfile struct {
	Key         string
	Label       string
	UserAgent   string
	RobotsToken string // token dùng trong robots.txt matching (có thể khác ua string)
	Family      string // search_crawler | ai_search | ai_training | user_fetcher | social_preview
	DocsURL     string
	// Headers mặc định bot này thường gửi
	DefaultHeaders map[string]string
}

// BotCatalog là danh sách đầy đủ các bot profile được hỗ trợ.
var BotCatalog = map[string]BotProfile{
	// ─── Search Crawlers ──────────────────────────────────────────────
	"googlebot-desktop": {
		Key:         "googlebot-desktop",
		Label:       "Googlebot (Desktop)",
		UserAgent:   "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		RobotsToken: "googlebot",
		Family:      "search_crawler",
		DocsURL:     "https://developers.google.com/search/docs/crawling-indexing/overview-google-crawlers",
		DefaultHeaders: map[string]string{
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Accept-Encoding": "gzip,deflate",
			// Googlebot không gửi Accept-Language
		},
	},
	"googlebot-smartphone": {
		Key:         "googlebot-smartphone",
		Label:       "Googlebot (Smartphone)",
		UserAgent:   "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.204 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		RobotsToken: "googlebot",
		Family:      "search_crawler",
		DocsURL:     "https://developers.google.com/search/docs/crawling-indexing/overview-google-crawlers",
		DefaultHeaders: map[string]string{
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Accept-Encoding": "gzip,deflate",
		},
	},
	"bingbot": {
		Key:         "bingbot",
		Label:       "Bingbot",
		UserAgent:   "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
		RobotsToken: "bingbot",
		Family:      "search_crawler",
		DocsURL:     "https://www.bing.com/webmasters/help/which-crawlers-does-bing-use-8c184ec0",
		DefaultHeaders: map[string]string{
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Accept-Encoding": "gzip,deflate",
		},
	},
	"yandexbot": {
		Key:         "yandexbot",
		Label:       "YandexBot",
		UserAgent:   "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
		RobotsToken: "yandexbot",
		Family:      "search_crawler",
		DocsURL:     "https://yandex.com/support/webmaster/robot-workings/what-is-robot.html",
		DefaultHeaders: map[string]string{
			"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		},
	},

	// ─── AI Search Crawlers ───────────────────────────────────────────
	"oai-searchbot": {
		Key:         "oai-searchbot",
		Label:       "OAI-SearchBot (OpenAI)",
		UserAgent:   "OAI-SearchBot/1.0; +https://openai.com/searchbot",
		RobotsToken: "oai-searchbot",
		Family:      "ai_search",
		DocsURL:     "https://platform.openai.com/docs/bots",
		DefaultHeaders: map[string]string{
			"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		},
	},
	"perplexitybot": {
		Key:         "perplexitybot",
		Label:       "PerplexityBot",
		UserAgent:   "PerplexityBot/1.0 (+https://docs.perplexity.ai/docs/perplexitybot)",
		RobotsToken: "perplexitybot",
		Family:      "ai_search",
		DocsURL:     "https://docs.perplexity.ai/docs/resources/perplexity-crawlers",
		DefaultHeaders: map[string]string{
			"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		},
	},

	// ─── AI Training Bots ─────────────────────────────────────────────
	"gptbot": {
		Key:         "gptbot",
		Label:       "GPTBot (OpenAI Training)",
		UserAgent:   "GPTBot/1.2 (+https://openai.com/gptbot)",
		RobotsToken: "gptbot",
		Family:      "ai_training",
		DocsURL:     "https://platform.openai.com/docs/bots",
		DefaultHeaders: map[string]string{
			"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		},
	},
	"claudebot": {
		Key:         "claudebot",
		Label:       "ClaudeBot (Anthropic Training)",
		UserAgent:   "Claude-Web/1.0 (+https://support.claude.ai/en/articles/8896518)",
		RobotsToken: "claudebot",
		Family:      "ai_training",
		DocsURL:     "https://support.anthropic.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler",
		DefaultHeaders: map[string]string{
			"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		},
	},
	"claude-searchbot": {
		Key:         "claude-searchbot",
		Label:       "Claude-SearchBot (Anthropic Search)",
		UserAgent:   "Claude-SearchBot/1.0 (+https://support.anthropic.com)",
		RobotsToken: "claude-searchbot",
		Family:      "ai_search",
		DocsURL:     "https://support.anthropic.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler",
		DefaultHeaders: map[string]string{
			"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		},
	},

	// ─── User-Triggered Fetchers ──────────────────────────────────────
	// Khác với training bot: user_fetcher được kích hoạt khi người dùng hỏi trực tiếp.
	// Robots Exclusion Protocol không ràng buộc chúng theo cách thông thường.
	"chatgpt-user": {
		Key:         "chatgpt-user",
		Label:       "ChatGPT-User (User-Triggered)",
		UserAgent:   "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot",
		RobotsToken: "chatgpt-user",
		Family:      "user_fetcher",
		DocsURL:     "https://platform.openai.com/docs/bots",
		DefaultHeaders: map[string]string{
			"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		},
	},
	"perplexity-user": {
		Key:         "perplexity-user",
		Label:       "Perplexity-User (User-Triggered)",
		UserAgent:   "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot",
		RobotsToken: "perplexity-user",
		Family:      "user_fetcher",
		DocsURL:     "https://docs.perplexity.ai/docs/resources/perplexity-crawlers",
		DefaultHeaders: map[string]string{
			"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		},
	},
	"claude-user": {
		Key:         "claude-user",
		Label:       "Claude-User (User-Triggered)",
		UserAgent:   "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; Claude-User/1.0",
		RobotsToken: "claude-user",
		Family:      "user_fetcher",
		DocsURL:     "https://support.anthropic.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler",
		DefaultHeaders: map[string]string{
			"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		},
	},

	// ─── Social Preview Bots ──────────────────────────────────────────
	"facebookbot": {
		Key:         "facebookbot",
		Label:       "facebookexternalhit (Facebook Preview)",
		UserAgent:   "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
		RobotsToken: "facebookexternalhit",
		Family:      "social_preview",
		DocsURL:     "https://developers.facebook.com/docs/sharing/webmasters/crawler/",
		DefaultHeaders: map[string]string{
			"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		},
	},
	"twitterbot": {
		Key:         "twitterbot",
		Label:       "Twitterbot (X Preview)",
		UserAgent:   "Twitterbot/1.0",
		RobotsToken: "twitterbot",
		Family:      "social_preview",
		DefaultHeaders: map[string]string{
			"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		},
	},
}

// DefaultCompareMatrix là tập bot dùng để so sánh chéo mặc định khi compare mode bật.
var DefaultCompareMatrix = []string{
	"googlebot-desktop",
	"googlebot-smartphone",
	"bingbot",
	"gptbot",
	"claudebot",
	"facebookbot",
}

// MaxCompareProfiles là số bot profile chạy song song tối đa trong compare mode.
const MaxCompareProfiles = 6

// GetProfile trả về profile theo key.
func GetProfile(key string) (BotProfile, bool) {
	p, ok := BotCatalog[key]
	return p, ok
}

// ToModelInfo chuyển profile sang struct trả về cho client.
func (p BotProfile) ToModelInfo() models.BotProfileInfo {
	return models.BotProfileInfo{
		Key:         p.Key,
		Label:       p.Label,
		UserAgent:   p.UserAgent,
		RobotsToken: p.RobotsToken,
		Family:      p.Family,
		DocsURL:     p.DocsURL,
	}
}

// FamilyLabel trả về tên tiếng Việt dễ hiểu của từng group.
func FamilyLabel(family string) string {
	switch family {
	case "search_crawler":
		return "Search Crawler (Công cụ tìm kiếm)"
	case "ai_search":
		return "AI Search Crawler (Tìm kiếm AI)"
	case "ai_training":
		return "AI Training Bot (Thu thập dữ liệu huấn luyện AI)"
	case "user_fetcher":
		return "User-Triggered Fetcher (Lấy dữ liệu theo yêu cầu người dùng)"
	case "social_preview":
		return "Social Preview Bot (Xem trước liên kết mạng xã hội)"
	default:
		return "Bot không xác định"
	}
}
