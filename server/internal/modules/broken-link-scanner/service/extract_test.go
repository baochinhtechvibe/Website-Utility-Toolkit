package service

import (
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseHTML_Extractor(t *testing.T) {
	htmlContent := `
		<html>
		<head>
			<meta http-equiv="refresh" content="0; url = https://refresh-target.com/page">
			<meta http-equiv="refresh" content="5;URL='https://refresh-target2.com/page'">
			<style>
				@import "https://css-import-1.com/style.css";
				@import url('https://css-import-2.com/style.css');
				.bg {
					background-image: url("https://css-image-1.png");
					list-style-image: url('https://css-image-2.png');
				}
			</style>
		</head>
		<body>
			<div style="background: url('/inline-img.jpg');"></div>
			<video src="/video.mp4" poster="/poster-image.jpg"></video>
			<img src="/fallback.jpg" srcset="/srcset-1.jpg 1x, /srcset-2.jpg 2x">
		</body>
		</html>
	`

	links := parseHTML(strings.NewReader(htmlContent))

	expectedLinks := []struct {
		kind   string
		rawURL string
	}{
		{"<meta>", "https://refresh-target.com/page"},
		{"<meta>", "https://refresh-target2.com/page"},
		{"CSS_IMPORT", "https://css-import-1.com/style.css"},
		{"CSS_IMPORT", "https://css-import-2.com/style.css"},
		{"CSS", "https://css-image-1.png"},
		{"CSS", "https://css-image-2.png"},
		{"CSS", "/inline-img.jpg"},
		{"<video>", "/video.mp4"},
		{"<video>", "/poster-image.jpg"},
		{"<img>", "/fallback.jpg"},
		{"<img>", "/srcset-1.jpg"},
		{"<img>", "/srcset-2.jpg"},
	}

	for _, exp := range expectedLinks {
		found := false
		for _, l := range links {
			if l.Kind == exp.kind && l.RawURL == exp.rawURL {
				found = true
				break
			}
		}
		assert.True(t, found, "Expected to find link: Kind=%s, RawURL=%s", exp.kind, exp.rawURL)
	}

	// Verify deduplication inside CSS (no duplicate url from @import url(...))
	import2Count := 0
	for _, l := range links {
		if l.RawURL == "https://css-import-2.com/style.css" {
			import2Count++
		}
	}
	assert.Equal(t, 1, import2Count, "Should not duplicate url(...) when already matched by @import")
}

func TestDedupeAndNormalize_CredentialsRejected(t *testing.T) {
	base, _ := url.Parse("https://example.com/")
	seen := make(map[string]bool)

	links := []unverifiedLink{
		{Kind: "<a>", SourceTag: "<a>", RawURL: "https://admin:secret@evil.com/steal"},
		{Kind: "<a>", SourceTag: "<a>", RawURL: "https://user@example.com/page"},
		{Kind: "<img>", SourceTag: "<img>", RawURL: "http://tok:pass@internal.net/logo.png"},
		{Kind: "<a>", SourceTag: "<a>", RawURL: "/safe-page"},
		{Kind: "<a>", SourceTag: "<a>", RawURL: "https://example.com/ok"},
	}

	result, invalidCount, _ := dedupeAndNormalize(links, base, "all", "https://example.com/", "example.com", seen)

	// Only /safe-page and /ok should survive
	assert.Equal(t, 2, len(result), "Should only accept 2 safe links")
	assert.Equal(t, 3, invalidCount, "Should count 3 credential URLs as invalid")

	for _, r := range result {
		parsed, _ := url.Parse(r.FinalURL)
		assert.Nil(t, parsed.User, "Result should not contain credentials: %s", r.FinalURL)
	}
}

func TestDedupeAndNormalize_MalformedURLs(t *testing.T) {
	base, _ := url.Parse("https://example.com/")
	seen := make(map[string]bool)

	links := []unverifiedLink{
		{Kind: "<a>", SourceTag: "<a>", RawURL: ""},
		{Kind: "<a>", SourceTag: "<a>", RawURL: "#section"},
		{Kind: "<a>", SourceTag: "<a>", RawURL: "javascript:alert(1)"},
		{Kind: "<a>", SourceTag: "<a>", RawURL: "data:text/html,<h1>Hi</h1>"},
		{Kind: "<a>", SourceTag: "<a>", RawURL: "mailto:test@example.com"},
		{Kind: "<a>", SourceTag: "<a>", RawURL: "tel:+1234567890"},
		{Kind: "<a>", SourceTag: "<a>", RawURL: "blob:https://example.com/uuid"},
		{Kind: "<a>", SourceTag: "<a>", RawURL: "/valid-relative"},
		{Kind: "<a>", SourceTag: "<a>", RawURL: "https://example.com/also-valid"},
	}

	result, invalidCount, _ := dedupeAndNormalize(links, base, "all", "https://example.com/", "example.com", seen)

	assert.Equal(t, 2, len(result), "Should accept only 2 valid URLs (relative + absolute)")
	assert.GreaterOrEqual(t, invalidCount, 5, "Should mark most malformed URLs as invalid")

	for _, r := range result {
		parsed, _ := url.Parse(r.FinalURL)
		assert.Contains(t, []string{"http", "https"}, parsed.Scheme, "Result scheme must be http or https: %s", r.FinalURL)
	}
}

func TestParseCSSText_Deduplication(t *testing.T) {
	css := `
		@import url('/fonts/inter.css');
		@import '/reset.css';
		.hero { background: url('/fonts/inter.css'); }
		.card { background: url('/images/card.jpg'); }
	`

	links := parseCSSText(css, "<style>")

	// @import url('/fonts/inter.css') should be caught by @import regex.
	// The url('/fonts/inter.css') in .hero should be deduped.
	interCount := 0
	for _, l := range links {
		if l.RawURL == "/fonts/inter.css" {
			interCount++
		}
	}
	assert.Equal(t, 1, interCount, "Should deduplicate CSS url() already caught by @import")

	// Verify all 3 unique URLs are present
	expectedURLs := []string{"/fonts/inter.css", "/reset.css", "/images/card.jpg"}
	for _, expected := range expectedURLs {
		found := false
		for _, l := range links {
			if l.RawURL == expected {
				found = true
				break
			}
		}
		assert.True(t, found, "Should find URL: %s", expected)
	}
}

func TestParseMetaRefresh_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected string
	}{
		{"Standard", "0; url=https://target.com/page", "https://target.com/page"},
		{"With spaces", "5; url = https://target.com/page", "https://target.com/page"},
		{"Single quotes", "0;URL='/new-page'", "/new-page"},
		{"Double quotes", `0;url="https://target.com"`, "https://target.com"},
		{"Uppercase URL", "3;URL=https://target.com/ABC", "https://target.com/ABC"},
		{"No match (no url=)", "5; refresh", ""},
		{"Empty content", "", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := parseMetaRefresh(tc.content, "<meta>")
			if tc.expected == "" {
				assert.Nil(t, result, "Should return nil for: %s", tc.content)
			} else {
				assert.NotNil(t, result, "Should find URL in: %s", tc.content)
				assert.Equal(t, tc.expected, result.RawURL)
			}
		})
	}
}
