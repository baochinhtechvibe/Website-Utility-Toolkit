package service

import (
	"strings"
	"testing"
)

func TestBuildCacheKey(t *testing.T) {
	key1 := BuildCacheKey("https://example.com", "googlebot-desktop", false, false, nil, false)
	key2 := BuildCacheKey("https://example.com", "googlebot-desktop", false, false, nil, true)
	
	if key1 == key2 {
		t.Errorf("Expected different cache keys for different ignoreTLSErrors options, got same %s", key1)
	}

	key3 := BuildCacheKey("https://example.com", "googlebot-desktop", true, false, nil, false)
	if key1 == key3 {
		t.Errorf("Expected different cache keys for different checkSitemap options")
	}
}

func TestNormalizeURLForCompare(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"https://Example.com/Path/?Query=1", "https://example.com/Path/?Query=1"},
		{"http://test.com/path#fragment", "http://test.com/path"},
		{"https://test.com/", "https://test.com/"},
	}

	for _, c := range cases {
		out := normalizeURLForCompare(c.input)
		if out != c.expected {
			t.Errorf("normalizeURLForCompare(%q) == %q, expected %q", c.input, out, c.expected)
		}
	}
}

func TestRobotsDirectives(t *testing.T) {
	if !HasNoindex("noindex, nofollow", "googlebot") {
		t.Errorf("Expected HasNoindex to be true")
	}
	if HasNoindex("index, follow", "googlebot") {
		t.Errorf("Expected HasNoindex to be false")
	}
	if !HasNofollow("index, nofollow", "googlebot") {
		t.Errorf("Expected HasNofollow to be true")
	}
	if !HasNoindex("googlebot: noindex", "googlebot") {
		t.Errorf("Expected HasNoindex to parse colon format")
	}
	if HasNoindex("googlebot: noindex", "bingbot") {
		t.Errorf("Expected HasNoindex to ignore other bot's rule")
	}
	// Test stateful parsing
	if !HasNofollow("googlebot: noindex, nofollow", "googlebot") {
		t.Errorf("Expected stateful parser to catch nofollow for googlebot")
	}
	if HasNofollow("googlebot: noindex, nofollow", "bingbot") {
		t.Errorf("Expected stateful parser to ignore googlebot's nofollow for bingbot")
	}
	if HasNoindex("otherbot: noindex, nofollow", "googlebot") {
		t.Errorf("Expected stateful parser to ignore otherbot's noindex for googlebot")
	}
	if !HasNoindex("otherbot: noindex, nofollow", "otherbot") {
		t.Errorf("Expected stateful parser to catch otherbot's noindex for otherbot")
	}
	if !HasNofollow("otherbot: noindex, nofollow", "otherbot") {
		t.Errorf("Expected stateful parser to catch otherbot's nofollow for otherbot")
	}

	// Test multi-header / global mix
	if !HasNoindex("googlebot: noindex, nofollow, noarchive", "googlebot") {
		t.Errorf("Expected stateful parser to handle 3 directives for googlebot (noindex)")
	}
	if !HasNofollow("googlebot: noindex, nofollow, noarchive", "googlebot") {
		t.Errorf("Expected stateful parser to handle 3 directives for googlebot (nofollow)")
	}
	if !HasNoindex("noindex, googlebot: nofollow", "bingbot") {
		t.Errorf("Expected global noindex to apply to bingbot")
	}
	if !HasNoindex("noindex, googlebot: nofollow", "googlebot") {
		t.Errorf("Expected global noindex to apply to googlebot")
	}
	if !HasNofollow("noindex, googlebot: nofollow", "googlebot") {
		t.Errorf("Expected scoped nofollow to apply to googlebot")
	}
	if HasNofollow("noindex, googlebot: nofollow", "bingbot") {
		t.Errorf("Expected scoped nofollow NOT to apply to bingbot")
	}
}

func TestParseMeta(t *testing.T) {
	html1 := `<html><head>
		<meta name="robots" content="index, follow">
		<meta name="googlebot" content="noindex">
		<meta name="bingbot" content="nofollow">
	</head></html>`
	
	resGoogle := ParseMeta(html1, "", "", "googlebot")
	if !strings.Contains(resGoogle.MetaRobots, "index, follow") || !strings.Contains(resGoogle.MetaRobots, "noindex") || strings.Contains(resGoogle.MetaRobots, "nofollow") {
		t.Errorf("Expected ParseMeta to capture global and googlebot directives: got %s", resGoogle.MetaRobots)
	}

	resBing := ParseMeta(html1, "", "", "bingbot")
	if !strings.Contains(resBing.MetaRobots, "index, follow") || !strings.Contains(resBing.MetaRobots, "nofollow") || strings.Contains(resBing.MetaRobots, "noindex") {
		t.Errorf("Expected ParseMeta to capture global and bingbot directives: got %s", resBing.MetaRobots)
	}

	html2 := `<html><head>
		<meta name="robots" content="noarchive">
		<meta name="robots" content="noindex">
	</head></html>`
	resMulti := ParseMeta(html2, "", "", "googlebot")
	if !strings.Contains(resMulti.MetaRobots, "noarchive") || !strings.Contains(resMulti.MetaRobots, "noindex") {
		t.Errorf("Expected ParseMeta to capture multiple generic robots tags: got %s", resMulti.MetaRobots)
	}

	html3 := `<html><head>
		<meta name="googlebot-news" content="noindex">
		<meta name="googlebot" content="nofollow">
	</head></html>`
	resBoundary := ParseMeta(html3, "", "", "googlebot")
	if strings.Contains(resBoundary.MetaRobots, "noindex") {
		t.Errorf("Expected ParseMeta to NOT capture googlebot-news when bot is googlebot")
	}
	if !strings.Contains(resBoundary.MetaRobots, "nofollow") {
		t.Errorf("Expected ParseMeta to capture googlebot directive")
	}

	html4 := `<html><head>
		<meta name = "robots" content = "noindex">
		<meta name="googlebot" content="nofollow">
	</head></html>`
	resSpacing := ParseMeta(html4, "", "", "googlebot")
	if !strings.Contains(resSpacing.MetaRobots, "noindex") {
		t.Errorf("Expected ParseMeta to handle spaces around equals sign for name attribute")
	}
	if !strings.Contains(resSpacing.MetaRobots, "nofollow") {
		t.Errorf("Expected ParseMeta to capture googlebot directive alongside generic")
	}
}
